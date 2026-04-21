"""mitmproxy addon: bridge legacy XBL2.0 UWP game auth to modern XBL3.0.

Chain on startup (all public documented XBL endpoints):

    [WAM / OS MSA session]
         |
         v  RPS compact ticket "t=...&p="
    user.auth.xboxlive.com/user/authenticate
         |
         v  UserToken
    device.auth.xboxlive.com/device/authenticate  (P-256 ProofOfPossession)
         |
         v  DeviceToken
    xsts.auth.xboxlive.com/xsts/authorize        (UserTokens + DeviceToken)
         |
         v  XSTS token + UserHash
    Authorization: XBL3.0 x=<UHS>;<XSTS>
    Signature: <ECDSA over method|path|auth|body>

Per-request policy:
  * `stats.xboxlive.com`, `communications.xboxlive.com` — these endpoints
    only speak XBL2.0 (server returns `methods=Xbl20`). No modern bridge
    exists server-side. Pass through untouched.
  * `auth.xboxlive.com/XSts/...` — the legacy XBL2 mint call the game
    makes itself. Leave it; the 200 response keeps the game's internal
    sign-in state machine moving.
  * Everything else in `*.xboxlive.com` with an `Authorization: XBL2.0`
    gets rewritten to XBL3.0 + Signature.

Run:  mitmdump -s addon/xbl_bridge.py  (with ticket_server.exe up)
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import re
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import ecdsa
from mitmproxy import ctx, http


def _forge_xsts_rstr(xsts_token: str, message_id: str) -> bytes:
    """Forge a WS-Trust 1.3 RequestSecurityTokenResponse envelope for
    Adera / Pinball-style legacy Microsoft.Xbox.dll XSts calls.

    The server's real XSts endpoint rejects WLID1.0 bootstrap credentials
    on post-deprecation accounts with `x-err: 0x8015DA87`. We substitute
    a synthetic success response carrying the bridge's already-minted
    modern XBL JWT (same one we use to rewrite XBL2.0 → XBL3.0 headers).
    The bearer JWT is the format these clients ask for via
    `http://oauth.net/grant_type/xjwt/1.0/bearer`.
    """
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    expires = now + datetime.timedelta(hours=16)
    iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    iso_exp = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
    # WS-Security base64 encoding for BinarySecurityToken
    b64 = base64.b64encode(xsts_token.encode("ascii")).decode("ascii")
    envelope = (
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:a="http://www.w3.org/2005/08/addressing">'
        '<s:Header>'
        '<a:Action s:mustUnderstand="1">'
        'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal'
        '</a:Action>'
        f'<a:RelatesTo>{message_id}</a:RelatesTo>'
        '</s:Header>'
        '<s:Body>'
        '<trust:RequestSecurityTokenResponseCollection'
        ' xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512">'
        '<trust:RequestSecurityTokenResponse>'
        '<trust:Lifetime>'
        '<wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/'
        f'oasis-200401-wss-wssecurity-utility-1.0.xsd">{iso}</wsu:Created>'
        '<wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/'
        f'oasis-200401-wss-wssecurity-utility-1.0.xsd">{iso_exp}</wsu:Expires>'
        '</trust:Lifetime>'
        '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">'
        '<EndpointReference xmlns="http://www.w3.org/2005/08/addressing">'
        '<Address>http://xboxlive.com</Address>'
        '</EndpointReference>'
        '</wsp:AppliesTo>'
        '<trust:RequestedSecurityToken>'
        '<trust:BinarySecurityToken'
        ' ValueType="http://oauth.net/grant_type/xjwt/1.0/bearer"'
        ' EncodingType="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
        f'{b64}'
        '</trust:BinarySecurityToken>'
        '</trust:RequestedSecurityToken>'
        '<trust:TokenType>'
        'http://oauth.net/grant_type/xjwt/1.0/bearer'
        '</trust:TokenType>'
        '<trust:RequestType>'
        'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue'
        '</trust:RequestType>'
        '<trust:KeyType>'
        'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer'
        '</trust:KeyType>'
        '</trust:RequestSecurityTokenResponse>'
        '</trust:RequestSecurityTokenResponseCollection>'
        '</s:Body>'
        '</s:Envelope>'
    )
    return envelope.encode("utf-8")

# --- configuration ----------------------------------------------------------

TICKET_SERVER_URL = "http://127.0.0.1:8099/ticket"
USER_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
DEVICE_AUTH_URL = "https://device.auth.xboxlive.com/device/authenticate"
XSTS_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
XBOXLIVE_RP = "http://xboxlive.com"

# Hosts the server still requires XBL2.0 on. Those tokens are dead — no
# modern bridge possible. We pass them through untouched so we don't make
# things worse than they already are.
XBL20_ONLY_HOSTS = {
    "stats.xboxlive.com",
    "communications.xboxlive.com",
}

# Hosts that are *dead* server-side — DNS still resolves but the IP no
# longer accepts connections. The legacy-SDK games block their sign-in
# state machine until they get a response from these endpoints, so we
# synthesize a 200-empty reply locally to keep the flow moving.
#
#   data.xboxlive.com — legacy XBL presence/beacon endpoint that Microsoft
#                       Adera (and likely others) posts to during sign-in.
#                       Decommissioned circa Xbox 360 retirement; now
#                       times out at the TCP layer.
DEAD_HOSTS_SHIM_200 = {
    "data.xboxlive.com",
}

# Mapping of legacy XBL2.0 numeric setting IDs to their modern string names
# (observed on the wire; the server switched from numeric to string between
# contract versions). Unknown IDs fall through untranslated.
SETTING_ID_TO_NAME: dict[int, str] = {
    268697606: "Gamerscore",
    268697658: "Gamertag",
    1076625425: "AccountTier",
    1079115841: "GameDisplayPicRaw",
    1080295439: "AppDisplayName",
    1090781248: "XboxOneRep",
    1139277891: "AppDisplayPicRaw",
    1342439435: "PublicGamerpic",
    1676148804: "GameDisplayName",
}
# Reverse map (string -> numeric) for rewriting the response back to what
# legacy Mahjong can parse.
SETTING_NAME_TO_ID: dict[str, int] = {v: k for k, v in SETTING_ID_TO_NAME.items()}

# Settings the modern profile endpoint allows non-privileged callers to
# request. Anything outside this set triggers a whole-batch "Restricted"
# (code=60). Mahjong asked for fields like AccountTier/XboxOneRep that no
# longer work without extra consent scopes.
SAFE_PROFILE_SETTINGS = {
    "AppDisplayName",
    "AppDisplayPicRaw",
    "GameDisplayName",
    "GameDisplayPicRaw",
    "Gamerscore",
    "Gamertag",
}

# Per-title-group allowlist for the titlestorage 403 shim.  Only games we
# know benefit from having a 403 -> 200(empty) smoothing belong here.
# Generalising the shim to ANY titlegroup was tried and caused a regression
# in Microsoft Minesweeper: its `SyncedData.json` path *needs* to 403 so
# the game falls back to progress.xboxlive.com/achievements (which works).
# Shimming it broke that fallback and the Awards page then showed
# "Sign in to Xbox to view and earn Achievements".
#
# Add new titlegroups here if you discover a game's storage path
# benefits from the shim. Keep it conservative.
_SHIM_TITLEGROUPS = {
    "af51caa0-ea8b-46e3-87be-ec824e127a41",  # Microsoft Mahjong
    "b3288d02-ddca-4e7c-955a-06142d6e138e",  # Microsoft Solitaire Collection
}
_TITLESTORAGE_USER_RE = re.compile(
    r"^/users/xuid\(\d+\)/storage/titlestorage/titlegroups/([0-9a-fA-F-]+)/"
)
_TITLESTORAGE_MEDIA_RE = re.compile(
    r"^/media/titlegroups/([0-9a-fA-F-]+)/storage/"
)


def _titlestorage_should_shim(path: str) -> bool:
    """True only if the titlestorage path's titlegroup is one we've
    whitelisted as benefiting from a 403 -> empty-200 shim."""
    m = _TITLESTORAGE_USER_RE.match(path) or _TITLESTORAGE_MEDIA_RE.match(path)
    if not m:
        return False
    return m.group(1).lower() in _SHIM_TITLEGROUPS

SSL_CTX = ssl.create_default_context()

# CRITICAL: the addon runs *inside* mitmproxy, and the system proxy points
# at mitmproxy. urllib would otherwise route our bootstrap calls back
# through the same proxy - infinite loop, then timeout. Build a proxy-less
# opener that bypasses WinINET/env proxy detection entirely.
_NOPROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# 100ns ticks between 1601-01-01 (Windows FILETIME epoch) and 1970-01-01 (Unix epoch)
FILETIME_EPOCH_OFFSET = 116_444_736_000_000_000


# --- request signer (XBL Signature header) ----------------------------------

class RequestSigner:
    """Xbox Live request signer (EC P-256, signature policy v1)."""

    SIGNATURE_VERSION = 1
    MAX_BODY_BYTES = 8192

    def __init__(self, signing_key: ecdsa.SigningKey | None = None):
        self.signing_key = signing_key or ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        self.verifying_key = self.signing_key.verifying_key

    def get_proof_key(self) -> dict:
        pub = self.verifying_key.to_string()
        return {
            "use": "sig",
            "alg": "ES256",
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(pub[:32]),
            "y": _b64url(pub[32:]),
        }

    def sign_request(self, method: str, url: str, authorization: str = "",
                     body: bytes = b"", timestamp: float | None = None) -> str:
        if timestamp is None:
            timestamp = time.time()
        filetime = FILETIME_EPOCH_OFFSET + int(timestamp * 10_000_000)

        parsed = urllib.parse.urlparse(url)
        path_and_query = parsed.path + (("?" + parsed.query) if parsed.query else "")

        version_bytes = struct.pack(">I", self.SIGNATURE_VERSION)
        filetime_bytes = struct.pack(">Q", filetime)

        signing_data = (
            version_bytes + b"\x00"
            + filetime_bytes + b"\x00"
            + method.upper().encode("ascii") + b"\x00"
            + path_and_query.encode("ascii") + b"\x00"
            + authorization.encode("ascii") + b"\x00"
            + body[: self.MAX_BODY_BYTES] + b"\x00"
        )
        digest = hashlib.sha256(signing_data).digest()
        sig = self.signing_key.sign_digest_deterministic(
            digest, sigencode=ecdsa.util.sigencode_string
        )  # 64 bytes (r || s)
        header_bytes = version_bytes + filetime_bytes + sig
        return base64.b64encode(header_bytes).decode("ascii")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


# --- HTTP helpers -----------------------------------------------------------

def _post_json(url: str, body: dict, headers: dict | None = None,
               signer: RequestSigner | None = None) -> dict:
    payload = json.dumps(body).encode("utf-8")
    req_headers = {
        "Content-Type": "application/json",
        "x-xbl-contract-version": "1",
    }
    if headers:
        req_headers.update(headers)
    if signer is not None:
        auth = req_headers.get("Authorization", "")
        req_headers["Signature"] = signer.sign_request("POST", url, auth, payload)
    req = urllib.request.Request(url, data=payload, method="POST", headers=req_headers)
    try:
        with _NOPROXY_OPENER.open(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")[:1500]
        raise RuntimeError(f"POST {url} -> HTTP {e.code}: {err_body}") from e


def _fetch_mbi_ticket() -> tuple[str, str]:
    with _NOPROXY_OPENER.open(TICKET_SERVER_URL, timeout=10) as r:
        data = json.loads(r.read().decode("utf-8"))
    return data["ticket"], data.get("account", "")


def _exchange_mbi_for_user_token(mbi_ticket: str) -> str:
    resp = _post_json(USER_AUTH_URL, {
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": mbi_ticket,
        },
    })
    return resp["Token"]


def _mint_device_token(signer: RequestSigner) -> tuple[str, str]:
    device_id = "{%s}" % uuid.uuid4()
    resp = _post_json(
        DEVICE_AUTH_URL,
        {
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
            "Properties": {
                "AuthMethod": "ProofOfPossession",
                "Id": device_id,
                "DeviceType": "Win32",
                "Version": "10.0.19045",
                "ProofKey": signer.get_proof_key(),
            },
        },
        signer=signer,
    )
    return resp["Token"], device_id


def _mint_xsts(user_token: str, relying_party: str = XBOXLIVE_RP,
               device_token: str | None = None,
               signer: RequestSigner | None = None) -> dict:
    props: dict = {"SandboxId": "RETAIL", "UserTokens": [user_token]}
    if device_token:
        props["DeviceToken"] = device_token
    return _post_json(
        XSTS_URL,
        {"RelyingParty": relying_party, "TokenType": "JWT", "Properties": props},
        signer=signer,
    )


# --- addon ------------------------------------------------------------------

class XblBridge:
    def __init__(self) -> None:
        self.signer: RequestSigner | None = None
        self.xbl3_auth: str | None = None
        self.uhs: str = ""
        self.xuid: str = ""
        self.gamertag: str = ""
        self.account: str = ""
        self.rewrote = 0
        self.passthrough_legacy = 0
        self.signed = 0

    def running(self) -> None:
        try:
            self._bootstrap()
        except Exception as exc:
            ctx.log.error(f"[xbl_bridge] bootstrap FAILED: {exc}")

    def _bootstrap(self) -> None:
        ctx.log.info("[xbl_bridge] MBI ticket from ticket_server...")
        mbi, account = _fetch_mbi_ticket()
        self.account = account
        ctx.log.info(f"[xbl_bridge]   account={account} mbi_len={len(mbi)}")

        user_token = _exchange_mbi_for_user_token(mbi)
        ctx.log.info(f"[xbl_bridge] UserToken ({len(user_token)} bytes)")

        # Mint a simple (UserTokens-only) XSTS. Empirically this works for
        # every endpoint Mahjong actually consumes successfully — profile,
        # progress, userpresence all return 200, and the server even echoes
        # legacy numeric setting IDs in the response (matching Mahjong's
        # XBL2-era deserializer).  A DeviceToken-bound XSTS gets *less*
        # access: profile.xboxlive.com returns "Restricted" when presented
        # a device-bound token without matching consent.  We keep
        # RequestSigner + device-token code paths available for future
        # endpoints that actually require signing.
        xsts = _mint_xsts(user_token)
        claims = xsts.get("DisplayClaims", {}).get("xui", [{}])[0]
        self.uhs = claims.get("uhs", "")
        self.xuid = claims.get("xid", "")
        self.gamertag = claims.get("gtg", "")
        xsts_token = xsts["Token"]
        self.xbl3_auth = f"XBL3.0 x={self.uhs};{xsts_token}"
        ctx.log.info(
            f"[xbl_bridge] READY — gamertag={self.gamertag} xuid={self.xuid} "
            f"simple XSTS token_len={len(xsts_token)}"
        )

    def request(self, flow: http.HTTPFlow) -> None:
        if self.xbl3_auth is None:
            return
        host = flow.request.host or ""
        if not host.endswith(".xboxlive.com"):
            return

        # Dead hosts: short-circuit with a synthetic 200 empty body so the
        # game's state machine unblocks. Setting flow.response here prevents
        # mitmproxy from ever trying to reach the (unreachable) upstream.
        if host in DEAD_HOSTS_SHIM_200:
            flow.response = http.Response.make(
                200, b"", {"Content-Type": "application/json"}
            )
            ctx.log.info(
                f"[xbl_bridge] dead-host shim: {flow.request.method} "
                f"{host}{flow.request.path[:100]} -> 200(empty)"
            )
            return

        # Legacy XSts mint call (auth.xboxlive.com/XSts/xsts.svc/IWSTrust13).
        # Post-deprecation of Xbox Live 1.0, the server rejects the WLID1.0
        # bootstrap tokens that Microsoft.Xbox.dll sends with
        # `x-err: 0x8015DA87` and a bare WCF dispatcher fault — Adera /
        # Pinball / Taptiles never progress past this.
        #
        # Forge a success response carrying the bridge's already-minted
        # modern XBL3.0 XSTS JWT. Clients that consume the bearer JWT
        # without verifying the SOAP envelope signature (we've seen Adera
        # do this) proceed into the profile / achievements fetch paths,
        # which the rest of this addon already bridges.
        if host in ("auth.xboxlive.com", "activeauth.xboxlive.com") and \
                flow.request.path.startswith("/XSts"):
            req_body = flow.request.get_content() or b""
            msg_id_match = re.search(rb"<a:MessageID>([^<]+)</a:MessageID>", req_body)
            msg_id = msg_id_match.group(1).decode("ascii", "replace") if msg_id_match else ""
            # Extract the raw JWT from "XBL3.0 x=<uhs>;<jwt>"
            jwt = self.xbl3_auth.split(";", 1)[1] if self.xbl3_auth and ";" in self.xbl3_auth else ""
            if not jwt:
                return  # bridge not bootstrapped; let the real server reject
            forged = _forge_xsts_rstr(jwt, msg_id)
            flow.response = http.Response.make(
                200, forged,
                {"Content-Type": "application/soap+xml; charset=utf-8"},
            )
            ctx.log.info(
                "[xbl_bridge] forged XSts success for "
                f"{host}{flow.request.path[:80]}  msg_id={msg_id[:40]}"
            )
            return

        # Hosts that only speak XBL2.0 server-side: pass through. Our rewrite
        # would actively break them — the XBL2.0 token Mahjong carries still
        # produces sensible 200s here despite being "deprecated".
        if host in XBL20_ONLY_HOSTS:
            self.passthrough_legacy += 1
            return

        auth = flow.request.headers.get("Authorization", "")
        if not auth.startswith("XBL2.0"):
            return

        # Rewrite: swap the Authorization header; leave everything else —
        # including `x-xbl-contract-version` and the request body — alone.
        # Empirically the server handles Mahjong's v=1 legacy-shaped payloads
        # correctly when presented a modern XBL3.0 token; bumping the
        # contract version or translating the body to modern schema actively
        # breaks Mahjong's (legacy-shaped) response parser.
        flow.request.headers["Authorization"] = self.xbl3_auth

        self.rewrote += 1
        ctx.log.info(
            f"[xbl_bridge] bridged {flow.request.method} "
            f"{host}{flow.request.path[:100]}"
        )

    def _translate_profile_settings_request(self, body: bytes) -> bytes:
        """Legacy {userIds:[int],settingIds:[num],titleId:num} -> modern
        {userIds:["str"],settings:[names]}.

        Drops settings the modern service treats as "Restricted" (privilege
        gated) — those cause the whole batch to return code=60 even if all
        other settings were readable. We keep the set Jigsaw successfully
        requests.
        """
        try:
            req = json.loads(body.decode("utf-8"))
        except Exception:
            return body
        if "settings" in req and "settingIds" not in req:
            return body  # already modern
        user_ids = [str(u) for u in req.get("userIds", [])]
        setting_ids = req.get("settingIds", []) or []
        settings: list[str] = []
        dropped_restricted: list[str] = []
        unknown: list[int] = []
        for sid in setting_ids:
            name = SETTING_ID_TO_NAME.get(int(sid))
            if name is None:
                unknown.append(int(sid))
            elif name in SAFE_PROFILE_SETTINGS:
                settings.append(name)
            else:
                dropped_restricted.append(name)
        if unknown:
            ctx.log.warn(
                f"[xbl_bridge] profile-settings shim: unmapped legacy "
                f"setting IDs {unknown}"
            )
        if dropped_restricted:
            ctx.log.info(
                f"[xbl_bridge] profile-settings shim: dropped restricted "
                f"{dropped_restricted}"
            )
        new = {"userIds": user_ids, "settings": settings}
        ctx.log.info(
            f"[xbl_bridge] profile-settings shim: {len(setting_ids)} "
            f"legacy ids -> {len(settings)} modern names"
        )
        return json.dumps(new).encode("utf-8")

    def response(self, flow: http.HTTPFlow) -> None:
        if self.xbl3_auth is None:
            return
        host = flow.request.host or ""
        if not host.endswith(".xboxlive.com"):
            return

        # titlestorage 403 shim, whitelisted per-titlegroup.
        if (
            host == "titlestorage.xboxlive.com"
            and flow.response
            and flow.response.status_code == 403
            and _titlestorage_should_shim(flow.request.path)
        ):
            self._shim_titlestorage(flow)
            return

        if flow.response and flow.response.status_code in (401, 403):
            ctx.log.warn(
                f"[xbl_bridge] {flow.response.status_code} on {flow.request.method} "
                f"{host}{flow.request.path[:120]}  "
                f"wwwauth={flow.response.headers.get('WWW-Authenticate', '')[:80]!r}"
            )

    def _shim_titlestorage(self, flow: http.HTTPFlow) -> None:
        method = flow.request.method
        if method == "GET":
            # Legacy Mahjong treats 404 here as a fatal download failure
            # (raises "error code 002000" for Daily Challenge). The XBL2-era
            # contract returned 200 with an empty body for "no saved
            # progress". Emulate that.
            flow.response.status_code = 200
            flow.response.headers["Content-Type"] = "application/json"
            flow.response.set_content(b"{}")
            ctx.log.info(
                f"[xbl_bridge] titlestorage shim: GET 403->200(empty) "
                f"{flow.request.path[:100]}"
            )
        elif method in ("PUT", "POST"):
            flow.response.status_code = 200
            flow.response.headers["Content-Type"] = "application/json"
            flow.response.set_content(b"{}")
            ctx.log.info(
                f"[xbl_bridge] titlestorage shim: {method} 403->200 "
                f"{flow.request.path[:100]}"
            )
        elif method == "DELETE":
            flow.response.status_code = 204
            flow.response.set_content(b"")
            ctx.log.info(
                f"[xbl_bridge] titlestorage shim: DELETE 403->204 "
                f"{flow.request.path[:100]}"
            )

    def _translate_profile_settings_response(self, flow: http.HTTPFlow) -> None:
        """Server returns settings keyed by name; legacy Mahjong expects
        them keyed by numeric id. Rewrite in place."""
        try:
            payload = json.loads((flow.response.content or b"").decode("utf-8"))
        except Exception:
            return
        translated = 0
        for pu in payload.get("profileUsers", []):
            for s in pu.get("settings", []):
                name = s.get("id")
                if isinstance(name, str) and name in SETTING_NAME_TO_ID:
                    s["id"] = SETTING_NAME_TO_ID[name]
                    translated += 1
            # Legacy format also puts userId as int
            if isinstance(pu.get("id"), str) and pu["id"].isdigit():
                pu["id"] = int(pu["id"])
            if isinstance(pu.get("hostId"), str) and pu["hostId"].isdigit():
                pu["hostId"] = int(pu["hostId"])
        new_body = json.dumps(payload).encode("utf-8")
        flow.response.set_content(new_body)
        ctx.log.info(
            f"[xbl_bridge] profile-settings response shim: translated "
            f"{translated} setting keys back to numeric"
        )


addons = [XblBridge()]
