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
import logging
import logging.handlers
import os
import re
import ssl
import struct
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

# Full rolling log of everything routed through Python's logging system
# while mitmdump is up: [xbl_bridge] ctx.log messages, mitmproxy's per-flow
# request/response lines, internal errors. The launcher window scrolls and
# can't be scrolled back after a long session -- this file can, and errors
# reported by the user can be inspected on demand.
MITMDUMP_LOG = os.path.join(tempfile.gettempdir(), "xct_mitmdump.log")

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

# Magic hostname the bridge intercepts in-flow (never forwarded upstream)
# to expose pre-fetched XBL data to in-package game code that cannot
# authenticate via Microsoft.Xbox.dll's local LRPC (XblAuthManager rejects
# self-signed sideloads with non-registered TitleIds, so the in-package
# `Microsoft.Xna.Framework.GamerServices.Gamer.SignedInGamers` collection
# comes back empty -- no SignedInGamer to call BeginGetAchievements on).
#
# Companion `xct-<title>-patcher` projects rewrite the title's achievement
# load function to fetch from this URL instead of going through the dead
# WinRT path. Since the game is on the system proxy and has the loopback
# exemption, an HTTP request to this hostname is delivered to mitmproxy,
# the addon recognises the magic host, and synthesises a response from
# data the bridge already has (XBL3.0 token + the user's XUID) by querying
# achievements.xboxlive.com on the user's behalf.
BRIDGE_INTERCEPT_HOST = "xct-bridge.invalid"

# TitleIds we proxy achievements for. Populated at bootstrap once we have
# the XBL3.0 token, then served from cache on subsequent requests to
# `http://xct-bridge.invalid/achievements/<titleId>`. Add a TitleId here
# when adding a sideloaded Win8 game whose Microsoft.Xbox.dll path is
# broken; the matching IL patcher (e.g. xct-gravityguy-patcher) replaces
# the game's Cocos2d.dll achievement loader to hit the magic URL.
ACHIEVEMENT_PROXY_TITLEIDS = {
    961415122,  # Gravity Guy (Miniclip SA, sideload via xct-gravityguy-patcher)
}

# Microsoft Store Content IDs known to be revoked from MS's catalog.
# Requests carrying these get rewritten to use KNOWN_GOOD_CONTENT_ID
# (learned at runtime, or supplied via the XCT_KNOWN_GOOD_CONTENT_ID
# environment variable) so MS issues a real signed license that
# Microsoft.Xbox.dll's PlayReady verifier can accept structurally --
# even if the licensed content GUID doesn't match the one the title
# asked about. (The bet is that MS-Xbox.dll only validates "is this a
# valid MS-signed license", not "is this a license for THIS content".)
REVOKED_CONTENT_IDS = {
    "714C3220-7798-F4AE-071D-9C1C8F40558F",  # Microsoft Taptiles
}
KNOWN_GOOD_CONTENT_ID_ENV = os.environ.get("XCT_KNOWN_GOOD_CONTENT_ID", "").strip()

# --- Per-title rewrite tables (loaded from xct-win8pass) --------------
#
# Four allowlists drive per-title rewrites in this addon:
#
#   ENTITLEMENT_FORGE_CONTENT_IDS    - licensing.mp.microsoft.com responses
#                                       whose top-level `contentId` matches
#                                       get their satisfactionFailure block
#                                       stripped.
#   UPSELL_BYPASS_PRODUCT_IDS         - licensing.mp.microsoft.com responses
#                                       whose satisfactionFailure.remediation-
#                                       ProductSkus contain a matching
#                                       productId get the same treatment.
#   ACQUIRE_RECEIPT_FORGE_PRODUCT_IDS - licensingwindows.mp/AcquireReceipt
#                                       responses for these productIds get
#                                       forged into a success body when MS
#                                       returns an error.
#   _SHIM_TITLEGROUPS                 - titlestorage.xboxlive.com 401/403
#                                       under any of these titlegroups gets
#                                       rewritten to 200 {} (empty body).
#                                       Allowlist not blanket -- Minesweeper
#                                       relies on a real 403 to fall back to
#                                       progress.xboxlive.com.
#
# All four come from %PROGRAMDATA%\xct\bridge_titles.json, which is
# regenerated by xct-win8pass's patch.ps1 every time it runs (one entry
# per titles/<PackageName>.json). Per-title knowledge lives in that repo;
# this bridge stays game-agnostic.
#
# If the config file is missing the bridge still works -- per-title
# rewrites just don't fire. A clear warning is logged once at startup.

def _load_bridge_titles_config() -> dict[str, set[str]]:
    """Load %PROGRAMDATA%\\xct\\bridge_titles.json (written by
    xct-win8pass) into the four allowlist sets. Returns empty sets on
    missing/malformed file (with a warning -- the bridge is still useful
    for diagnostics without per-title rewrites)."""
    empty = {
        "titlestorage_shim_titlegroups":     set(),
        "upsell_bypass_product_ids":         set(),
        "entitlement_forge_content_ids":     set(),
        "acquire_receipt_forge_product_ids": set(),
    }
    cfg_path = os.path.join(
        os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
        "xct", "bridge_titles.json",
    )
    if not os.path.isfile(cfg_path):
        logging.warning(
            "[xbl_bridge] no per-title config at %s -- per-title rewrites "
            "(titlestorage shim / upsell bypass / entitlement forge) will "
            "not fire. Run xct-win8pass's patch.ps1 against any title to "
            "generate the file.", cfg_path,
        )
        return empty
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        logging.warning(
            "[xbl_bridge] failed to parse %s: %s -- per-title rewrites disabled.",
            cfg_path, exc,
        )
        return empty
    return {
        "titlestorage_shim_titlegroups":     {s.lower() for s in data.get("titlestorage_shim_titlegroups",   []) or []},
        "upsell_bypass_product_ids":         {s.upper() for s in data.get("upsell_bypass_product_ids",       []) or []},
        "entitlement_forge_content_ids":     {s.upper() for s in data.get("entitlement_forge_content_ids",   []) or []},
        "acquire_receipt_forge_product_ids": {s.upper() for s in data.get("acquire_receipt_forge_product_ids", []) or []},
    }


_BRIDGE_TITLES_CFG = _load_bridge_titles_config()
ENTITLEMENT_FORGE_CONTENT_IDS     = _BRIDGE_TITLES_CFG["entitlement_forge_content_ids"]
UPSELL_BYPASS_PRODUCT_IDS         = _BRIDGE_TITLES_CFG["upsell_bypass_product_ids"]
ACQUIRE_RECEIPT_FORGE_PRODUCT_IDS = _BRIDGE_TITLES_CFG["acquire_receipt_forge_product_ids"]
logging.info(
    "[xbl_bridge] per-title config: %d titlegroups, %d upsell pids, "
    "%d entitlement-forge content IDs, %d acquire-receipt forge pids",
    len(_BRIDGE_TITLES_CFG["titlestorage_shim_titlegroups"]),
    len(UPSELL_BYPASS_PRODUCT_IDS),
    len(ENTITLEMENT_FORGE_CONTENT_IDS),
    len(ACQUIRE_RECEIPT_FORGE_PRODUCT_IDS),
)

# Modern XBL3 auth chain endpoints. When a title (sideloaded with a non-
# Microsoft signing cert, license-revoked, or otherwise running with an
# identity Microsoft's XBL backend doesn't recognise) calls these, the
# real server rejects -- title.auth is the typical failure point because
# it cross-checks the package's signing-cert hash against Microsoft's
# title registry. We short-circuit each endpoint with a forged success
# response carrying the bridge's pre-minted UserToken / XSTS so the
# title proceeds straight to the achievements / profile / etc. fetches
# this addon already bridges.
#
# This generalises the WS-Trust forgery we do for legacy clients
# (auth.xboxlive.com/XSts) to the modern XBL3 chain. Together they
# cover both legacy SDK titles (Mahjong/Minesweeper/Solitaire/Adera) and
# modern XBL3 titles (Taptiles, plus any future revoked/sideloaded title)
# without per-title fixes.
MODERN_AUTH_FORGE_HOSTS = {
    "user.auth.xboxlive.com",
    "title.auth.xboxlive.com",
    "xsts.auth.xboxlive.com",
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

# Loaded from xct-win8pass's bridge_titles.json (see top of file).
# Allowlist not blanket: Minesweeper's `SyncedData.json` path *needs*
# the 403 so the game falls back to progress.xboxlive.com/achievements
# -- shimming universally broke its Awards page.
_SHIM_TITLEGROUPS = _BRIDGE_TITLES_CFG["titlestorage_shim_titlegroups"]
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


def _rep_label_to_score(label) -> float:
    """Map XboxOneRep label strings to a 0-100 score for shim consumers.

    Microsoft.Xbox.IUserProfile.Reputation is typed Double in the winmd,
    but profile.xboxlive.com returns the rep as a label string ("GoodPlayer",
    "AvoidMe", etc.). Convert via the same buckets the current Xbox UI uses.
    """
    if not label:
        return 75.0
    key = str(label).strip().lower().replace(" ", "")
    return {
        "goodplayer":   75.0,
        "averageplayer": 50.0,
        "needswork":    25.0,
        "avoidme":       5.0,
    }.get(key, 75.0)


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

class _SuppressConnectionEvents(logging.Filter):
    """Hide mitmproxy's per-TCP-connection chatter from the terminal.

    mitmproxy's view filter (`~d xboxlive.com` on the command line) only
    suppresses per-*flow* log lines. Connection-level events fire earlier
    in the pipeline — before a flow exists — so the user's general
    browsing traffic (Discord, Google, Discord CDN, gstatic, etc.) still
    shows up as `client connect` / `server connect` lines in the launcher
    window even with the flow filter in place. Content-filter those
    specific messages here so the launcher stays focused on xboxlive.com.
    """

    _NEEDLES = (
        "client connect",
        "server connect",
        "client disconnect",
        "server disconnect",
        # System-wide proxy means non-game apps (Edge, Slack, Discord,
        # telemetry, etc.) also hit mitmproxy. Some of them speak HTTP/2
        # but include hop-by-hop headers (Connection / Upgrade / Keep-
        # Alive) that RFC 7540 forbids in HTTP/2 framing. mitmproxy
        # correctly rejects them and logs one line per flow; that's
        # pure noise from the bridge's perspective. The xboxlive titles
        # we care about don't trigger this -- if they ever did, the
        # bridge would show 401/403 follow-ups which we'd notice anyway.
        "HTTP/2 protocol error: Connection-specific header field present",
    )

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        return not any(n in msg for n in self._NEEDLES)


class XblBridge:
    def __init__(self) -> None:
        self.signer: RequestSigner | None = None
        self.xbl3_auth: str | None = None
        # Raw cached tokens for the modern XBL3 auth-chain forgery. We
        # need them separately from xbl3_auth so we can drop them into
        # forged user.auth / xsts.auth response bodies without re-parsing
        # "XBL3.0 x=<uhs>;<jwt>" each time.
        self.user_token: str | None = None
        self.xsts_token_raw: str | None = None
        self.uhs: str = ""
        self.xuid: str = ""
        self.gamertag: str = ""
        self.account: str = ""
        self.rewrote = 0
        self.passthrough_legacy = 0
        self.signed = 0
        # One-shot flag so we only dump the full decoded license-challenge
        # XML once per session (it can be ~2KB and the title polls
        # constantly -- printing it every iteration drowns the log).
        self._license_xml_dumped = False
        # Content ID substituted into license requests for revoked titles.
        # Seeded from XCT_KNOWN_GOOD_CONTENT_ID env var if set, otherwise
        # learned passively the first time another app on the system makes
        # a successful licensing.mp.microsoft.com call.
        self._known_good_content_id: str | None = (
            KNOWN_GOOD_CONTENT_ID_ENV or None
        )
        # Consecutive-duplicate log suppression for titlestorage shims.
        # Mahjong polls titlestorage every couple hundred ms; without this
        # the launcher window becomes unreadable. _log_titlestorage_shim
        # collapses runs of identical (method, kind) events into a
        # "(repeated Nx)" flush line emitted when a different event arrives.
        self._ts_shim_last_key: tuple[str, str] | None = None
        self._ts_shim_dup_count = 0
        # Tri-state learned from observing the real auth.xboxlive.com/XSts
        # response. None = not yet observed, True = upstream returned a
        # real <jwt .../> (this user's MSA still works end-to-end against
        # the legacy XBL2.0 backend — bridge stays silent), False =
        # upstream rejected with x-err=0x8015DA87 or similar, so we forge
        # the response and keep rewriting XBL2.0→XBL3.0 on later requests.
        #
        # The SAZ captured from a signed-in user with no bridge running
        # proved the legacy endpoints are partially live — Microsoft
        # appears to be rolling a fix out unevenly. Making the bridge
        # reactive (forge only on observed failure) means users in the
        # working cohort get native end-to-end and the "Microsoft-friendly
        # PoC" story stays honest.
        self._legacy_backend_works: bool | None = None
        # Pre-fetched, JSON-encoded achievement payloads keyed by TitleId.
        # Populated by _fetch_achievements_for_proxy_titles() at bootstrap;
        # served from the magic BRIDGE_INTERCEPT_HOST request handler.
        self._achievements_cache: dict[int, bytes] = {}

    def running(self) -> None:
        # Attach the connection-event suppressor to every registered log
        # handler. mitmproxy's termlog addon installs its handler on the
        # root logger by the time `running` fires.
        _quiet = _SuppressConnectionEvents()
        root = logging.getLogger()
        for h in root.handlers:
            h.addFilter(_quiet)

        # Tee every log record to a rotating file so after-session
        # debugging is possible. Deliberately WITHOUT the _quiet filter
        # (terminal stays clean, log stays verbose) and at DEBUG level
        # so connection events, flow details, and internal mitmproxy
        # warnings are all captured. 10 MB per file, keep 2 backups.
        try:
            with open(MITMDUMP_LOG, "a", encoding="utf-8") as banner:
                now = datetime.datetime.now().isoformat(timespec="seconds")
                banner.write(
                    f"\n{'='*60}\n=== session start {now} ===\n{'='*60}\n"
                )
            fh = logging.handlers.RotatingFileHandler(
                MITMDUMP_LOG,
                maxBytes=10_000_000,
                backupCount=2,
                encoding="utf-8",
            )
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)-5s %(name)s: %(message)s"
            ))
            root.addHandler(fh)
            # Raise root level if it's currently higher than DEBUG, else
            # the FileHandler won't see DEBUG/INFO records.
            if root.level == logging.NOTSET or root.level > logging.DEBUG:
                root.setLevel(logging.DEBUG)
            ctx.log.info(f"[xbl_bridge] full log -> {MITMDUMP_LOG}")
        except Exception as exc:
            ctx.log.warn(
                f"[xbl_bridge] could not open log file {MITMDUMP_LOG}: {exc}"
            )

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
        self.user_token = user_token
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
        self.xsts_token_raw = xsts_token
        self.xbl3_auth = f"XBL3.0 x={self.uhs};{xsts_token}"
        ctx.log.info(
            f"[xbl_bridge] READY — gamertag={self.gamertag} xuid={self.xuid} "
            f"simple XSTS token_len={len(xsts_token)}"
        )
        if self._known_good_content_id:
            ctx.log.info(
                f"[xbl_bridge]   license rewrite seeded with Content ID "
                f"{self._known_good_content_id}"
            )

        self._fetch_achievements_for_proxy_titles()

    def _fetch_achievements_for_proxy_titles(self) -> None:
        """Pre-fetch achievement state from achievements.xboxlive.com for
        every TitleId in ACHIEVEMENT_PROXY_TITLEIDS. The bridge has the
        XBL3.0 token + the user's XUID, so it can read the user's actual
        progress directly (the in-package Microsoft.Xbox.dll path the game
        would normally use is broken on self-signed sideloads -- see
        BRIDGE_INTERCEPT_HOST docstring).

        Cached as JSON bytes ready to serve; refreshed only on bridge
        restart (the user's earned achievements rarely change mid-session).
        """
        if not self.xuid or not self.xbl3_auth:
            return
        for tid in ACHIEVEMENT_PROXY_TITLEIDS:
            try:
                # Contract version 1 is what Win8-era / Xbox 360 titles like
                # Gravity Guy use server-side. v2 returns 200 with
                # `totalRecords: 0` because v2 only lists titles whose
                # achievements have been migrated to the modern service
                # config schema; v1 returns the legacy XACH-style rows for
                # this title.
                #
                # v1 returns ONLY the user's unlocked achievements (verified
                # against `unlockedOnly=false`, `types=Persistent`, and the
                # title-level `/titles/{tid}/achievements` path which 404s
                # in v1). The full title roster (locked + unlocked, with
                # names/descriptions/imageIds) lives in the game's
                # in-package `xbl.spa` (XACH chunk); the patched game-side
                # achievement loader merges the bridge's earned-only list
                # with that local roster to render the panel.
                url = (
                    f"https://achievements.xboxlive.com/users/xuid({self.xuid})"
                    f"/achievements?titleId={tid}"
                )
                req = urllib.request.Request(url, headers={
                    "Authorization": self.xbl3_auth,
                    "x-xbl-contract-version": "1",
                    "Accept": "application/json",
                })
                with _NOPROXY_OPENER.open(req, timeout=15) as resp:
                    raw = resp.read()
                data = json.loads(raw.decode("utf-8"))
                achievements = data.get("achievements") or []

                # Collapse MS's v1 schema to the minimum the game-side
                # helper expects. Each item has:
                #   id (int), name, description, lockedDescription,
                #   unlocked (bool), gamerscore (int), isSecret (bool),
                #   imageId, timeUnlocked, ...
                simplified = []
                for a in achievements:
                    earned = bool(a.get("unlocked"))
                    simplified.append({
                        "id": str(a.get("id", "")),
                        "name": a.get("name") or "",
                        "description": (
                            a.get("description")
                            or a.get("lockedDescription")
                            or ""
                        ),
                        "percent": 100.0 if earned else 0.0,
                        "score": int(a.get("gamerscore") or 0),
                        "hidden": bool(a.get("isSecret", False)),
                    })

                self._achievements_cache[tid] = json.dumps(simplified).encode("utf-8")
                n_earned = sum(1 for a in simplified if a["percent"] >= 100)
                ctx.log.info(
                    f"[xbl_bridge] achievement proxy: TitleId {tid} -> "
                    f"{len(simplified)} achievements ({n_earned} earned)"
                )
            except Exception as exc:
                ctx.log.warn(
                    f"[xbl_bridge] achievement proxy: fetch failed for "
                    f"TitleId {tid}: {exc}"
                )

    def request(self, flow: http.HTTPFlow) -> None:
        if self.xbl3_auth is None:
            return
        host = flow.request.host or ""

        # Magic-URL handler. Game-side IL patches in companion
        # xct-<title>-patcher projects route data fetches that the
        # in-package Microsoft.Xbox.dll path can't deliver (because
        # XblAuthManager rejects the self-signed sideload) through
        # http://xct-bridge.invalid/<resource>. mitmproxy receives the
        # request via the system proxy; we synthesise the response and
        # never forward upstream.
        if host == BRIDGE_INTERCEPT_HOST:
            self._serve_bridge_intercept(flow)
            return

        # Microsoft Store license-content rewrite + shim. Sideloaded
        # copies of Store-revoked titles (Taptiles, etc.) call
        # licensing.mp.microsoft.com/v7.0/licenses/content with their
        # original Content ID; MS removed those Content IDs from the
        # catalog, so the real server returns 400 +
        # `ContentIdNotInCatalog`. The game loops on the call and never
        # proceeds to XBL auth.
        #
        # Two-tier strategy:
        #   1. Rewrite. The contentId is a top-level JSON field, NOT
        #      inside the signed ClientChallenge XML, so we can change
        #      it without breaking any signature. If we have a known-
        #      good Content ID (seeded from XCT_KNOWN_GOOD_CONTENT_ID
        #      or learned from observing another title's successful
        #      licensing call this session), substitute it and let the
        #      modified request flow upstream. MS issues a real signed
        #      license for the substitute content -- the bet is that
        #      Microsoft.Xbox.dll's PlayReady verifier accepts any
        #      MS-signed license without cross-checking the content ID
        #      it asked about.
        #   2. Empty-shim fallback. If we don't yet have a known-good
        #      Content ID to substitute, return an empty-license body
        #      (no policies / licenses / contentLicenses). This isn't
        #      enough on its own (PlayReady-style verification expects
        #      structure), but keeps the network noise contained while
        #      the user runs another working title to seed the cache.
        #
        # Lives BEFORE the .xboxlive.com early-out on purpose: this
        # endpoint isn't on xboxlive.com.
        if (
            host == "licensing.mp.microsoft.com"
            and flow.request.path.startswith("/v7.0/licenses/content")
        ):
            # Only act on requests for KNOWN-revoked Content IDs.
            # Non-revoked titles (Mahjong, Wordament, etc.) have valid
            # entries in MS's catalog and should reach the real server
            # unmodified -- we got bitten earlier by intercepting all
            # license traffic and feeding back empty-license, which made
            # the game think it had no license.
            try:
                req_body = flow.request.get_content() or b""
                req_json = json.loads(req_body.decode("utf-8"))
                cid = (req_json.get("contentId") or "").upper()
            except Exception:
                cid = ""
            if cid not in {r.upper() for r in REVOKED_CONTENT_IDS}:
                return  # Pass through to MS unmodified.

            if self._maybe_rewrite_license_request(flow):
                # Modified body, let mitmproxy forward upstream. Don't
                # set flow.response.
                return
            # Revoked title and no known-good substitute available --
            # fall back to empty-shim. Better than letting the real
            # 400/ContentIdNotInCatalog reach the game (which polls
            # forever); empty 200 at least varies the response shape
            # so the game might progress to other startup paths.
            synth = json.dumps({
                "policies": [],
                "licenses": [],
                "contentLicenses": [],
            }).encode("utf-8")
            flow.response = http.Response.make(
                200, synth,
                {"Content-Type": "application/json", "Cache-Control": "no-store"},
            )
            ctx.log.info(
                f"[xbl_bridge] license-content shim: synthesised 200 empty-license "
                f"for revoked contentId={cid} (no known-good substitute yet)"
            )
            return

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

        # Modern XBL3 auth chain forgery. Short-circuit user.auth /
        # title.auth / xsts.auth with synthetic success responses carrying
        # the bridge's pre-minted tokens. See MODERN_AUTH_FORGE_HOSTS doc.
        if host in MODERN_AUTH_FORGE_HOSTS:
            forged = self._forge_modern_auth_response(host)
            if forged is not None:
                flow.response = http.Response.make(
                    200, forged,
                    {"Content-Type": "application/json", "Cache-Control": "no-store"},
                )
                ctx.log.info(
                    f"[xbl_bridge] forged modern XBL3 auth: "
                    f"{flow.request.method} {host}{flow.request.path[:80]}"
                )
                return

        # Legacy XSts mint call (auth.xboxlive.com/XSts/xsts.svc/IWSTrust13):
        # pass through to the real server and intercept the RESPONSE. If
        # upstream rejects with x-err=0x8015DA87 (WLID1.0 deprecated for
        # this MSA) the response hook forges a success body carrying the
        # bridge's modern XBL3 JWT; if upstream returns a real <jwt .../>
        # (MS's partial fix is active for this user) we leave everything
        # alone so the game signs in natively. See _handle_xsts_response.
        # Return here without setting flow.response so mitmproxy forwards
        # upstream.
        if host in ("auth.xboxlive.com", "activeauth.xboxlive.com") and \
                flow.request.path.startswith("/XSts"):
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

        # Always rewrite XBL2.0 -> XBL3.0 (except for XBL20_ONLY_HOSTS
        # handled above). The earlier `_legacy_backend_works is True`
        # short-circuit was based on the assumption that "if XSts mints
        # a real <jwt>, the rest of the legacy XBL2 chain still works
        # for this user." Hitman GO disproved it: this MSA's XSts call
        # returns a real XBL2 JWT, but profile.xboxlive.com (and likely
        # other downstream services) reject it with 401 token_required
        # because they no longer parse the `XBL2.0 x=<jwt v="1.0" .../>`
        # XML wrapper. So even when the game has a "valid" legacy token,
        # we still need to swap it for our XBL3.0 token to make the
        # downstream calls succeed. _legacy_backend_works is kept as a
        # one-shot informational log (see _handle_xsts_response) so the
        # launcher window still surfaces the cohort the user is in.
        # Rewrite: swap the Authorization header; leave everything else —
        # including `x-xbl-contract-version` and the request body — alone.
        # Empirically the server handles Mahjong's v=1 legacy-shaped payloads
        # correctly when presented a modern XBL3.0 token; bumping the
        # contract version or translating the body to modern schema actively
        # breaks Mahjong's (legacy-shaped) response parser.
        flow.request.headers["Authorization"] = self.xbl3_auth

        self.rewrote += 1
        # Suppress the per-request "bridged" log for titlestorage hosts.
        # Mahjong polls them dozens of times per second and the shim log
        # emitted from the response hook already captures the interesting
        # information (403 -> 200 rewrite). Keeping both floods the window.
        if host == "titlestorage.xboxlive.com":
            return
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

        # Microsoft Store license-service traces + passive content-ID
        # learning + entitlement forging. All run on licensing.mp
        # responses.
        if host == "licensing.mp.microsoft.com" and flow.response:
            self._maybe_forge_entitlement_response(flow)
            self._maybe_learn_known_good_content_id(flow)

        # Win8-era license-receipt endpoint. Used by Wordament-class
        # titles to fetch the app's purchase receipt; MS returns
        # ErrorCode="0xc03f300a" when the user has no receipt for the
        # requested productId (typical for sideloads or de-listed
        # titles). Rewrite to ErrorCode="0" so the game treats receipt-
        # check as passed and proceeds to XBL auth.
        if host == "licensingwindows.mp.microsoft.com" and flow.response:
            self._maybe_forge_acquire_receipt(flow)

        # Catch-all trace for dead-game-backend hosts so we can see
        # exactly what response Wordament-class titles are getting from
        # their original Microsoft Studios servers (most are retired).
        # Single-line summary; if a host needs deeper inspection we can
        # extend per-host.
        DEAD_BACKEND_TRACE_HOSTS = (
            "ping.wordament.net",
            "wordament.net",
            "licensing.mp.microsoft.com",
            "licensingwindows.mp.microsoft.com",
            "storeedge.microsoft.com",
            "collections.mp.microsoft.com",
            "da.xboxservices.com",
        )
        if host in DEAD_BACKEND_TRACE_HOSTS and flow.response:
            req_body = (flow.request.get_content() or b"")[:200]
            resp_body = (flow.response.content or b"")[:300]
            ctx.log.info(
                f"[xbl_bridge] DEAD-BACKEND-TRACE {flow.request.method} "
                f"{host}{flow.request.path[:80]} -> {flow.response.status_code} "
                f"req={req_body!r} resp={resp_body!r}"
            )
            if not self._license_xml_dumped:
                self._license_xml_dumped = True
                req_full = flow.request.get_content() or b""
                resp_full = flow.response.content or b""
                # Dump the FULL request body (uncompressed, decoded). The
                # ClientChallenge XML inside is just protocol metadata --
                # the Content ID and any per-call signatures live in
                # OTHER JSON fields at the top level. Also pretty-print
                # the JSON keys + first chars of each value so structural
                # inspection doesn't drown in 12 KB of base64 blobs.
                try:
                    req_json = json.loads(req_full.decode("utf-8"))
                    keys_summary = "\n".join(
                        f"      {k}: {repr(v)[:200]}{'...' if len(repr(v)) > 200 else ''}"
                        for k, v in req_json.items()
                    )
                    challenge_b64 = req_json.get("clientChallenge", "")
                    try:
                        decoded_xml = base64.b64decode(challenge_b64).decode("utf-8", errors="replace")
                    except Exception:
                        decoded_xml = "<<challenge decode failed>>"
                except Exception as exc:
                    keys_summary = f"<<json parse failed: {exc}>>"
                    decoded_xml = ""
                ctx.log.info(
                    f"[xbl_bridge] LICENSE-DUMP one-shot full trace for "
                    f"{flow.request.method} {flow.request.path}\n"
                    f"  status: {flow.response.status_code}\n"
                    f"  request_body_len: {len(req_full)} bytes\n"
                    f"  request_json_keys (truncated values):\n{keys_summary}\n"
                    f"  decoded_challenge_xml ({len(decoded_xml)} chars):\n"
                    f"    {decoded_xml}\n"
                    f"  response_body ({len(resp_full)} bytes):\n"
                    f"    {resp_full[:2000].decode('utf-8', errors='replace')}"
                )
            else:
                ctx.log.info(
                    f"[xbl_bridge] LICENSE-TRACE {flow.request.method} "
                    f"{flow.request.path[:80]} -> {flow.response.status_code}"
                )
            return

        if not host.endswith(".xboxlive.com"):
            return

        # Reactive XSts forgery. See _handle_xsts_response.
        if (
            host in ("auth.xboxlive.com", "activeauth.xboxlive.com")
            and flow.request.path.startswith("/XSts")
            and flow.response
        ):
            self._handle_xsts_response(flow)
            # Do not return — let the AUTH-TRACE block below log the final
            # (possibly forged) state for observability.

        # titlestorage 401/403 shim, whitelisted per-titlegroup. Both
        # status codes share the same root cause (the bridge mints a
        # generic non-title-scoped XSTS so titlestorage rejects it),
        # so both rewrite identically. Keflings hits 401 with
        # `token_required` instead of 403 -- same effect.
        if (
            host == "titlestorage.xboxlive.com"
            and flow.response
            and flow.response.status_code in (401, 403)
            and _titlestorage_should_shim(flow.request.path)
        ):
            self._shim_titlestorage(flow)
            return

        # packagespc.xboxlive.com/GetBasePackage 403 shim. The PackagesPC
        # service validates that an installed UWP package is registered
        # with Xbox Live and returns JSON metadata. The bridge's XSTS is
        # minted with RelyingParty=http://xboxlive.com (no per-title
        # scope), so this endpoint replies 403 / empty WWW-Authenticate.
        # Hitman GO treats that rejection as "Xbox Live unavailable" and
        # never proceeds to achievements/profile/etc. -- the Achievements
        # page just shows "Unable to connect to Xbox at this time."
        # Synthesize 200(empty) so the title's state machine moves past
        # the package-validation gate. Other Microsoft.Xbox.dll titles
        # (Mahjong, Solitaire, Adera, Wordament, ...) don't gate their
        # XBL stack on packagespc, so this is safe to apply universally.
        if (
            host == "packagespc.xboxlive.com"
            and flow.response
            and flow.response.status_code == 403
            and flow.request.path.startswith("/GetBasePackage/")
        ):
            flow.response.status_code = 200
            flow.response.headers["Content-Type"] = "application/json"
            flow.response.set_content(b"{}")
            ctx.log.info(
                f"[xbl_bridge] packagespc shim: 403 -> 200(empty) "
                f"{flow.request.path[:100]}"
            )
            return

        # progress.xboxlive.com/.../progress/titleachievements returns the
        # full per-title achievement catalog with `unlocked:false` on every
        # row, even when the user has earned achievements on the modern
        # service (the Win8-era unlock state never propagated forward when
        # MS migrated to achievements.xboxlive.com). Without a merge, in-
        # game Achievements panels for titles that read this endpoint
        # (Assassin's Creed Pirates, ...) display every entry as locked.
        # Fetch the v1 unlocked list and stamp `unlocked` / `unlockedOnline`
        # / `timeUnlocked` onto matching catalog rows.
        if (
            host == "progress.xboxlive.com"
            and flow.response
            and flow.response.status_code == 200
            and flow.request.method == "GET"
            and "/progress/titleachievements" in (flow.request.path or "")
        ):
            self._maybe_merge_progress_titleachievements(flow)

        # Log every game-side modern XBL auth-endpoint response with a body
        # snippet. Modern XBL3 titles (e.g. Taptiles) bypass the legacy
        # IWSTrust13 forgery path entirely and mint their own UserToken /
        # TitleToken / XSTS via these endpoints; when sign-in fails for
        # such a title, the body of the failed request usually carries the
        # x-err code or an "Identity" / "Restricted" reason that tells us
        # exactly where the auth chain broke. Low frequency (only during
        # sign-in), high value.
        AUTH_TRACE_HOSTS = (
            "user.auth.xboxlive.com",
            "device.auth.xboxlive.com",
            "title.auth.xboxlive.com",
            "xsts.auth.xboxlive.com",
        )
        if flow.response and host in AUTH_TRACE_HOSTS:
            body = (flow.response.content or b"")[:400]
            try:
                body_repr = body.decode("utf-8", errors="replace")
            except Exception:
                body_repr = repr(body)
            x_err = flow.response.headers.get("x-err", "")
            ctx.log.info(
                f"[xbl_bridge] AUTH-TRACE {flow.request.method} {host}{flow.request.path[:80]} "
                f"-> {flow.response.status_code}"
                + (f" x-err={x_err}" if x_err else "")
                + f" body={body_repr!r}"
            )

        # Surface any 4xx/5xx on xboxlive hosts (was previously only
        # 401/403). Modern auth chain rejections often come back as 400
        # or 503; we want to see those too rather than have them silently
        # roll past in the launcher window. Include the request's
        # Authorization header (truncated) and both bodies so the bridge
        # log alone is enough to diagnose without firing up Fiddler.
        if flow.response and flow.response.status_code >= 400:
            req_body = (flow.request.get_content() or b"")[:400]
            resp_body = (flow.response.content or b"")[:400]
            req_auth = flow.request.headers.get("Authorization", "")
            ctx.log.warn(
                f"[xbl_bridge] {flow.response.status_code} on {flow.request.method} "
                f"{host}{flow.request.path[:120]}  "
                f"wwwauth={flow.response.headers.get('WWW-Authenticate', '')[:120]!r} "
                f"x-err={flow.response.headers.get('x-err', '')!r} "
                f"req_auth={req_auth[:160]!r} "
                f"req_body={req_body!r} "
                f"resp_body={resp_body!r}"
            )

        # Per-flow trace for `*.xboxlive.com` traffic so the bridge log
        # alone is enough to diagnose any title-side failure -- no need
        # to fire up Fiddler/HAR. Skips a small set of high-frequency
        # polling hosts (titlestorage already has its own dedup-
        # collapsed shim log, userpresence pings every minute and adds
        # no diagnostic value) to keep the log readable. Set
        # XCT_TRACE_XBL=0 to disable entirely.
        XBL_TRACE_SKIP_HOSTS = {
            "titlestorage.xboxlive.com",
            "userpresence.xboxlive.com",
        }
        if (
            flow.response
            and host not in XBL_TRACE_SKIP_HOSTS
            and os.environ.get("XCT_TRACE_XBL", "1") != "0"
        ):
            req_body = (flow.request.get_content() or b"")[:300]
            resp_body = (flow.response.content or b"")[:300]
            req_auth = flow.request.headers.get("Authorization", "")
            ctx.log.info(
                f"[xbl_bridge] XBL-TRACE {flow.request.method} "
                f"{host}{flow.request.path[:120]} -> "
                f"{flow.response.status_code} "
                f"req_auth={req_auth[:120]!r} "
                f"req_body={req_body!r} "
                f"resp_body={resp_body!r}"
            )

    def _serve_bridge_intercept(self, flow: http.HTTPFlow) -> None:
        """Synthesise a response for an `xct-bridge.invalid` request.

        Endpoint family for the Microsoft.Xbox.dll shim
        (`xct-msxbox-shim`) — every method body in the shim that needs
        live XBL data calls one of these. The bridge holds the user's
        XBL3.0 token + XUID after `_bootstrap()`, so it can talk to
        `*.xboxlive.com` directly without proxy-loop concerns.

        Routes:
          GET  /xbox/user
              -> {"xuid": 2533..., "gamertag": "XCT dot LIVE"}
          GET  /xbox/users/{xuid}/profile
              -> {"gamertag", "gamerscore", "gamerPictureUrl", ...}
          GET  /xbox/users/{xuid}/title/{titleId}/achievements
                  ?skipItems=N&maxItems=N&unlockedOnly=true
              -> {"items": [<Achievement>, ...], "totalRecords": N}
              Schema matches Microsoft.Xbox.Achievement directly:
                {id, name, description, lockedDescription, gamerscore,
                 isEarned, isSecret, imageId, sequence, timeUnlocked,
                 titleId, type, flags, unlockedOnline, platform,
                 pictureUrl}
          POST /xbox/users/{xuid}/title/{titleId}/achievements/{aid}/unlock
              -> {} (200) — submits unlock to MS's achievements service
          GET  /xbox/title/{titleId}/leaderboards
              -> {"items": [<LeaderboardMetadata>, ...]}  (TODO)
          GET  /xbox/users/{xuid}/titlegroups/{guid}/storage
                  ?path=&skipItems=&maxItems=
              -> {"items": [<TitleStorageFile>, ...], "totalRecords": N} (TODO)

        Legacy compat:
          GET  /achievements/{titleId}
              -> simplified earned-only list (used by xct-gravityguy-patcher's
                 Cocos2d.dll IL hook -- pre-shim integration).

        Anything else returns 404 with a diagnostic body.
        """
        path = (flow.request.path or "/").split("?", 1)[0]
        method = flow.request.method

        routes = [
            ("GET",  r"^/xbox/user$",                                                  self._h_xbox_user_current),
            ("GET",  r"^/xbox/users/(?P<xuid>\d+)/profile$",                          self._h_xbox_user_profile),
            ("GET",  r"^/xbox/users/(?P<xuid>\d+)/title/(?P<tid>\d+)/achievements$", self._h_xbox_user_title_achievements),
            ("POST", r"^/xbox/users/(?P<xuid>\d+)/title/(?P<tid>\d+)/achievements/(?P<aid>\d+)/unlock$", self._h_xbox_achievement_unlock),
            # Diagnostic sink. The shim's xct::state::Trace() POSTs every
            # event here so it shows up in mitmdump even when the
            # package dir is read-only for UWP app-container writes.
            ("POST", r"^/xbox/diag$",                                                  self._h_xbox_diag),
            # legacy compat for the existing Cocos2d helper
            ("GET",  r"^/achievements/(?P<tid>\d+)$",                                  self._h_legacy_earned_names),
        ]
        for m_method, pattern, handler in routes:
            if method != m_method:
                continue
            match = re.match(pattern, path)
            if match:
                try:
                    handler(flow, **match.groupdict())
                except Exception as exc:
                    ctx.log.error(
                        f"[xbl_bridge] bridge-intercept handler {handler.__name__} "
                        f"raised: {type(exc).__name__}: {exc}"
                    )
                    if not flow.response:
                        flow.response = http.Response.make(
                            500, json.dumps({"error": str(exc)}).encode("utf-8"),
                            {"Content-Type": "application/json"},
                        )
                return

        ctx.log.warn(f"[xbl_bridge] bridge-intercept: no route for {method} {path!r}")
        flow.response = http.Response.make(
            404, json.dumps({"error": f"no route for {method} {path}"}).encode("utf-8"),
            {"Content-Type": "application/json"},
        )

    # --- bridge-intercept handlers ---------------------------------------

    def _h_xbox_diag(self, flow: http.HTTPFlow) -> None:
        """POST /xbox/diag — log a shim-side diagnostic event."""
        body = (flow.request.get_content() or b"").decode("utf-8", errors="replace")
        ctx.log.info(f"[xbl_bridge] SHIM-DIAG {body}")
        flow.response = http.Response.make(
            204, b"", {"Content-Type": "text/plain"},
        )

    def _h_xbox_user_current(self, flow: http.HTTPFlow) -> None:
        """GET /xbox/user — current signed-in user identity."""
        if not self.xuid or not self.gamertag:
            flow.response = http.Response.make(
                503, json.dumps({"error": "bridge not bootstrapped"}).encode(),
                {"Content-Type": "application/json"},
            )
            return
        body = json.dumps({
            "xuid": int(self.xuid) if self.xuid.isdigit() else self.xuid,
            "gamertag": self.gamertag,
        }).encode("utf-8")
        flow.response = http.Response.make(
            200, body,
            {"Content-Type": "application/json", "Cache-Control": "no-store"},
        )
        ctx.log.info(f"[xbl_bridge] bridge-intercept: /xbox/user -> xuid={self.xuid}")

    def _h_xbox_user_profile(self, flow: http.HTTPFlow, xuid: str) -> None:
        """GET /xbox/users/{xuid}/profile — proxy peoplehub for the profile.

        Maps peoplehub's response into the Microsoft.Xbox.UserProfile
        WinRT shape (Gamertag, Gamerscore, GamerPictureUrl, Bio, ...).
        """
        # profile.xboxlive.com is the canonical XBL profile-settings API.
        # Returns a `profileUsers[].settings[]` array of {id, value} pairs
        # where id is the setting name (Gamertag, Gamerscore, ...).
        # Stable contract since Win10 launch; works for any xuid the
        # caller has read access to (which includes self).
        wanted = [
            "Gamertag",
            "Gamerscore",
            "GameDisplayPicRaw",
            "GameDisplayName",
            "AppDisplayName",
            "AppDisplayPicRaw",
            "Bio",
            "Location",
            "Motto",
            "RealName",
            "AccountTier",
            "XboxOneRep",
            "PublicGamerpic",
        ]
        url = (
            f"https://profile.xboxlive.com/users/xuid({xuid})/settings"
            f"?settings={','.join(wanted)}"
        )
        try:
            req = urllib.request.Request(url, headers={
                "Authorization": self.xbl3_auth or "",
                "x-xbl-contract-version": "3",
                "Accept": "application/json",
                "Accept-Language": "en-US",
            })
            with _NOPROXY_OPENER.open(req, timeout=15) as resp:
                upstream = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            ctx.log.warn(f"[xbl_bridge] /xbox/users/{xuid}/profile fetch failed: {exc}")
            flow.response = http.Response.make(
                502, json.dumps({"error": str(exc)}).encode(),
                {"Content-Type": "application/json"},
            )
            return

        users = upstream.get("profileUsers") or []
        if not users:
            flow.response = http.Response.make(
                404, json.dumps({"error": "user not found"}).encode(),
                {"Content-Type": "application/json"},
            )
            return
        # Flatten settings list to a name->value dict
        settings = {s.get("id"): s.get("value") for s in users[0].get("settings") or []}
        # Pick the best gamerpic url -- prefer PublicGamerpic, then GameDisplayPicRaw.
        pic = (
            settings.get("PublicGamerpic")
            or settings.get("GameDisplayPicRaw")
            or settings.get("AppDisplayPicRaw")
            or ""
        )
        out = {
            "gamertag":            settings.get("Gamertag") or "",
            "gamerscore":          int(settings.get("Gamerscore") or 0),
            "gamerPictureUrl":     pic,
            "smallGamerPictureUrl": pic,
            "avatarImageUrl":      pic,
            "hasAvatar":           bool(pic),
            "name":                settings.get("RealName") or "",
            "bio":                 settings.get("Bio") or "",
            "location":            settings.get("Location") or "",
            "motto":               settings.get("Motto") or "",
            # AccountTier comes back as "Gold" / "Silver" / "" -- pass through
            "membershipLevel":     settings.get("AccountTier") or "Silver",
            # XboxOneRep is a label ("GoodPlayer", "Avoid Me", "AvoidMe").
            # Microsoft.Xbox.IUserProfile.Reputation is a Double per the
            # winmd, so we map the label to a 0-100 score the way the
            # current Xbox UI does it (Avoid Me ~ 0, GoodPlayer ~ 75).
            "reputation": _rep_label_to_score(settings.get("XboxOneRep")),
            "reputationLabel":      settings.get("XboxOneRep") or "",
        }
        flow.response = http.Response.make(
            200, json.dumps(out).encode("utf-8"),
            {"Content-Type": "application/json"},
        )
        ctx.log.info(f"[xbl_bridge] bridge-intercept: /xbox/users/{xuid}/profile -> {out['gamertag']}")

    def _maybe_merge_progress_titleachievements(self, flow: http.HTTPFlow) -> None:
        """Stamp v1 unlock state onto a 200 progress.xboxlive.com
        /progress/titleachievements response.

        The legacy endpoint always reports `unlocked:false` for every row;
        the user's actual unlocks live on achievements.xboxlive.com (v1).
        For each catalog row whose `id` matches an unlocked v1 row, set
        `unlocked` / `unlockedOnline` true and copy the unlock timestamp
        + flags so the game's Achievements UI renders the user's progress.
        """
        m = re.match(
            r"^/users/xuid\((\d+)\)/progress/titleachievements",
            flow.request.path or "",
        )
        if not m:
            return
        xuid = m.group(1)
        tid = flow.request.query.get("titleId") if flow.request.query else None
        if not tid:
            return

        try:
            body = json.loads((flow.response.content or b"").decode("utf-8"))
        except Exception:
            return
        achievements = body.get("achievements")
        if not isinstance(achievements, list) or not achievements:
            return

        try:
            url = (
                f"https://achievements.xboxlive.com/users/xuid({xuid})"
                f"/achievements?titleId={tid}"
            )
            req = urllib.request.Request(url, headers={
                "Authorization": self.xbl3_auth or "",
                "x-xbl-contract-version": "1",
                "Accept": "application/json",
            })
            with _NOPROXY_OPENER.open(req, timeout=10) as resp:
                unlocked_data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            ctx.log.warn(
                f"[xbl_bridge] titleachievements merge: v1 fetch failed for "
                f"tid {tid}: {exc}"
            )
            return

        unlocked_by_id: dict[int, dict] = {}
        for a in (unlocked_data.get("achievements") or []):
            try:
                aid = int(a.get("id") or 0)
            except (TypeError, ValueError):
                continue
            if aid and bool(a.get("unlocked")):
                unlocked_by_id[aid] = a
        if not unlocked_by_id:
            ctx.log.info(
                f"[xbl_bridge] titleachievements merge: tid {tid} has no v1 "
                f"unlocks for xuid {xuid}, leaving response untouched"
            )
            return

        merged = 0
        for a in achievements:
            try:
                aid = int(a.get("id") or 0)
            except (TypeError, ValueError):
                continue
            u = unlocked_by_id.get(aid)
            if not u:
                continue
            a["unlocked"] = True
            a["unlockedOnline"] = True
            if u.get("timeUnlocked"):
                a["timeUnlocked"] = u["timeUnlocked"]
            if u.get("flags") is not None:
                a["flags"] = u["flags"]
            if u.get("platform") is not None:
                a["platform"] = u["platform"]
            merged += 1

        if merged == 0:
            return

        flow.response.set_content(json.dumps(body).encode("utf-8"))
        # Recompute Content-Length so downstream parsers don't read stale.
        if "Content-Length" in flow.response.headers:
            flow.response.headers["Content-Length"] = str(
                len(flow.response.content or b"")
            )
        ctx.log.info(
            f"[xbl_bridge] titleachievements merge: tid {tid} -> "
            f"{merged}/{len(achievements)} marked unlocked "
            f"(v1 returned {len(unlocked_by_id)} unlocked)"
        )

    def _h_xbox_user_title_achievements(
        self, flow: http.HTTPFlow, xuid: str, tid: str
    ) -> None:
        """GET /xbox/users/{xuid}/title/{tid}/achievements — full achievement list.

        Calls achievements.xboxlive.com with the v1 contract (the only
        shape that returns Win8-era achievements, per discovery).
        Returns Microsoft.Xbox.Achievement-shaped JSON, which the shim
        marshals 1:1 into WinRT objects.
        """
        # Parse query opts (skipItems, maxItems, unlockedOnly).
        # mitmproxy's flow.request.query is a MultiDictView, which exposes
        # .get() / .get_all() but isn't a string. Use it directly.
        q = flow.request.query
        unlocked_only = (q.get("unlockedOnly") or "false").lower() == "true"
        try:
            max_items = int(q.get("maxItems") or "100")
        except ValueError:
            max_items = 100

        url = (
            f"https://achievements.xboxlive.com/users/xuid({xuid})"
            f"/achievements?titleId={tid}&maxItems={max_items}"
        )
        if unlocked_only:
            url += "&unlockedOnly=true"

        try:
            req = urllib.request.Request(url, headers={
                "Authorization": self.xbl3_auth or "",
                "x-xbl-contract-version": "1",  # legacy schema for Win8-era titles
                "Accept": "application/json",
            })
            with _NOPROXY_OPENER.open(req, timeout=15) as resp:
                upstream = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            ctx.log.warn(
                f"[xbl_bridge] /xbox/users/{xuid}/title/{tid}/achievements "
                f"fetch failed: {exc}"
            )
            flow.response = http.Response.make(
                502, json.dumps({"error": str(exc)}).encode(),
                {"Content-Type": "application/json"},
            )
            return

        raw_achievements = upstream.get("achievements") or []
        items = []
        for a in raw_achievements:
            items.append({
                "id":               int(a.get("id") or 0),
                "titleId":          int(a.get("titleId") or 0),
                "name":             a.get("name") or "",
                "description":      a.get("description") or "",
                "lockedDescription": a.get("lockedDescription") or "",
                "gamerscore":       int(a.get("gamerscore") or 0),
                "isEarned":         bool(a.get("unlocked")),
                "isSecret":         bool(a.get("isSecret")),
                "imageId":          int(a.get("imageId") or 0),
                "sequence":         int(a.get("sequence") or 0),
                "timeUnlocked":     a.get("timeUnlocked") or "",
                "type":             int(a.get("type") or 0),
                "flags":            int(a.get("flags") or 0),
                "unlockedOnline":   bool(a.get("unlockedOnline")),
                "platform":         int(a.get("platform") or 0),
                "pictureUrl":       a.get("imageUrl") or "",
            })

        out = {
            "items": items,
            "totalRecords": int(upstream.get("pagingInfo", {}).get("totalRecords") or len(items)),
        }
        flow.response = http.Response.make(
            200, json.dumps(out).encode("utf-8"),
            {"Content-Type": "application/json"},
        )
        ctx.log.info(
            f"[xbl_bridge] bridge-intercept: /xbox/users/{xuid}/title/{tid}/achievements "
            f"-> {len(items)} items ({sum(1 for i in items if i['isEarned'])} earned)"
        )

    def _h_xbox_achievement_unlock(
        self, flow: http.HTTPFlow, xuid: str, tid: str, aid: str
    ) -> None:
        """POST /xbox/users/{xuid}/title/{tid}/achievements/{aid}/unlock.

        Submits an achievement unlock to MS's achievements service. The
        Win8-era v1 schema uses the action=progressUpdate mutation
        endpoint; modern v2 shape works for some titles too. We try v1
        first (matches the read schema), fall back to v2.
        """
        if not self.xbl3_auth:
            flow.response = http.Response.make(
                503, json.dumps({"error": "bridge not bootstrapped"}).encode(),
                {"Content-Type": "application/json"},
            )
            return

        url = f"https://achievements.xboxlive.com/users/xuid({xuid})/achievements"
        body_json = {
            "action":       "progressUpdate",
            "titleId":      int(tid),
            "userId":       str(xuid),
            "achievements": [{
                "id":              int(aid),
                "percentComplete": 100,
            }],
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(body_json).encode("utf-8"),
                method="POST",
                headers={
                    "Authorization": self.xbl3_auth,
                    "x-xbl-contract-version": "2",
                    "Content-Type": "application/json",
                },
            )
            with _NOPROXY_OPENER.open(req, timeout=15) as resp:
                resp_body = resp.read()
                resp_status = resp.status
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")[:500]
            ctx.log.warn(
                f"[xbl_bridge] achievement unlock {aid} for tid {tid} -> "
                f"HTTP {e.code}: {err_body}"
            )
            flow.response = http.Response.make(
                502, json.dumps({
                    "error": f"upstream HTTP {e.code}",
                    "body": err_body,
                }).encode(),
                {"Content-Type": "application/json"},
            )
            return
        except Exception as exc:
            ctx.log.warn(f"[xbl_bridge] achievement unlock failed: {exc}")
            flow.response = http.Response.make(
                502, json.dumps({"error": str(exc)}).encode(),
                {"Content-Type": "application/json"},
            )
            return

        ctx.log.info(
            f"[xbl_bridge] bridge-intercept: unlocked achievement {aid} for "
            f"tid {tid}, xuid {xuid} -> {resp_status} ({len(resp_body)}B)"
        )
        flow.response = http.Response.make(
            200, json.dumps({"ok": True, "upstream_status": resp_status}).encode(),
            {"Content-Type": "application/json"},
        )

    def _h_legacy_earned_names(self, flow: http.HTTPFlow, tid: str) -> None:
        """GET /achievements/{titleId} — legacy compat for the Cocos2d
        helper in xct-gravityguy-patcher. Returns the cached
        simplified earned-only list (the format the helper's regex
        parser expects).
        """
        tid_int = int(tid)
        body = self._achievements_cache.get(tid_int)
        if body is None:
            ctx.log.warn(
                f"[xbl_bridge] legacy /achievements/{tid_int} not in cache "
                f"(known: {sorted(self._achievements_cache.keys())})"
            )
            flow.response = http.Response.make(
                404, b"[]",
                {"Content-Type": "application/json"},
            )
            return
        flow.response = http.Response.make(
            200, body,
            {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "Access-Control-Allow-Origin": "*",
            },
        )
        ctx.log.info(
            f"[xbl_bridge] bridge-intercept: legacy /achievements/{tid_int} "
            f"({len(body)}B)"
        )

    def _maybe_rewrite_license_request(self, flow: http.HTTPFlow) -> bool:
        """If the request's contentId matches a known-revoked Content ID
        AND we have a known-good substitute, swap the field in-place and
        return True so the caller forwards the modified request upstream.
        Returns False if no rewrite happened (caller should fall back to
        the empty-shim).
        """
        if not self._known_good_content_id:
            return False
        try:
            body = flow.request.get_content() or b""
            req = json.loads(body.decode("utf-8"))
            cid = (req.get("contentId") or "").upper()
            if cid not in {r.upper() for r in REVOKED_CONTENT_IDS}:
                return False
            original = req["contentId"]
            req["contentId"] = self._known_good_content_id
            new_body = json.dumps(req).encode("utf-8")
            flow.request.set_content(new_body)
            ctx.log.info(
                f"[xbl_bridge] license-content rewrite: contentId "
                f"{original} -> {self._known_good_content_id} "
                f"(forwarding modified request to MS)"
            )
            return True
        except Exception as exc:
            ctx.log.warn(f"[xbl_bridge] license-content rewrite failed: {exc}")
            return False

    def _maybe_forge_acquire_receipt(self, flow: http.HTTPFlow) -> None:
        """Replace a failing AcquireReceipt response with a fully-
        populated synthetic ReceiptResponse + AppReceipt whose AppId
        matches the productId the game asked about.

        The Win8-era licensingwindows endpoint returns an XML
        `<ReceiptResponse>` carrying either an error code or a
        `<Receipt>` element with one or more `<AppReceipt>` /
        `<ProductReceipt>` children. Sideloaded or de-listed titles
        get ErrorCode="0xc03f300a" or empty receipts and treat them as
        fatal. We forge a structurally-complete success body.
        Critically: extract the productId from the request URL's
        querystring and reuse it as the synthetic AppReceipt's AppId,
        so games that cross-check "does this receipt cover the product
        I asked about" pass that check too. (No XML signature -- if
        the game cryptographically validates the Signature, we hit the
        same wall as Taptiles' PlayReady license and only a binary
        patch helps.)

        Allowlisted by productId: forging a signature-less receipt for
        a title that doesn't strictly need one (e.g. Mahjong) breaks
        sign-in, because the title's receipt validator trips on the
        missing Signature whereas it would have happily ignored MS's
        real "no receipt" error. Only titles in
        ACQUIRE_RECEIPT_FORGE_PRODUCT_IDS get the synthetic body.
        """
        if flow.response.status_code != 200:
            return
        try:
            # Pull productId out of the request URL: the path is e.g.
            # /Licensing/License/AcquireReceipt/6.2/0?productId=<GUID>
            qs = urllib.parse.urlparse(flow.request.path).query
            requested_product_id = (
                urllib.parse.parse_qs(qs).get("productId", ["00000000-0000-0000-0000-000000000000"])[0]
            )
            if requested_product_id.upper() not in {
                p.upper() for p in ACQUIRE_RECEIPT_FORGE_PRODUCT_IDS
            }:
                return  # Pass MS's real response through unmodified.
            body = (flow.response.content or b"").decode("utf-8", errors="replace")
            if "<ReceiptResponse" not in body:
                return
            # Only forge if MS returned an error; pass through real success.
            if 'ErrorCode="0"' in body and "<Receipt" in body:
                return
            now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
            iso_now = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            iso_purchase = "2020-01-01T00:00:00Z"
            forged = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<ReceiptResponse xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
                ' xmlns:xsd="http://www.w3.org/2001/XMLSchema" Version="1.0" ErrorCode="0">'
                f'<Receipt Version="1.0" ReceiptDate="{iso_now}"'
                ' ReceiptDeviceId="00000000-0000-0000-0000-000000000000">'
                '<AppReceipt Id="00000000-0000-0000-0000-000000000001"'
                f' AppId="{requested_product_id}"'
                f' LicenseType="Full" PurchaseDate="{iso_purchase}"/>'
                '</Receipt>'
                '</ReceiptResponse>'
            )
            flow.response.set_content(forged.encode("utf-8"))
            ctx.log.info(
                f"[xbl_bridge] AcquireReceipt forge: synthetic receipt "
                f"with AppId={requested_product_id}"
            )
        except Exception as exc:
            ctx.log.warn(f"[xbl_bridge] AcquireReceipt forge failed: {exc}")

    def _maybe_forge_entitlement_response(self, flow: http.HTTPFlow) -> None:
        """Strip a `satisfactionFailure` block from the licensing response
        so the game treats it as an entitled success. Used for titles
        still in MS's catalog but for which the user has no
        purchase/install entitlement. Without this rewrite the game gets
        the no-entitlement reply, aborts at the licensing layer
        (Wordament-class) or shows a "GET THE FULL VERSION" trial dialog
        (Gravity-Guy-class).

        Two match paths:
          1. Request body's top-level `contentId` is in
             ENTITLEMENT_FORGE_CONTENT_IDS. Used by titles that send
             contentId as a plain JSON field (Wordament).
          2. Response's `satisfactionFailure.remediationProductSkus[]`
             contains a productId in UPSELL_BYPASS_PRODUCT_IDS. Used by
             titles whose request only carries an opaque base64'd
             clientChallenge XML and the contentId can't be cheaply
             extracted from the request -- the response's upsell
             remediation block is the canonical title identifier.
        """
        if flow.response.status_code != 200:
            return
        try:
            resp = json.loads((flow.response.content or b"").decode("utf-8"))
            if "satisfactionFailure" not in resp:
                return  # already satisfied
            sf = resp.get("satisfactionFailure", {})

            match_reason: str | None = None

            try:
                req = json.loads((flow.request.get_content() or b"").decode("utf-8"))
                cid = (req.get("contentId") or "").upper()
                if cid in {c.upper() for c in ENTITLEMENT_FORGE_CONTENT_IDS}:
                    match_reason = f"contentId={cid}"
            except Exception:
                pass

            if match_reason is None:
                upsell_pids_upper = {p.upper() for p in UPSELL_BYPASS_PRODUCT_IDS}
                for sku in sf.get("remediationProductSkus", []) or []:
                    pid = (sku.get("productId") or "").upper()
                    if pid in upsell_pids_upper:
                        match_reason = f"productId={pid}"
                        break

            if match_reason is None:
                return

            forged = json.dumps({
                "policies": [],
                "licenses": [],
                "contentLicenses": [],
            }).encode("utf-8")
            flow.response.set_content(forged)
            ctx.log.info(
                f"[xbl_bridge] entitlement forge: stripped satisfactionFailure "
                f"-> empty-success ({match_reason})"
            )
        except Exception as exc:
            ctx.log.warn(f"[xbl_bridge] entitlement forge failed: {exc}")

    def _maybe_learn_known_good_content_id(self, flow: http.HTTPFlow) -> None:
        """If a real licensing.mp call came back 200 (i.e., MS recognised
        the content), capture its contentId so we can use it as the
        substitute for revoked titles' future calls. Skips revoked IDs
        (don't learn from our own shim's 200 responses) and no-ops once
        a value is already cached.

        Two extraction paths: (1) `/v7.0/licenses/content` requests carry
        the contentId in the request JSON body (used by titles minting a
        fresh license). (2) `/v7.0/licenses/leases/renew` responses
        contain the contentId in the URL keys of the returned `leases`
        dict (used by titles renewing already-cached licenses, e.g.
        Mahjong on a machine that's run it before). Without (2) the
        learning never fires for a session where every healthy title
        already has cached licenses, and revoked-title rewrites have no
        substitute to use.
        """
        if self._known_good_content_id:
            return
        if not flow.response or flow.response.status_code != 200:
            return
        revoked_upper = {r.upper() for r in REVOKED_CONTENT_IDS}
        try:
            req = json.loads((flow.request.get_content() or b"").decode("utf-8"))
            cid = req.get("contentId", "")
            if cid and cid.upper() not in revoked_upper:
                self._known_good_content_id = cid
                ctx.log.info(
                    f"[xbl_bridge] learned known-good Content ID for license "
                    f"rewrite: {cid} (any further revoked-title calls will be "
                    f"rewritten to use this ID)"
                )
                return
        except Exception:
            pass
        try:
            resp_text = (flow.response.content or b"").decode("utf-8", errors="replace")
            for m in re.finditer(
                r"contentId=([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})",
                resp_text,
            ):
                cid = m.group(1)
                if cid.upper() in revoked_upper:
                    continue
                self._known_good_content_id = cid
                ctx.log.info(
                    f"[xbl_bridge] learned known-good Content ID for license "
                    f"rewrite: {cid} (extracted from {flow.request.path[:60]} "
                    f"response; any further revoked-title calls will be "
                    f"rewritten to use this ID)"
                )
                return
        except Exception:
            pass

    def _forge_modern_auth_response(self, host: str) -> bytes | None:
        """Build a synthesised success response for the modern XBL3 auth
        endpoints user.auth / title.auth / xsts.auth.

        Strategy:
          * user.auth -> our bootstrap-cached UserToken in the response's
            Token field, plus the matching uhs in DisplayClaims.xui[0].
            The client passes the Token through to xsts.auth (which we
            also forge), so the cached value is sufficient.
          * title.auth -> a synthetic opaque blob in Token. Real
            TitleTokens require Microsoft's per-title private signing
            key which we don't have, but clients don't validate this
            token locally -- they just forward it to xsts.auth, which we
            forge -- so an opaque base64 placeholder is fine.
          * xsts.auth -> our bootstrap-cached XSTS in Token, plus xui
            claims (gtg/xid/uhs/agg/usr/utr/xtg) so the title can read
            the gamertag, XUID and userhash. Downstream achievements/
            profile/etc. services validate this Token's signature
            against Microsoft's keys, so it must be the real XSTS we
            minted via the no-proxy bootstrap chain.

        Returns None if bootstrap hasn't completed yet (no cached tokens
        to forge with) -- caller falls through to default behaviour.
        """
        if not (self.user_token and self.xsts_token_raw and self.uhs and self.xuid):
            return None
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        expires = now + datetime.timedelta(hours=16)
        iso = now.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
        iso_exp = expires.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")

        if host == "user.auth.xboxlive.com":
            payload = {
                "IssueInstant": iso,
                "NotAfter": iso_exp,
                "Token": self.user_token,
                "DisplayClaims": {"xui": [{"uhs": self.uhs}]},
            }
        elif host == "title.auth.xboxlive.com":
            synth_title_token = base64.b64encode(
                b"xct-bridge-synth-title-token-" + os.urandom(64)
            ).decode("ascii")
            payload = {
                "IssueInstant": iso,
                "NotAfter": iso_exp,
                "Token": synth_title_token,
                "DisplayClaims": {"xti": [{"tid": "0"}]},
            }
        elif host == "xsts.auth.xboxlive.com":
            payload = {
                "IssueInstant": iso,
                "NotAfter": iso_exp,
                "Token": self.xsts_token_raw,
                "DisplayClaims": {"xui": [{
                    "gtg": self.gamertag,
                    "xid": self.xuid,
                    "uhs": self.uhs,
                    "agg": "Adult",
                    "usr": "234",
                    "utr": "190",
                    "prv": "",
                    "xtg": "0",
                }]},
            }
        else:
            return None

        return json.dumps(payload).encode("utf-8")

    def _log_titlestorage_shim(self, method: str, kind: str, path: str) -> None:
        """Log a titlestorage shim with run-length dedup on (method, kind).

        Consecutive identical events silently increment a counter. When a
        different (method, kind) arrives, the previous run's counter is
        flushed as a "(repeated Nx)" line before the new event logs. This
        keeps the launcher window readable during Mahjong's storage-polling
        bursts while still surfacing every distinct shim event.
        """
        key = (method, kind)
        if key == self._ts_shim_last_key:
            self._ts_shim_dup_count += 1
            return
        if self._ts_shim_dup_count > 0:
            ctx.log.info(
                f"[xbl_bridge]   (repeated {self._ts_shim_dup_count + 1}x)"
            )
        self._ts_shim_last_key = key
        self._ts_shim_dup_count = 0
        ctx.log.info(
            f"[xbl_bridge] titlestorage shim: {method} {kind} {path[:100]}"
        )

    def _shim_titlestorage(self, flow: http.HTTPFlow) -> None:
        method = flow.request.method
        path = flow.request.path
        orig_status = flow.response.status_code
        if method == "GET":
            # Legacy Mahjong treats 404 here as a fatal download failure
            # (raises "error code 002000" for Daily Challenge). The XBL2-era
            # contract returned 200 with an empty body for "no saved
            # progress". Emulate that.
            flow.response.status_code = 200
            flow.response.headers["Content-Type"] = "application/json"
            flow.response.set_content(b"{}")
            self._log_titlestorage_shim(method, f"{orig_status}->200(empty)", path)
        elif method in ("PUT", "POST"):
            flow.response.status_code = 200
            flow.response.headers["Content-Type"] = "application/json"
            flow.response.set_content(b"{}")
            self._log_titlestorage_shim(method, f"{orig_status}->200", path)
        elif method == "DELETE":
            flow.response.status_code = 204
            flow.response.set_content(b"")
            self._log_titlestorage_shim(method, f"{orig_status}->204", path)

    def _handle_xsts_response(self, flow: http.HTTPFlow) -> None:
        """Inspect the real auth.xboxlive.com/XSts/xsts.svc/IWSTrust13
        response and either record that the legacy backend is working for
        this user, or forge a success envelope in place if it's rejected.

        Cohort detection:
          * 200 + body contains `<jwt ` inside RequestedSecurityToken →
            MS's legacy backend is issuing a real XBL2.0 JWE for this MSA.
            Set _legacy_backend_works=True and leave the response
            untouched. The request hook will stop rewriting Authorization
            on subsequent XBL calls so the game's own tokens flow through.
          * anything else (status >= 400, x-err header present, missing
            <jwt>) → treat as the classic post-deprecation rejection.
            Rewrite the response body to a synthetic RSTRC carrying the
            bridge's already-minted modern XBL3 JWT, and set
            _legacy_backend_works=False so XBL2.0→XBL3.0 header swap
            resumes for later requests.
        """
        resp = flow.response
        body = resp.content or b""
        x_err = resp.headers.get("x-err", "")

        looks_good = (
            resp.status_code == 200
            and not x_err
            and b"<jwt " in body
        )
        if looks_good:
            if self._legacy_backend_works is not True:
                self._legacy_backend_works = True
                ctx.log.info(
                    "[xbl_bridge] legacy XSts succeeded upstream (real "
                    f"<jwt .../> returned, {len(body)}B). Microsoft's "
                    "backend works for this MSA — bridge will NOT rewrite "
                    "Authorization on subsequent XBL requests."
                )
            return

        # Failure path: forge a RSTRC carrying our bridge's modern XBL3 JWT.
        jwt = (
            self.xbl3_auth.split(";", 1)[1]
            if self.xbl3_auth and ";" in self.xbl3_auth
            else ""
        )
        if not jwt:
            ctx.log.warn(
                "[xbl_bridge] XSts upstream failed but bridge not "
                "bootstrapped; leaving response untouched"
            )
            return
        req_body = flow.request.get_content() or b""
        msg_id_match = re.search(rb"<a:MessageID>([^<]+)</a:MessageID>", req_body)
        msg_id = (
            msg_id_match.group(1).decode("ascii", "replace")
            if msg_id_match
            else ""
        )
        forged = _forge_xsts_rstr(jwt, msg_id)
        resp.status_code = 200
        resp.headers["Content-Type"] = "application/soap+xml; charset=utf-8"
        if "x-err" in resp.headers:
            del resp.headers["x-err"]
        resp.set_content(forged)
        if self._legacy_backend_works is not False:
            self._legacy_backend_works = False
            ctx.log.info(
                "[xbl_bridge] legacy XSts rejected upstream (x-err="
                f"{x_err!r}, orig_status={resp.status_code}) — forging "
                "response with bridge's XBL3 JWT; subsequent XBL calls "
                "will have Authorization swapped XBL2.0→XBL3.0."
            )
        else:
            ctx.log.info(
                f"[xbl_bridge] forged XSts success (x-err={x_err!r} "
                f"msg_id={msg_id[:40]})"
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
