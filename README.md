# xct-win8bridge

**Restoring Xbox Live sign-in for legacy Microsoft Store / Windows 8-era games on Windows 10 and 11 — using only public, documented Microsoft APIs.**

Microsoft quietly deprecated the old `XBL2.0`-formatted XSTS tokens used by the original Windows 8 Store generation of first-party titles. The games still install, still launch, still talk to `*.xboxlive.com` — but every request returns `HTTP 401 token_required` from the server, the in-game sign-in prompt never completes, and features that depend on the player's Xbox Live identity (gamerpic, friend list, **achievements**, leaderboards) go dark.

This project is a **working proof that those titles can be bridged to the modern `XBL3.0` token format entirely via public, documented APIs** — no reverse-engineered private endpoints, no spoofed client IDs, no process injection, no binary patching. The goal is to demonstrate to Microsoft that the legacy stack can be reactivated with a thin compatibility layer, so that the preservation of these titles — and the achievement records users earned on them — is technically achievable.

## Status

> **Aim: every legacy Windows 8-era first-party Xbox Live title.**
> **Currently: 2 of 2 tried, working.**

| Title | TitleId | Sign-in | Gamerpic | Legacy achievement list |
|---|---|:---:|:---:|:---:|
| Microsoft Mahjong (1.9.0.40714) | 1297290225 | ✓ | ✓ | ✓ |
| Microsoft Minesweeper (2.9.1913.0) | 1297290226 | ✓ | ✓ | ✓ |

Daily Challenge loaders in Mahjong are blocked by a separate, unrelated problem — the Arkadium backend that hosts the challenge content is itself decommissioned. That's out of scope here and lives under a different umbrella.

## Why this is Microsoft-friendly

Design constraints we hold ourselves to:

- **Only public, documented APIs.** `WebAuthenticationCoreManager` (WinRT broker), `user.auth.xboxlive.com` + `device.auth.xboxlive.com` + `xsts.auth.xboxlive.com` (public XBL mint chain). Nothing private, nothing reversed.
- **The calling identity is our own.** A user-registered Azure AD / Entra app (personal Microsoft accounts). Not Microsoft's Android Xbox client ID, not the Store's, not someone else's. Anyone forking this project registers their own.
- **No process injection, no binary modification of game executables.** The bridge is strictly a network interceptor.
- **No private IPC into Gaming Services / Xbox components.** We don't poke at the `xgameruntime.dll` broker or shim any system DLLs. Everything the bridge does could be done by a first-class Microsoft-provided compatibility service.

If Microsoft implemented the same transformation server-side, this project would become obsolete — and that's the intended outcome.

## How it works

Two components:

### 1. `ticket_server` — a tiny Rust HTTP service

Exposes `GET http://127.0.0.1:8099/ticket` and returns an **MBI_SSL compact ticket** for `user.auth.xboxlive.com`, minted via the Windows [`WebAuthenticationCoreManager`][wam] broker against the MSA already signed into the operating system. No popup, no secondary login.

Under the hood this is `FindAccountProviderWithAuthorityAsync("https://login.microsoft.com", "consumers")` → `WebTokenRequest(provider, "service::user.auth.xboxlive.com::MBI_SSL", <your_client_id>)` → `GetTokenSilentlyAsync`. First run may prompt once for consent; subsequent runs are silent.

[wam]: https://learn.microsoft.com/en-us/windows/uwp/security/web-account-manager

### 2. `mahjong_bridge.py` — a [mitmproxy][mitmproxy] addon

On startup:

1. Fetches the MBI_SSL ticket from `ticket_server`.
2. Exchanges it at `https://user.auth.xboxlive.com/user/authenticate` → XBL `UserToken`.
3. Exchanges `UserToken` at `https://xsts.auth.xboxlive.com/xsts/authorize` (RelyingParty `http://xboxlive.com`, UserTokens only) → XSTS token + UserHash.
4. Assembles an `Authorization: XBL3.0 x=<UserHash>;<XSTS>` header.

On each game request to `*.xboxlive.com`:

- Legacy mint calls to `auth.xboxlive.com/XSts/xsts.svc/IWSTrust13` pass through untouched (the game needs its 200 OK to keep its sign-in state machine moving).
- Endpoints that only speak XBL2.0 server-side (`stats.xboxlive.com`, `communications.xboxlive.com`) pass through untouched — our rewrite would actively break them.
- Everything else with `Authorization: XBL2.0 ...` gets the Authorization header swapped for our XBL3.0 one. **Nothing else is touched.** Not the body, not `x-xbl-contract-version`, not anything. (We tried bumping + translating — legacy games' response parsers quietly reject the modern shape.)
- Per-user title-group storage (`titlestorage.xboxlive.com/users/xuid(...)/storage/titlestorage/titlegroups/<guid>/...`) returns `403` because our XSTS is not title-scoped — Title-bound tokens require a title's private signing key which only Microsoft has. We shim these with empty-body `200` (GET) / `200` acknowledgements (PUT) so legacy "no saved state yet" behavior kicks in cleanly, rather than the game interpreting 403 as a download failure.

[mitmproxy]: https://mitmproxy.org

```
      ┌─── Windows MSA (already signed into OS) ────┐
      │                                             │
      ▼                                             │
 WebAuthenticationCoreManager ──── MBI_SSL ticket ──┘
                │
                ▼
       ticket_server (Rust)
                │  GET /ticket
                ▼
       mahjong_bridge.py (mitmproxy addon)
                │
   user.auth.xboxlive.com   ← MBI
   device.auth.xboxlive.com ← (not needed; simple flow)
   xsts.auth.xboxlive.com   ← UserToken
                │
       XBL3.0 x=<uhs>;<xsts>
                │
                ▼
      legacy game's outgoing *.xboxlive.com traffic
        (Authorization header swapped; everything
         else passes through unchanged)
```

## Requirements

- Windows 10 or 11
- Python 3 with `mitmproxy` and `ecdsa`:

  ```
  pip install mitmproxy ecdsa
  ```

- Rust (stable) — only to build `ticket_server`:

  ```
  cargo build --release --bin ticket_server
  ```

- An Azure AD / Entra app registration to identify the caller of `WebAuthenticationCoreManager`.  **You don't have to register your own** — this repo ships with a working client ID in `src/bin/ticket_server.rs` that you're welcome to reuse. It's a public client ID (no secret), scoped to "Personal Microsoft accounts only", and does nothing beyond requesting Xbox Live user tickets for whoever consents to it. If you'd rather own the identity, see [Registering your own app](#registering-your-own-app-optional) below.

- The mitmproxy CA certificate trusted in the Windows Local Machine certificate store so `*.xboxlive.com` TLS can be intercepted. mitmproxy prints the command once when you first run it.

- The UWP game's `AppContainer` must be loopback-exempted so it can reach `127.0.0.1:8080`:

  ```
  CheckNetIsolation LoopbackExempt -a -n="Microsoft.MicrosoftMahjong_8wekyb3d8bbwe"
  CheckNetIsolation LoopbackExempt -a -n="Microsoft.MicrosoftMinesweeper_8wekyb3d8bbwe"
  ```

## Setup

### Build

```
cargo build --release
```

### Run

In three terminals / sessions:

```
# 1. ticket server (keeps running)
target\release\ticket_server.exe

# 2. mitmproxy with the bridge addon
mitmweb -s addon\mahjong_bridge.py

# 3. Enable the system proxy so the game routes through mitmproxy
powershell -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyServer -Value '127.0.0.1:8080'; Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 1"
# Modern UWP games also use WinHTTP, which has a separate setting:
netsh winhttp set proxy proxy-server="127.0.0.1:8080" bypass-list="<-loopback>"
```

Launch Mahjong or Minesweeper from the Start menu. Sign-in should resolve, the gamerpic should appear in the top-right, and the Awards page should populate with your legacy achievement set.

### Registering your own app (optional)

The bundled client ID is good enough to run this project; Microsoft issues you a personal MSA-scoped ticket when *your* account consents to *any* app requesting that scope. But if you'd rather own the identity yourself:

1. Open [portal.azure.com](https://portal.azure.com) → **App registrations** → **New registration**.
2. Name: whatever (e.g. `xct-win8bridge-<yourname>`).
3. **Supported account types: "Personal Microsoft accounts only"** — Xbox Live runs on consumer MSAs.
4. No redirect URI needed (the WAM broker path doesn't use OAuth web redirects).
5. Register, then copy the **Application (client) ID** GUID.
6. Under **Authentication → Advanced settings**, set **Allow public client flows** to Yes.
7. Replace `CLIENT_ID` in `src/bin/ticket_server.rs` and `src/bin/xal_probe.rs` with your GUID.

### Tear-down

```
powershell -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 0"
netsh winhttp reset proxy
```

## Scope

**In scope.** UWP titles shipped with the legacy `Microsoft.Xbox.dll` + `xbl.spa` XBL2.0 SDK that authenticate via `auth.xboxlive.com/XSts/xsts.svc/IWSTrust13`. Detect these by checking the package install dir — if both files are present, this bridge should cover it.

**Out of scope.** Modern `Microsoft.Xbox.Services.dll` / XSAPI rewrites. The Windows 10 Solitaire Collection is an example: it shares its TitleId with its legacy predecessor but its binary was rewritten against the modern XSAPI, so it never makes the XBL2.0 calls this bridge rewrites. It's not *broken* — it's simply not in the class of problems this project addresses. If you want to play the Win8 era Solitaire Collection, obtain that specific build.

**Separately scoped.** Games whose Store entitlement was revoked (delisted from Store). That's a license-infrastructure problem, not an auth problem. See e.g. [xct-pinball-patcher] for that class of fix — different project, different tooling.

[xct-pinball-patcher]: https://github.com/freshdex/xct-pinball-patcher

## Progress board

- [x] Microsoft Mahjong
- [x] Microsoft Minesweeper
- [ ] Microsoft Jigsaw (the legacy Windows 8 version, not the modern rewrite)
- [ ] Microsoft Taptiles
- [ ] Microsoft Wordament
- [ ] Microsoft Sudoku (legacy)
- [ ] Crossroad 2 / Crash Course 2
- [ ] Any other Windows 8 first-party title that shipped with `Microsoft.Xbox.dll` + `xbl.spa`

Pull requests for additional titles welcome — most will just need a loopback exemption, zero code changes. Titles whose title-group storage path differs from the default pattern may need a line in the `titlestorage` shim.

## Forking notes

- **Reuse the bundled client ID freely**, or register your own — either works. The bundled one is a public client ID with no secret and no special privileges; each user's own Microsoft account is always what actually authenticates.
- **The MSA ticket never leaves the local machine.** `ticket_server` binds to `127.0.0.1` only. The XBL3.0 mint chain after that goes direct to `*.xboxlive.com`.
- **No retention.** This is not a token-caching layer. Every session re-mints.
- **Be a good neighbour.** The bridge exists to demonstrate the transformation, not to hammer XBL. Don't script it to mass-request.

## Acknowledgements

Built on the work and patience of the Xbox preservation community, particularly the [xbox-collection-tracker](https://github.com/freshdex/xbox-collection-tracker) project whose proven XBL auth primitives informed the initial exploration here.

---

> If you work at Microsoft on the Xbox Live platform and are reading this: **please**, the only thing separating these titles from still-working is a thin XBL2→XBL3 translation layer the server no longer performs. Every transformation this project does is mechanical and could be done server-side.
