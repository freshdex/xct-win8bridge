# xct-win8bridge

**Restoring Xbox Live sign-in for legacy Microsoft Store / Windows 8-era games on Windows 10 and 11 — using only public, documented Microsoft APIs.**

Microsoft quietly deprecated the old `XBL2.0`-formatted XSTS tokens used by the original Windows 8 Store generation of first-party titles. The games still install, still launch, still talk to `*.xboxlive.com` — but every request returns `HTTP 401 token_required` from the server, the in-game sign-in prompt never completes, and features that depend on the player's Xbox Live identity (gamerpic, friend list, **achievements**, leaderboards) go dark.

This project is a **working proof that those titles can be bridged to the modern `XBL3.0` token format entirely via public, documented APIs** — no reverse-engineered private endpoints, no spoofed client IDs, no process injection, no binary patching. The goal is to demonstrate to Microsoft that the legacy stack can be reactivated with a thin compatibility layer, so that the preservation of these titles — and the achievement records users earned on them — is technically achievable.

## Featured

The project has been covered in the press as a potential path to revive hundreds of broken Windows 8-era Xbox Live titles:

- **Pure Xbox** — [Xbox PC Project Might Have Solved How To Fix Hundreds Of Broken Windows Games](https://www.purexbox.com/news/2026/04/xbox-pc-project-might-have-solved-how-to-fix-hundreds-of-broken-windows-games)
- **r/xbox** — [Microsoft Could Fix Hundreds Of Broken Xbox Games](https://www.reddit.com/r/xbox/comments/1srhvdy/microsoft_could_fix_hundreds_of_broken_xbox/)

Follow progress on X: [**@XCTdotLIVE**](https://x.com/XCTdotLIVE). We're continuing to add more games — watch the [Status](#status) table and the changelog below.

## Changelog

### v1.1 — 2026-04-22

- **New titles working end-to-end:** Microsoft Solitaire Collection, Microsoft Adera.
- **XSts response forgery** for `auth.xboxlive.com/XSts/xsts.svc/IWSTrust13` (and `activeauth.xboxlive.com`). Microsoft's server rejects the legacy `WLID1.0` bootstrap tokens on post-deprecation accounts with `x-err: 0x8015DA87` + a bare WCF dispatcher fault — historically the dead-end for Adera and other `Microsoft.Xbox.dll`-based titles. The bridge now substitutes a valid WS-Trust 1.3 `RequestSecurityTokenResponseCollection` envelope carrying its own modern XBL JWT, letting the client proceed into the profile / progress / titlestorage fetch paths that the rest of the addon already bridges.
- **Dead-host shim** for `data.xboxlive.com`. Microsoft retired the legacy XBL beacon endpoint; it still resolves but no longer accepts TCP connections. Adera blocks its sign-in state machine waiting for a 200 response here, so the bridge synthesizes a `200 OK` empty reply locally. mitmproxy runs with `connection_strategy=lazy` so it doesn't try to pre-connect to the unreachable upstream.
- **Microsoft Solitaire Collection** added to the titlestorage `403 → 200(empty)` allowlist (titlegroup `b3288d02-ddca-4e7c-955a-06142d6e138e`).
- **One-click batch launcher** (`launch.bat` / `stop.bat`) — replaces the previous six-terminal manual setup. `launch.bat` self-elevates via UAC, then runs a 7-step pipeline:

  1. **Dependency check** — verifies `python` and `cargo` are on `PATH` (fails fast with an install hint if not).
  2. **Python deps** — `pip install --quiet --upgrade mitmproxy ecdsa` (idempotent; noop on re-runs).
  3. **Build `ticket_server`** — `cargo build --release --bin ticket_server`; cached after the first build so subsequent runs are near-instant.
  4. **mitmproxy CA bootstrap** — starts `mitmdump` briefly on a scratch port to generate `%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer` if it doesn't exist yet.
  5. **CA trust** — `certutil -addstore Root` of the mitmproxy CA into `LocalMachine\Root` so UWP apps accept the MITM cert for `*.xboxlive.com`. Skipped if already present.
  6. **Loopback exemptions** — `CheckNetIsolation LoopbackExempt -a -n=…` for every supported title's PackageFamilyName (Mahjong, Minesweeper, Solitaire Collection, Adera as of v1.1). Required so the AppContainer can reach `127.0.0.1:8080`.
  7. **Helpers + proxies** — spawns `ticket_server.exe` (green window) and `mitmdump -s addon/xbl_bridge.py --flow-detail 1` (yellow window, live intercept log), then enables both the WinINET (HKCU registry) and WinHTTP (`netsh winhttp set proxy`) system proxies pointing at `127.0.0.1:8080`.

  `stop.bat` reverses only the volatile state: WinINET proxy off, WinHTTP reset to direct, `mitmdump` / `mitmweb` / `ticket_server` killed. It deliberately leaves the mitmproxy CA and loopback exemptions installed so re-runs of `launch.bat` skip steps 4–6 entirely.

### v1.0 — Initial release

- `ticket_server` (Rust) — MBI_SSL ticket via `WebAuthenticationCoreManager` against the Windows-signed-in MSA.
- `xbl_bridge.py` (mitmproxy addon) — exchanges MBI ticket → UserToken → XSTS, then rewrites legacy `Authorization: XBL2.0` headers to `XBL3.0` on `*.xboxlive.com` traffic, with `stats` / `communications` passthrough and a per-titlegroup titlestorage 403 shim.
- Working titles: **Microsoft Mahjong**, **Microsoft Minesweeper**.
- Setup was manual at this stage — Python dep install, cargo build, mitmproxy CA trust, loopback exemptions and proxy enable were all separate terminal commands in the README. The batch launcher in v1.1 collapses that into a single double-click.

## Status

> **Aim: every legacy Windows 8-era first-party Xbox Live title.**
> **Currently: 4 of 4 tried, working.**

| Title | TitleId | Sign-in | Gamerpic | Legacy achievement list |
|---|---|:---:|:---:|:---:|
| Microsoft Mahjong (1.9.0.40714) | 1297290225 | ✓ | ✓ | ✓ |
| Microsoft Minesweeper (2.9.1913.0) | 1297290226 | ✓ | ✓ | ✓ |
| Microsoft Solitaire Collection (2.11.1807.1002) | 1297287741 | ✓ | ✓ | ✓ |
| Microsoft Adera (2.5.2.34894) | 1297290206 | ✓ | ✓ | ✓ |

Microsoft Mahjong with gamertag, gamerpic and its legacy XBL2-era achievement set all populating through the bridge:

![Microsoft Mahjong — signed in, avatar loaded, legacy achievements rendered](docs/mahjong-achievements.png)

Microsoft Minesweeper likewise — same bridge, no title-specific code:

![Microsoft Minesweeper — signed in, avatar loaded, legacy achievements rendered](docs/minesweeper-achievements.png)

Microsoft Solitaire Collection — gamertag, gamerscore, full Awards grid and Daily Challenge badges all populated:

![Microsoft Solitaire Collection — Awards page with Medals, Daily Challenge Badges, and game-specific achievement tiles](docs/solitaire-achievements.png)

Microsoft Adera — unlocked by v1.1's XSts response forgery. Gamerscore 577030 + the General and Adera: The Shifting Sands achievement sets rendering:

![Microsoft Adera — Achievements page with General and Adera: The Shifting Sands achievement sets, gamerscore 577030](docs/adera-achievements.png)

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

### 2. `xbl_bridge.py` — a [mitmproxy][mitmproxy] addon

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
       xbl_bridge.py (mitmproxy addon)
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

### Quick start (one click)

Double-click **`launch.bat`** at the repo root. It will:

1. Self-elevate (UAC prompt — needed for cert install, WinHTTP proxy, and loopback exemptions),
2. Install the Python dependencies (`mitmproxy`, `ecdsa`),
3. Build `ticket_server` (cached after the first build),
4. Generate + trust the mitmproxy CA in the Windows Local Machine root store,
5. Grant loopback exemptions to the supported games,
6. Open two helper windows — `ticket_server` (green) and `mitmdump` (yellow, with live intercept logging),
7. Enable the WinINET + WinHTTP system proxies.

Once it prints `READY`, launch Microsoft Mahjong or Microsoft Minesweeper from Start. The `mitmdump` window scrolls every request the bridge rewrites:

```
[xbl_bridge] bridged GET profile.xboxlive.com/users/me/id
[xbl_bridge] bridged GET titlestorage.xboxlive.com/users/xuid(...)/storage/titlestorage/titlegroups/.../data/unverified/DailyChallengeSettings,json
[xbl_bridge] titlestorage shim: GET 403->200(empty) /users/xuid(...)/.../DailyChallengeSettings,json
```

When you're done, press any key in the launcher window (or double-click **`stop.bat`**) to disable the proxies and stop the helpers. The CA and loopback exemptions stay installed so subsequent launches are near-instant.

### Manual run

If you prefer running the pieces by hand, in three separate terminals:

```
cargo build --release
target\release\ticket_server.exe
mitmdump -s addon\xbl_bridge.py --flow-detail 1
```

And enable the proxies:

```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d 127.0.0.1:8080 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f
netsh winhttp set proxy proxy-server="127.0.0.1:8080" bypass-list="<-loopback>"
```

Teardown:

```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f
netsh winhttp reset proxy
```

### Registering your own app (optional)

The bundled client ID is good enough to run this project; Microsoft issues you a personal MSA-scoped ticket when *your* account consents to *any* app requesting that scope. But if you'd rather own the identity yourself:

1. Open [portal.azure.com](https://portal.azure.com) → **App registrations** → **New registration**.
2. Name: whatever (e.g. `xct-win8bridge-<yourname>`).
3. **Supported account types: "Personal Microsoft accounts only"** — Xbox Live runs on consumer MSAs.
4. No redirect URI needed (the WAM broker path doesn't use OAuth web redirects).
5. Register, then copy the **Application (client) ID** GUID.
6. Under **Authentication → Advanced settings**, set **Allow public client flows** to Yes.
7. Replace `CLIENT_ID` in `src/bin/ticket_server.rs` and `src/bin/xal_probe.rs` with your GUID.

## Scope

UWP titles shipped with the legacy `Microsoft.Xbox.dll` + `xbl.spa` XBL2.0 SDK that authenticate via `auth.xboxlive.com/XSts/xsts.svc/IWSTrust13`. Detect these by checking the package install dir — if both files are present, this bridge should cover it.

## Forking notes

- **Reuse the bundled client ID freely**, or register your own — either works. The bundled one is a public client ID with no secret and no special privileges; each user's own Microsoft account is always what actually authenticates.
- **The MSA ticket never leaves the local machine.** `ticket_server` binds to `127.0.0.1` only. The XBL3.0 mint chain after that goes direct to `*.xboxlive.com`.
- **No retention.** This is not a token-caching layer. Every session re-mints.
- **Be a good neighbour.** The bridge exists to demonstrate the transformation, not to hammer XBL. Don't script it to mass-request.

## Acknowledgements

Built on the work and patience of the Xbox preservation community, particularly the xbox-collection-tracker project whose proven XBL auth primitives informed the initial exploration here.

---

> If you work at Microsoft on the Xbox Live platform and are reading this: **please**, the only thing separating these titles from still-working is a thin XBL2→XBL3 translation layer the server no longer performs. Every transformation this project does is mechanical and could be done server-side.
