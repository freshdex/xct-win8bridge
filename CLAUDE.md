# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A compatibility shim that lets Windows 8-era UWP Xbox Live titles (Microsoft Mahjong / Minesweeper / Solitaire Collection / Adera) sign in on Windows 10/11 after Microsoft deprecated the `XBL2.0` token format those titles use. The bridge transparently rewrites legacy `XBL2.0` `Authorization` headers into modern `XBL3.0` tokens on outbound `*.xboxlive.com` traffic. Only public, documented Microsoft APIs — no process injection, no binary patching, no private endpoints. The intent is to demonstrate to Microsoft that the legacy stack can be reactivated server-side with a thin translation layer.

## Common commands

Run everything via `launch.bat` / `stop.bat` in day-to-day work — manual invocation is only useful for iterating on `xbl_bridge.py`.

```
cargo build --release --bin ticket_server   # build the Rust helper
cargo run --bin xal_probe                   # smoke-test the WAM path (prints MBI ticket to stdout)
target\release\ticket_server.exe            # run the helper (binds 127.0.0.1:8099)
mitmdump -s addon\xbl_bridge.py --flow-detail 1   # run the bridge (binds 127.0.0.1:8080)
launch.bat                                  # full setup: CA trust, loopback exemptions, proxies, helpers
stop.bat                                    # reverse the volatile state (proxies off, helpers killed)
```

There is no test suite. Verification is empirical: run the bridge, launch a title from Start, watch `[xbl_bridge] bridged …` lines scroll in the `mitmdump` window, and confirm the in-game Achievements / Awards page populates.

## Architecture

Two cooperating processes plus a launcher.

**`ticket_server` (`src/bin/ticket_server.rs`)** — minimal single-threaded HTTP server on `127.0.0.1:8099`. `GET /ticket` returns `{ "ticket", "account" }` where `ticket` is an **MBI_SSL compact RPS ticket** for `user.auth.xboxlive.com`, minted via `WebAuthenticationCoreManager` (WinRT WAM broker) against the MSA already signed into Windows. Falls back from `GetTokenSilentlyAsync` → `RequestTokenAsync` only if the broker reports `UserInteractionRequired`. The `CLIENT_ID` constant is a public Entra app registration (personal MSA accounts only, public-client flows on); same GUID is hardcoded in `xal_probe.rs`.

**`xbl_bridge.py` (`addon/xbl_bridge.py`)** — mitmproxy addon. On `running()` it bootstraps the XBL3.0 chain once:

```
MBI ticket (from ticket_server)
  → POST user.auth.xboxlive.com/user/authenticate    → UserToken
  → POST xsts.auth.xboxlive.com/xsts/authorize       → XSTS + UserHash
  → cached header: "Authorization: XBL3.0 x=<uhs>;<xsts>"
```

Then on each `request`/`response` hook it applies this per-host policy to `*.xboxlive.com` traffic:

| Host / path | Behavior |
|---|---|
| `data.xboxlive.com` | Synthesize `200 OK` empty locally (upstream IP no longer accepts TCP; Adera blocks on it). |
| `auth.xboxlive.com` / `activeauth.xboxlive.com` + `/XSts/...` | **Forge** a WS-Trust 1.3 `RequestSecurityTokenResponseCollection` carrying the bridge's modern JWT. Real server rejects the game's WLID1.0 bootstrap with `x-err: 0x8015DA87` — this is the fix for `Microsoft.Xbox.dll` titles like Adera. |
| `stats.xboxlive.com`, `communications.xboxlive.com` | Pass through untouched — only speak XBL2.0 server-side; rewriting would break them. |
| `titlestorage.xboxlive.com` returning 403 | If the path's `titlegroup` GUID is in `_SHIM_TITLEGROUPS`, rewrite to `200 {}` (GET/PUT/POST) or `204` (DELETE). Our XSTS isn't title-scoped so per-title storage 403s; games interpret that as a download failure rather than "no saved state yet". |
| `packagespc.xboxlive.com/GetBasePackage/...` returning 403 | Rewrite to `200 {}`. The PackagesPC service validates that an installed UWP package is registered with Xbox Live; the bridge's generic XSTS isn't title-scoped so the call 403s. Hitman GO treats the 403 as "Xbox Live unavailable" and refuses to load achievements; other Microsoft.Xbox.dll titles in the portfolio don't gate on it, so the rewrite is universal. |
| Any other `*.xboxlive.com` with `Authorization: XBL2.0 …` | Swap the `Authorization` header only. **Do not touch the body, `x-xbl-contract-version`, or any other header** — legacy response parsers reject the modern shape. |

**`launch.bat`** — self-elevates via UAC, then auto-updates itself, then runs a 7-step idempotent pipeline: dep check (python only) → `pip install mitmproxy ecdsa` → locate `ticket_server.exe` (prefer `target\release\ticket_server.exe` → fall back to committed `bin\ticket_server.exe` → last resort `cargo build` if cargo is on `PATH`) → mitmproxy CA generation → `certutil -addstore Root` → `CheckNetIsolation LoopbackExempt -a -n=<pfn>` for each supported game → start `ticket_server.exe` hidden via `start "" /B` (stdio redirected to `%TEMP%\xct_ticket_server.log`, tied to the launcher's console so closing the window kills it) → `GET /health` health-check → enable WinINET (HKCU registry) + WinHTTP (`netsh winhttp`) proxies pointing at `127.0.0.1:8080` → run `mitmdump` **in the foreground of the launcher window itself** (all three processes are visible to the user as a single window). When `mitmdump` exits (user Ctrl+C then N at the "Terminate batch job?" prompt) the script falls through to `call stop.bat`. `stop.bat` only reverses volatile state — the CA trust and loopback exemptions are deliberately left installed so subsequent runs skip those steps.

**Auto-update** — the `LAUNCHER_VERSION` variable at the top of `launch.bat` is compared (as a semver `[version]` cast in PowerShell) against the `tag_name` of `GET /repos/freshdex/xct-win8bridge/releases/latest`. If the remote is strictly greater, the launcher: downloads `/archive/refs/tags/<tag>.zip`, extracts it to `%TEMP%`, writes a one-shot helper `.cmd` to `%TEMP%` that waits 2s (for the parent to exit) then `robocopy`s the extracted tree over the launcher's own directory (excluding `target .git captures patches build`), sets `XCT_JUST_UPDATED=1` in its env, and spawns the freshly-overwritten `launch.bat`. The child sees the flag and skips the update check this session, preventing an update loop if the maintainer ever forgets to bump `LAUNCHER_VERSION` in a release. The check is skipped entirely if `.git/` exists (contributor checkout).

**`bin/ticket_server.exe`** — prebuilt helper binary committed to the repo so end-users don't need Rust. Rebuild and re-commit after any change to `src/bin/ticket_server.rs`: `cargo build --release --bin ticket_server && copy /Y target\release\ticket_server.exe bin\ticket_server.exe`.

**`.github/workflows/release.yml`** — tag-triggered (`v*`) Windows build of `ticket_server.exe`, attached as a GitHub release asset via `softprops/action-gh-release`. Creating the release is what makes `/releases/latest` respond with that tag, which is what drives auto-update. Also useful as a CI build check and as a way to produce a fresh binary without a local Rust toolchain (trigger via workflow_dispatch, download the artifact, drop into `bin/`, commit).

## Maintainer: cutting a release

1. Edit code, commit as usual on `main`.
2. If `src/bin/ticket_server.rs` changed: `cargo build --release --bin ticket_server && copy /Y target\release\ticket_server.exe bin\ticket_server.exe`, then commit the updated binary.
3. **Bump `LAUNCHER_VERSION` in `launch.bat`** to the new tag (e.g. `v1.2`). Forgetting this step will cause auto-updating users to loop-download the new zip once per launch (the `XCT_JUST_UPDATED` safety valve prevents an *infinite* loop within a single session, but every fresh launch still re-downloads unnecessarily).
4. Tag and push: `git tag v1.2 && git push origin main v1.2`.
5. The release workflow builds and publishes the release; existing users pick it up on their next `launch.bat` run.

## Non-obvious constraints

These are empirically-discovered invariants. Tempting "improvements" to any of them have broken things in the past:

- **The bridge's XSTS is minted with `UserTokens` only, no DeviceToken.** Adding a device token makes `profile.xboxlive.com` return `Restricted` without matching consent scopes. The `RequestSigner` / `_mint_device_token` code paths stay in the file for future endpoints that need them.
- **Only swap `Authorization`, nothing else.** Previous attempts to bump `x-xbl-contract-version` or translate request bodies to the modern schema broke Mahjong's legacy response parser.
- **Always swap `Authorization` on every non-XBL20-only host, even when the legacy XSts mints a real `<jwt>`.** An earlier `_legacy_backend_works=True` short-circuit tried to "stay native" when MS's legacy backend looked healthy for this MSA, on the theory that the user would be in a working cohort. Hitman GO disproved this: real XSts JWT, but `profile.xboxlive.com` still returns 401 `token_required` because modern services no longer parse the `XBL2.0 x=<jwt v="1.0" t=".../>` XML wrapper. The `_handle_xsts_response` observation now only logs the cohort, it doesn't gate rewriting.
- **The titlestorage 403→200 shim is an allowlist, not a blanket rewrite.** Minesweeper's `SyncedData.json` path *needs* the 403 so the game falls back to `progress.xboxlive.com/achievements` — shimming it universally broke Minesweeper's Awards page.
- **Hot-paths inside the addon must not use the system proxy.** The addon runs *inside* mitmproxy, and the system proxy points back at mitmproxy. Its outbound HTTP calls go through `_NOPROXY_OPENER` (a `urllib` opener built with `ProxyHandler({})`) to avoid an infinite loop / timeout.
- **`launch.bat` resolves the pip-installed `mitmdump` via `sysconfig` and prepends its Scripts dir to `PATH`.** The standalone mitmproxy Windows installer ships its own embedded Python that can't see `ecdsa` (or any other pip-installed dep) — if its `mitmdump.exe` is on PATH first, the bridge addon errors on import. Don't "simplify" this back to a bare `mitmdump` invocation.
- **mitmproxy runs with `connection_strategy=lazy`** (implicitly, via the dead-host shim setting `flow.response` before mitmproxy connects upstream) so it never tries to pre-connect to unreachable dead hosts like `data.xboxlive.com`.

## Adding a new title

1. Find the game's `PackageFamilyName` (`Get-AppxPackage Microsoft.<Title> | Select PackageFamilyName`).
2. Add a `CheckNetIsolation LoopbackExempt -a -n=…` line to `launch.bat` step 5.
3. Run the game with the bridge on and watch `mitmdump` output.
4. If it gets stuck on `auth.xboxlive.com/XSts` → it's a `Microsoft.Xbox.dll` title, the forgery path should already cover it.
5. If it's blocked on titlestorage 403s for a Daily Challenge or similar, add the title's `titlegroup` GUID to `_SHIM_TITLEGROUPS` in `xbl_bridge.py`.
6. If it blocks on a new dead host, add it to `DEAD_HOSTS_SHIM_200`.
