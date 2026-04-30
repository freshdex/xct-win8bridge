@echo off
rem xct-win8bridge launcher -- one-click setup + run with live intercept log.
rem Double-click this file. It will self-elevate (UAC prompt).

setlocal EnableDelayedExpansion
cd /d "%~dp0"

rem === Launcher version -- BUMP this before tagging a release on GitHub.
rem     launch.bat auto-updates by comparing this against the latest release
rem     tag; a forgotten bump means users ship-loop re-downloading.
set "LAUNCHER_VERSION=v1.5"

rem --- self-elevate ----------------------------------------------------------
net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo [*] Admin required. Relaunching elevated via UAC...
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title xct-win8bridge launcher
color 0B

echo.
echo ============================================================
echo   xct-win8bridge launcher  %LAUNCHER_VERSION%
echo   https://github.com/freshdex/xct-win8bridge
echo ============================================================
echo.

rem --- pre-flight teardown ---------------------------------------------------
rem If a previous launch.bat run was killed before its watcher could fire
rem stop.bat (force-killed via Task Manager, system crash, the watcher
rem race-lost to a slow proxy unset, etc.), the system still has the old
rem proxy registry pointed at 127.0.0.1:<old port> with no listener -- and
rem step [1/7]'s pip install then fails with WinError 10061 ("target
rem machine actively refused"). Wipe stale proxy + helper state up-front
rem so each launch can come up clean even if the prior one didn't shut
rem down properly. Idempotent: a normal launch starts with no stale state
rem and these are no-ops.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
netsh winhttp reset proxy >nul 2>&1
taskkill /F /IM mitmdump.exe      >nul 2>&1
taskkill /F /IM mitmweb.exe       >nul 2>&1
taskkill /F /IM ticket_server.exe >nul 2>&1

rem --- auto-update check -----------------------------------------------------
rem Skip if: we just updated in this session, or the user has a git checkout
rem (contributors manage their own version via git).
if defined XCT_JUST_UPDATED (
    echo [*] Update just applied -- skipping update check.
    goto :update_done
)
if exist "%~dp0.git" (
    echo [*] Git checkout detected -- skipping auto-update.
    goto :update_done
)

echo [*] Checking for launcher updates...
set "REMOTE_VERSION="
for /f "delims=" %%i in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $latest = (Invoke-RestMethod -Uri 'https://api.github.com/repos/freshdex/xct-win8bridge/releases/latest' -TimeoutSec 5).tag_name; if ([version]$latest.TrimStart('v') -gt [version]('%LAUNCHER_VERSION%').TrimStart('v')) { $latest } } catch { }"') do set "REMOTE_VERSION=%%i"

if "%REMOTE_VERSION%"=="" (
    echo     [up to date or offline]
    goto :update_done
)

echo     New version %REMOTE_VERSION% available ^(you have %LAUNCHER_VERSION%^). Updating...

set "ZIP=%TEMP%\xct-win8bridge-%REMOTE_VERSION%.zip"
curl -L -f -s -o "%ZIP%" "https://github.com/freshdex/xct-win8bridge/archive/refs/tags/%REMOTE_VERSION%.zip"
if errorlevel 1 (
    echo     [download failed, continuing with current version]
    goto :update_done
)

set "EXTRACT_DIR=%TEMP%\xct-update-%REMOTE_VERSION%"
rmdir /s /q "%EXTRACT_DIR%" >nul 2>&1
powershell -NoProfile -Command "Expand-Archive -Path '%ZIP%' -DestinationPath '%EXTRACT_DIR%' -Force" >nul 2>&1
if errorlevel 1 (
    echo     [extract failed, continuing with current version]
    del "%ZIP%" >nul 2>&1
    goto :update_done
)

rem GitHub source zipballs extract to a single top-level dir (<repo>-<tag sans v>).
set "SRC="
for /d %%D in ("%EXTRACT_DIR%\*") do set "SRC=%%D"
if not defined SRC (
    echo     [extracted zip had no top-level dir, aborting update]
    del "%ZIP%" >nul 2>&1
    goto :update_done
)

rem Write a helper batch to TEMP that waits for us to exit, then overwrites
rem launch.bat safely and relaunches. Overwriting launch.bat while it is the
rem active script corrupts cmd.exe's line-seek state, so we must not do it
rem in-process.
set "HELPER=%TEMP%\xct-update-helper.cmd"
> "%HELPER%" echo @echo off
>> "%HELPER%" echo timeout /t 2 /nobreak ^>nul
>> "%HELPER%" echo robocopy "%SRC%" "%~dp0." /E /IS /IT /XD target .git captures patches build /NFL /NDL /NJH /NJS /NP ^>nul
>> "%HELPER%" echo del "%ZIP%" ^>nul 2^>^&1
>> "%HELPER%" echo rmdir /s /q "%EXTRACT_DIR%" ^>nul 2^>^&1
>> "%HELPER%" echo set "XCT_JUST_UPDATED=1"
>> "%HELPER%" echo start "" "%~f0"

echo     Handing off to updater and relaunching...
start "" "%HELPER%"
exit /b 0

:update_done

rem --- port selection --------------------------------------------------------
rem Default mitmproxy listen port is 8080. That collides with SABnzbd,
rem Tomcat, common dev servers, etc. Walk a fallback ladder of ports and
rem silently use the first free one -- no user prompt.
set "MITM_PORT="
for %%P in (8080 8081 8082 8083 8084 8085 8086 8087 18080 18081 18082 18083) do (
    if not defined MITM_PORT (
        powershell -NoProfile -Command "try { $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, %%P); $l.Start(); $l.Stop(); exit 0 } catch { exit 1 }"
        if not errorlevel 1 set "MITM_PORT=%%P"
    )
)
if not defined MITM_PORT (
    echo [!] No free port found in 8080..8087 / 18080..18083. Aborting.
    echo     Free up one of those ports or extend the search list near the
    echo     top of launch.bat.
    pause & exit /b 1
)
if not "%MITM_PORT%"=="8080" (
    echo [*] Port 8080 in use -- automatically using %MITM_PORT% instead.
)

rem --- dependency checks -----------------------------------------------------
where python >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found on PATH.
    echo     Install Python 3 from https://python.org and re-run.
    pause & exit /b 1
)

echo [1/7] Installing Python packages (mitmproxy, ecdsa)...
python -m pip install --quiet --disable-pip-version-check --upgrade mitmproxy ecdsa
if errorlevel 1 (
    echo [!] pip install failed. Check your internet/Python install and retry.
    pause & exit /b 1
)

rem The standalone mitmproxy Windows installer ships its own embedded
rem Python and cannot see the 'ecdsa' we just pip-installed. If that
rem mitmdump is on PATH, it wins and the bridge errors on import.
rem Resolve the pip-installed Scripts dir and prepend it to PATH so the
rem pip-install mitmdump wins in any spawned cmd.
set "MITMDUMP_DIR="
for /f "delims=" %%i in ('python -c "import os, sys, site, sysconfig; paths=[sysconfig.get_path('scripts'), os.path.join(sys.prefix, 'Scripts'), os.path.join(os.path.dirname(site.getusersitepackages()), 'Scripts')]; [print(p) for p in paths if os.path.exists(os.path.join(p, 'mitmdump.exe'))]"') do (
    if not defined MITMDUMP_DIR set "MITMDUMP_DIR=%%i"
)
if not defined MITMDUMP_DIR (
    echo [!] pip-installed mitmdump.exe not found under Python's Scripts dir.
    echo     This shouldn't happen after a successful pip install. Try:
    echo         python -m pip install --force-reinstall mitmproxy
    pause & exit /b 1
)
set "PATH=%MITMDUMP_DIR%;%PATH%"

echo [2/7] Locating ticket_server.exe...
rem Precedence:
rem   1. target\release\ticket_server.exe  (contributor's fresh cargo build)
rem   2. bin\ticket_server.exe             (binary committed to the repo)
rem   3. cargo build                       (contributor without a prior build)
set "TICKET_SERVER="
if exist "target\release\ticket_server.exe" (
    set "TICKET_SERVER=target\release\ticket_server.exe"
    echo       [using contributor build: target\release\ticket_server.exe]
) else if exist "bin\ticket_server.exe" (
    set "TICKET_SERVER=bin\ticket_server.exe"
    echo       [using bundled binary: bin\ticket_server.exe]
) else (
    where cargo >nul 2>&1
    if errorlevel 1 (
        echo [!] No ticket_server.exe found and Rust/cargo is not installed.
        echo     The repo is supposed to ship a prebuilt bin\ticket_server.exe.
        echo     Re-download the repo, or install Rust ^(https://rustup.rs^)
        echo     and run: cargo build --release --bin ticket_server
        pause & exit /b 1
    )
    echo       No prebuilt found. Building with cargo...
    cargo build --release --bin ticket_server
    if errorlevel 1 (
        echo [!] cargo build failed.
        pause & exit /b 1
    )
    set "TICKET_SERVER=target\release\ticket_server.exe"
)

rem --- mitmproxy CA + trust --------------------------------------------------
echo [3/7] Generating mitmproxy CA cert (once, if missing)...
if not exist "%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer" (
    echo       No CA on disk yet. Starting mitmdump briefly to generate one...
    start "" /B mitmdump --listen-port 18099 -q
    timeout /t 4 /nobreak >nul
    taskkill /F /IM mitmdump.exe >nul 2>&1
)

echo [4/7] Ensuring mitmproxy CA is trusted by Windows...
certutil -store -silent Root | findstr /C:"O=mitmproxy" >nul 2>&1
if errorlevel 1 (
    certutil -addstore -f Root "%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer"
    if errorlevel 1 (
        echo [!] Failed to install mitmproxy CA into LocalMachine\Root.
        pause & exit /b 1
    )
) else (
    echo       [already trusted]
)

rem --- loopback exemptions ---------------------------------------------------
echo [5/7] Granting loopback access to supported games...
CheckNetIsolation LoopbackExempt -a -n="Microsoft.MicrosoftMahjong_8wekyb3d8bbwe"             >nul 2>&1
CheckNetIsolation LoopbackExempt -a -n="Microsoft.MicrosoftMinesweeper_8wekyb3d8bbwe"         >nul 2>&1
CheckNetIsolation LoopbackExempt -a -n="Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe" >nul 2>&1
CheckNetIsolation LoopbackExempt -a -n="Microsoft.Adera_8wekyb3d8bbwe"                        >nul 2>&1
rem Microsoft Taptiles -- xct-taptiles-patcher offers two install paths,
rem both supported here. Exempt both PFNs so whichever path the user took
rem works. patch-and-install.ps1 preserves identity (PFN ends 8wekyb3d8bbwe)
rem and is "cleaner" but Microsoft.Xbox.dll appears to gate XBL locally
rem when the package claims to be Microsoft, so sign-in fails before any
rem network traffic. patch-rename.ps1 renames Name to Microsoft.Taptiles
rem .Patched + Publisher to CN=xct-taptiles-patcher (PFN ends 252h5yj5c87g0),
rem which makes the XBL chain actually attempt user.auth / title.auth /
rem xsts.auth -- where the modern-XBL3 forgery in xbl_bridge.py short-
rem circuits each call with our pre-minted XSTS.
CheckNetIsolation LoopbackExempt -a -n="Microsoft.Taptiles_8wekyb3d8bbwe"                     >nul 2>&1
CheckNetIsolation LoopbackExempt -a -n="Microsoft.Taptiles.Patched_252h5yj5c87g0"             >nul 2>&1
rem Microsoft Studios Wordament -- Win8-era ad-supported word-puzzle title.
rem Stock package crashes on launch (TWinUI 5961 / view-activation phase 4)
rem because XAML construction touches the retired comScore + Microsoft.
rem Advertising activatable types. xct-wordament-patcher strips those
rem activatable-class registrations from AppxManifest.xml and re-signs;
rem PFN is preserved so XBL recognises the TitleId.
CheckNetIsolation LoopbackExempt -a -n="Microsoft.Studios.Wordament_8wekyb3d8bbwe"             >nul 2>&1
rem Microsoft Rocket Riot 3D -- Win8-era DX11 game whose stock package
rem fails activation with HRESULT 0x803F8001 (LICENSE_E_NOT_AVAILABLE);
rem MS revoked the Store license same way they did Taptiles. xct-rocketriot
rem -patcher renames the package to .Patched / CN=xct-rocketriot-patcher
rem to sidestep the license check, then re-signs. Bridge handles the
rem unknown-TitleId via its modern-XBL3 forgery path.
CheckNetIsolation LoopbackExempt -a -n="Microsoft.RocketRiot.Patched_54fpwjmqm1ce6"            >nul 2>&1
rem TY the Tasmanian Tiger -- Win8-era port, stock package still activates
rem (license intact, no patcher needed). Just needs XBL sign-in bridged.
CheckNetIsolation LoopbackExempt -a -n="Microsoft.TYtheTasmanianTiger_8wekyb3d8bbwe"           >nul 2>&1
rem Assassin's Creed Pirates -- Ubisoft Win8 port, license intact on users
rem who bought it pre-delist. Stock package activates; XBL sign-in only
rem reaches the bridge once the UWP AppContainer loopback block is lifted.
CheckNetIsolation LoopbackExempt -a -n="Ubisoft.AssassinsCreedPirates_ngz4m417e0mpw"           >nul 2>&1
rem Hitman GO -- Square Enix Win8.1 port (Unity + Microsoft.Xbox.dll).
rem Stock package activates; the modern XBL3 chain it runs through
rem otherwise gates on packagespc.xboxlive.com/GetBasePackage which the
rem bridge's generic XSTS doesn't pass -- handled by the packagespc 403
rem shim in xbl_bridge.py.
CheckNetIsolation LoopbackExempt -a -n="39C668CD.HitmanGO_r7bfsmp40f67j"                       >nul 2>&1
rem Hydro Thunder Hurricane -- Microsoft Studios (Vector Unit) Win8 port.
rem Stock package activates; bridge handles legacy XBL2.0 sign-in via the
rem always-rewrite policy.
CheckNetIsolation LoopbackExempt -a -n="Microsoft.Studios.HydroThunderHurricane_8wekyb3d8bbwe" >nul 2>&1
echo       Mahjong, Minesweeper, Solitaire Collection, Adera, Taptiles, Wordament, RocketRiot, TY, AC Pirates, Hitman GO, Hydro Thunder exempted.

rem --- start ticket_server hidden, fall back to visible on cold consent -----
rem Default to hidden for a clean single-window UX. Once WAM has cached
rem the MSA consent for our client_id, /ticket completes via
rem GetTokenSilentlyAsync in ~50ms with no UI, so hidden is fine. The
rem probe below detects a cold cache (fresh machine, token expired,
rem consent revoked) by short-timing the first /ticket call; on failure
rem we kill the hidden instance and restart ticket_server VISIBLY so
rem WAM's consent dialog has a real parent window to render against.
rem A hidden console can't parent a visible dialog, which is what made
rem first-run consent silently hang in earlier v1.2.x builds.
echo [6/7] Starting ticket_server (hidden)...
set "TICKET_SERVER_LOG=%TEMP%\xct_ticket_server.log"
del "%TICKET_SERVER_LOG%" >nul 2>&1
start "" /B "%TICKET_SERVER%" > "%TICKET_SERVER_LOG%" 2>&1

rem Health-check before proceeding.
timeout /t 2 /nobreak >nul
powershell -NoProfile -Command "try { $null = Invoke-WebRequest -Uri 'http://127.0.0.1:8099/health' -TimeoutSec 3 -UseBasicParsing; exit 0 } catch { exit 1 }"
if errorlevel 1 (
    echo [!] ticket_server failed to start. Log tail:
    powershell -NoProfile -Command "Get-Content -Tail 20 '%TICKET_SERVER_LOG%' 2>$null"
    taskkill /F /IM ticket_server.exe >nul 2>&1
    pause & exit /b 1
)

rem Probe /ticket with a SHORT timeout. Warm cache -> returns in ~50ms,
rem done. Cold cache -> WAM tries to show a consent dialog which the
rem hidden console can't display, so the call hangs; we abort at 5s and
rem fall back to a visible ticket_server for the interactive flow.
echo       Probing WAM token cache...
powershell -NoProfile -Command "try { $null = Invoke-WebRequest -Uri 'http://127.0.0.1:8099/ticket' -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop; exit 0 } catch { exit 1 }"
if errorlevel 1 (
    echo       WAM cache cold -- restarting ticket_server visibly so a
    echo       Microsoft sign-in dialog can render. Approve it when it appears.
    taskkill /F /IM ticket_server.exe >nul 2>&1
    timeout /t 1 /nobreak >nul
    start "xct-win8bridge: ticket_server" cmd /k "%TICKET_SERVER%"
    timeout /t 2 /nobreak >nul
    powershell -NoProfile -Command "try { $null = Invoke-WebRequest -Uri 'http://127.0.0.1:8099/ticket' -TimeoutSec 120 -UseBasicParsing -ErrorAction Stop; exit 0 } catch { Write-Host ('       ' + $_.Exception.Message); exit 1 }"
    if errorlevel 1 (
        echo [!] Could not mint an MBI ticket. See the visible ticket_server
        echo     window for the underlying WAM error. Most common causes:
        echo       - consent dialog was cancelled or timed out
        echo       - the Windows-signed-in MSA is not permitted for Xbox Live
        taskkill /F /IM ticket_server.exe >nul 2>&1
        pause & exit /b 1
    )
    echo       [OK] Consent granted -- next launch will be silent and hidden.
) else (
    echo       [OK] WAM cache warm -- ticket minted silently.
)

rem --- enable proxies --------------------------------------------------------
echo [7/7] Enabling system proxies (WinINET + WinHTTP)...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:!MITM_PORT!" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
netsh winhttp set proxy proxy-server="127.0.0.1:!MITM_PORT!" bypass-list="<-loopback>" >nul

rem --- close-cleanup watcher ------------------------------------------------
rem cmd.exe doesn't run any downstream cleanup when its window dies. Only
rem the Ctrl+C -> N exit path falls through to the `call stop.bat` at the
rem bottom of this script; closing via the window X, taskkill, or Ctrl+C
rem -> Y all leave proxies pointed at 127.0.0.1:!MITM_PORT! and helpers running,
rem forcing the user to remember to launch stop.bat manually.
rem
rem Resolve our own PID via a unique window-title marker matched against
rem `tasklist /v`. (Don't try to use PowerShell's $PID.ParentProcessId --
rem PS is spawned under a `cmd /c` that for /f wraps around the command,
rem so its ParentProcessId is that intermediate cmd, which dies the moment
rem PS exits and would make Wait-Process fire stop.bat immediately.)
set "LAUNCHER_MARKER=xct-launcher-%RANDOM%-%RANDOM%-%RANDOM%"
title %LAUNCHER_MARKER%
set "LAUNCHER_PID="
for /f "tokens=2 delims=," %%p in ('tasklist /v /fo csv /nh ^| findstr /c:"%LAUNCHER_MARKER%"') do if not defined LAUNCHER_PID set "LAUNCHER_PID=%%~p"
title xct-win8bridge launcher %LAUNCHER_VERSION%

if defined LAUNCHER_PID (
    rem Watcher script: blocks on Wait-Process for the launcher's PID,
    rem then runs stop.bat. Idempotent against the inline `call stop.bat`
    rem at the end of this script.
    set "WATCHER_CMD=%TEMP%\xct_watcher.cmd"
    > "!WATCHER_CMD!" echo @echo off
    >> "!WATCHER_CMD!" echo powershell -NoProfile -Command "Wait-Process -Id !LAUNCHER_PID! -ErrorAction SilentlyContinue"
    >> "!WATCHER_CMD!" echo call "%~dp0stop.bat"

    rem VBS shim to run the watcher detached + truly hidden. Start-Process
    rem -WindowStyle Hidden is unreliable when invoked from an elevated
    rem cmd (intermittently flashes a window or fails to detach); the
    rem long-standing WScript.Shell.Run pattern with mode 0 is the
    rem bulletproof way to fire-and-forget a console process invisibly.
    rem `)` must be escaped as `^)` because we're inside an `if (...)`
    rem block and unescaped close-parens prematurely terminate the block,
    rem so without the caret the VBS gets written without its closing
    rem paren and cscript fails with "Expected ')'" at compile time.
    set "WATCHER_VBS=%TEMP%\xct_watcher.vbs"
    > "!WATCHER_VBS!" echo Set WshShell = CreateObject("WScript.Shell"^)
    >> "!WATCHER_VBS!" echo WshShell.Run "cmd /c """"!WATCHER_CMD!""""", 0, False
    cscript //nologo "!WATCHER_VBS!" >nul
)

color 0A
echo.
echo ============================================================
echo   READY -- mitmdump starts below in this window
echo ============================================================
echo.
echo   Launch any of these titles from your Start Menu:
echo.
echo     Microsoft Mahjong              Microsoft.MicrosoftMahjong_8wekyb3d8bbwe
echo     Microsoft Minesweeper          Microsoft.MicrosoftMinesweeper_8wekyb3d8bbwe
echo     Microsoft Solitaire Collection Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe
echo     Microsoft Adera                Microsoft.Adera_8wekyb3d8bbwe
echo     Microsoft Taptiles             Microsoft.Taptiles_8wekyb3d8bbwe
echo     Hitman GO                      39C668CD.HitmanGO_r7bfsmp40f67j
echo     Assassin's Creed Pirates       Ubisoft.AssassinsCreedPirates_ngz4m417e0mpw
echo     Hydro Thunder Hurricane        Microsoft.Studios.HydroThunderHurricane_8wekyb3d8bbwe
echo.
echo   Live intercepts scroll below. Expect lines like:
echo     [xbl_bridge] bridged GET profile.xboxlive.com/users/me/id
echo.
echo   Full session log (verbose, includes per-flow detail):
echo     %TEMP%\xct_mitmdump.log
echo.
echo   TO STOP:  close this window OR press Ctrl+C. A hidden
echo             watcher process runs stop.bat automatically
echo             when the launcher exits, regardless of how --
echo             proxies + helpers are reverted either way.
echo.
echo ============================================================
echo.

rem View filter: show xboxlive flows EXCEPT titlestorage. The addon's
rem titlestorage shim produces its own dedup-collapsed "[xbl_bridge]
rem titlestorage shim: ..." line per distinct shim event, which is the
rem useful signal. Leaving titlestorage in the view filter too would flood
rem the launcher window with per-flow request/response lines (games like
rem Mahjong poll titlestorage dozens of times per second). Non-xboxlive
rem traffic is already short-circuited by the addon and hidden here.
rem `[xbl_bridge]` ctx.log lines are logger-level, not view-filtered, so
rem they still appear regardless.
rem
rem connection_strategy=lazy + upstream_cert=false:
rem   Dead hosts like data.xboxlive.com still resolve in DNS but no longer
rem   accept TCP. In mitmproxy's default (eager) mode the proxy dials the
rem   upstream during CONNECT to grab its real cert, fails with "TCP
rem   refused"/timeout, and replies 502 Bad Gateway -- the client never
rem   gets to make the inner HTTP request, so the DEAD_HOSTS_SHIM_200 in
rem   xbl_bridge.py's request() hook never fires. Lazy mode defers the
rem   upstream connect until/unless it is actually needed, and
rem   upstream_cert=false tells mitmproxy to generate the MITM leaf cert
rem   from the client's SNI rather than the real server's cert. Together
rem   they let the addon synthesise a 200 response locally for dead hosts
rem   without ever touching upstream.
rem
rem ignore_hosts:
rem   Pass through (no TLS interception) for hosts that have nothing to do
rem   with the games -- Delivery Optimization, Windows Update telemetry,
rem   diagnostic data, Edge/SmartScreen, Defender. These were generating
rem   "Server TLS handshake failed. Certificate verify failed: unable to
rem   get local issuer certificate" warnings every few seconds because
rem   Microsoft signs them with internal-issuing CAs not in mitmproxy's
rem   bundled `certifi` CA list. Passthrough means the proxy doesn't try
rem   to terminate TLS for them at all -- the connection is relayed
rem   straight to the upstream, no cert check happens, no log noise. The
rem   game-relevant Microsoft hosts (`*.xboxlive.com`, `*.mp.microsoft.com`)
rem   are NOT in this list -- their CA chains validate fine against
rem   certifi.
set "MITM_IGNORE=--ignore-hosts \.dsp\.mp\.microsoft\.com$ --ignore-hosts \.update\.microsoft\.com$ --ignore-hosts \.events\.data\.microsoft\.com$ --ignore-hosts \.config\.edge\.skype\.com$ --ignore-hosts \.smartscreen\.microsoft\.com$ --ignore-hosts \.delivery\.mp\.microsoft\.com$"
mitmdump --listen-host 127.0.0.1 --listen-port !MITM_PORT! -s addon\xbl_bridge.py --flow-detail 1 --set connection_strategy=lazy --set upstream_cert=false %MITM_IGNORE% "~d xboxlive.com & ! ~d titlestorage.xboxlive.com"

rem Reached after mitmdump exits normally or the user presses Ctrl+C then N.
echo.
echo [*] mitmdump stopped. Running stop.bat to clean up...
call "%~dp0stop.bat"
