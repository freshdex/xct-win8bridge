@echo off
rem xct-win8bridge launcher -- one-click setup + run with live intercept log.
rem Double-click this file. It will self-elevate (UAC prompt).

setlocal EnableDelayedExpansion
cd /d "%~dp0"

rem === Launcher version -- BUMP this before tagging a release on GitHub.
rem     launch.bat auto-updates by comparing this against the latest release
rem     tag; a forgotten bump means users ship-loop re-downloading.
set "LAUNCHER_VERSION=v1.2.3"

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
echo       Mahjong, Minesweeper, Solitaire Collection, Adera exempted.

rem --- start ticket_server hidden -------------------------------------------
rem ticket_server normally prints one "listening on..." line and nothing else,
rem so it's safe to run silently with output captured to a log file. Running
rem it via `start /B` keeps it tied to this console -- if the user closes
rem the window, ticket_server dies with it (stop.bat would otherwise orphan).
echo [6/7] Starting ticket_server (hidden, log: %%TEMP%%\xct_ticket_server.log)...
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

rem --- enable proxies --------------------------------------------------------
echo [7/7] Enabling system proxies (WinINET + WinHTTP)...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:8080" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
netsh winhttp set proxy proxy-server="127.0.0.1:8080" bypass-list="<-loopback>" >nul

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
echo.
echo   Live intercepts scroll below. Expect lines like:
echo     [xbl_bridge] bridged GET profile.xboxlive.com/users/me/id
echo.
echo   TO STOP:  press Ctrl+C, then type N at the "Terminate
echo             batch job (Y/N)?" prompt. Answering N lets
echo             stop.bat run and reverses the proxies.
echo             (Y skips cleanup -- proxies stay on; run
echo             stop.bat manually if that happens.)
echo.
echo ============================================================
echo.

rem `~d xboxlive.com` is a mitmproxy view filter -- it only suppresses the
rem per-flow stdout lines for non-xboxlive hosts. The addon still sees every
rem flow (and short-circuits non-xboxlive ones itself), and `[xbl_bridge]`
rem ctx.log lines are unaffected. This just hides the user's general browsing
rem traffic from the launcher window.
mitmdump --listen-host 127.0.0.1 --listen-port 8080 -s addon\xbl_bridge.py --flow-detail 1 "~d xboxlive.com"

rem Reached after mitmdump exits normally or the user presses Ctrl+C then N.
echo.
echo [*] mitmdump stopped. Running stop.bat to clean up...
call "%~dp0stop.bat"
