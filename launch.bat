@echo off
rem xct-win8bridge launcher — one-click setup + run with live intercept log.
rem Double-click this file. It will self-elevate (UAC prompt).

setlocal EnableDelayedExpansion
cd /d "%~dp0"

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
echo   xct-win8bridge launcher
echo   https://github.com/freshdex/xct-win8bridge
echo ============================================================
echo.

rem --- dependency checks -----------------------------------------------------
where python >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found on PATH.
    echo     Install Python 3 from https://python.org and re-run.
    pause & exit /b 1
)

where cargo >nul 2>&1
if errorlevel 1 (
    echo [!] Rust/cargo not found on PATH.
    echo     Install the stable Rust toolchain from https://rustup.rs and re-run.
    pause & exit /b 1
)

echo [1/7] Installing Python packages (mitmproxy, ecdsa)...
python -m pip install --quiet --disable-pip-version-check --upgrade mitmproxy ecdsa
if errorlevel 1 (
    echo [!] pip install failed. Check your internet/Python install and retry.
    pause & exit /b 1
)

echo [2/7] Building ticket_server (cached after first build)...
if not exist "target\release\ticket_server.exe" (
    cargo build --release --bin ticket_server
    if errorlevel 1 (
        echo [!] cargo build failed.
        pause & exit /b 1
    )
) else (
    echo       [cached]
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

rem --- start helpers ---------------------------------------------------------
echo [6/7] Launching ticket_server and mitmdump in new windows...

start "xct-win8bridge: ticket_server" cmd /k "title xct-win8bridge :: ticket_server& color 0A& target\release\ticket_server.exe"
timeout /t 2 /nobreak >nul

start "xct-win8bridge: mitmdump (live intercepts)" cmd /k "title xct-win8bridge :: mitmdump& color 0E& mitmdump --listen-host 127.0.0.1 --listen-port 8080 -s addon\xbl_bridge.py --flow-detail 1"

timeout /t 3 /nobreak >nul

rem --- enable proxies --------------------------------------------------------
echo [7/7] Enabling system proxies (WinINET + WinHTTP)...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:8080" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
netsh winhttp set proxy proxy-server="127.0.0.1:8080" bypass-list="<-loopback>" >nul

color 0A
echo.
echo ============================================================
echo   READY
echo ============================================================
echo.
echo   Launch Microsoft Mahjong or Microsoft Minesweeper now
echo   from your Start Menu. Live intercepts scroll in the
echo   "mitmdump" window — you should see lines like:
echo.
echo     [xbl_bridge] bridged GET profile.xboxlive.com/users/me/id
echo.
echo   When finished, run stop.bat (or close this window) to
echo   tear down proxies + helpers.
echo.
echo ============================================================
echo.
echo   Press any key to stop and tear down cleanly.
pause >nul

call "%~dp0stop.bat"
