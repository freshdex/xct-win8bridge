@echo off
rem xct-win8bridge teardown -- reverse launch.bat.

setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    echo [*] Relaunching elevated...
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title xct-win8bridge stop
color 0C

echo.
echo [*] Disabling WinINET proxy...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul

echo [*] Resetting WinHTTP proxy...
netsh winhttp reset proxy >nul

echo [*] Stopping helpers...
taskkill /F /IM mitmdump.exe      >nul 2>&1
taskkill /F /IM mitmweb.exe       >nul 2>&1
taskkill /F /IM ticket_server.exe >nul 2>&1

rem Clear the published bridge port so a fresh launch.bat picks a
rem genuinely-free port (and the win8pass shim sees no stale value if
rem it loads while the bridge is down). The ACL'd parent dir stays.
del "%ProgramData%\xct\bridge_port" >nul 2>&1

echo.
echo   Stopped. Proxies disabled, helpers terminated.
echo   Loopback exemptions + mitmproxy CA remain installed
echo   (re-runs of launch.bat are faster this way).
echo.
timeout /t 2 /nobreak >nul
