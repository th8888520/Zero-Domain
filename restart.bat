@echo off
chcp 65001 >nul 2>&1
cls
echo.
echo ========================================
echo   零域网关 - 正在重启
echo ========================================
echo.

echo [1/2] 停止旧服务...
set ZERODOMAIN_NOPAUSE=1
call "%~dp0stop.bat"
set ZERODOMAIN_NOPAUSE=

timeout /t 3 /nobreak >nul

echo.
echo [2/2] 启动新服务...
call "%~dp0start.bat"