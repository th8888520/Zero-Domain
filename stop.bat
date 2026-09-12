@echo off
chcp 65001 >nul 2>&1
cls
echo.
echo ========================================
echo   零域网关 - 正在停止
echo ========================================
echo.

set "SCRIPT_DIR=%~dp0"
set "LISTEN_PORT=8787"
if exist "%SCRIPT_DIR%.env" (
  for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%SCRIPT_DIR%.env") do (
    if /I "%%A"=="LISTEN_PORT" set "LISTEN_PORT=%%B"
  )
)
if "%LISTEN_PORT%"=="" set "LISTEN_PORT=8787"

REM Restore Claude settings (.zero-domain.backup; legacy .zerodomain.backup supported)
echo [1/4] 还原 Claude settings...
set "SETTINGS_FILE=%USERPROFILE%\.claude\settings.json"
set "BACKUP_FILE=%USERPROFILE%\.claude\settings.json.zero-domain.backup"
set "LEGACY_BACKUP=%USERPROFILE%\.claude\settings.json.zerodomain.backup"
if exist "%LEGACY_BACKUP%" if not exist "%BACKUP_FILE%" (
    echo   正在迁移旧版备份文件名...
    move /Y "%LEGACY_BACKUP%" "%BACKUP_FILE%" >nul 2>&1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%restore-claude.ps1" -SettingsFile "%SETTINGS_FILE%" -BackupFile "%BACKUP_FILE%"

echo.
echo [2/4] 关闭系统代理...
reg add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
echo   系统代理已关闭

REM Stop process on LISTEN_PORT only. Graceful first, then force kill.
echo.
echo [3/4] 查找端口 %LISTEN_PORT% 上的零域进程...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr /R /C:":%LISTEN_PORT% .*LISTENING"') do (
    echo   发现进程 PID: %%a
    echo   正在优雅停止...
    taskkill /PID %%a >nul 2>&1
    timeout /t 4 /nobreak >nul
    tasklist /FI "PID eq %%a" 2>nul | findstr /I "%%a" >nul 2>&1
    if not errorlevel 1 (
        echo   优雅停止超时，正在强制结束...
        taskkill /F /PID %%a >nul 2>&1
        timeout /t 2 /nobreak >nul
    )
    goto :stopped
)
echo   未发现运行中的进程
goto :end

:stopped
echo   服务已停止

:end
echo.
echo [4/4] 校验端口状态...
netstat -ano | findstr /R /C:":%LISTEN_PORT% .*LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo   端口仍被占用
) else (
    echo   端口已释放
)

echo.
echo ========================================
echo   零域已停止
echo ========================================
echo.
if /I not "%ZERODOMAIN_NOPAUSE%"=="1" pause