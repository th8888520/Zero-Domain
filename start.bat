@echo off
chcp 65001 >nul 2>&1
cls
echo.
echo ========================================
echo   零域网关 - 正在启动
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

echo [1/5] 检查端口 %LISTEN_PORT%...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr /R /C:":%LISTEN_PORT% .*LISTENING"') do (
    echo   发现旧进程 PID: %%a，正在优雅停止...
    taskkill /PID %%a >nul 2>&1
    timeout /t 3 /nobreak >nul
    tasklist /FI "PID eq %%a" 2>nul | findstr /I "%%a" >nul 2>&1
    if not errorlevel 1 (
        echo   仍在运行，强制结束 PID: %%a
        taskkill /F /PID %%a >nul 2>&1
        timeout /t 1 /nobreak >nul
    )
)
echo   端口已就绪

REM Backup and configure Claude settings (.zero-domain.backup)
echo.
echo [2/5] 配置 Claude settings...
set "SETTINGS_FILE=%USERPROFILE%\.claude\settings.json"
set "BACKUP_FILE=%USERPROFILE%\.claude\settings.json.zero-domain.backup"
set "LEGACY_BACKUP=%USERPROFILE%\.claude\settings.json.zerodomain.backup"
if exist "%LEGACY_BACKUP%" if not exist "%BACKUP_FILE%" (
    echo   正在迁移旧版备份文件名...
    move /Y "%LEGACY_BACKUP%" "%BACKUP_FILE%" >nul 2>&1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%configure-claude.ps1" -SettingsFile "%SETTINGS_FILE%" -BackupFile "%BACKUP_FILE%" -ProxyURL "http://127.0.0.1:%LISTEN_PORT%"

echo.
echo [3/5] 启动零域...
cd /d "%SCRIPT_DIR%"
if not exist logs mkdir logs
start /B "" bun run src/index.ts >logs\zerodomain.log 2>&1

echo   等待服务就绪...
timeout /t 5 /nobreak >nul

echo.
echo [4/5] 校验服务状态...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr /R /C:":%LISTEN_PORT% .*LISTENING"') do (
    echo   服务已启动，PID: %%a
    set ZERODOMAIN_PID=%%a
    goto :verified
)
echo   启动失败，请查看 logs\zerodomain.log
pause
exit /b 1

:verified
echo.
echo [5/5] 打开管理后台...
timeout /t 2 /nobreak >nul
start http://127.0.0.1:%LISTEN_PORT%/admin

echo.
echo ========================================
echo   零域已启动成功
echo ========================================
echo.
echo   管理后台: http://127.0.0.1:%LISTEN_PORT%/admin
echo   管理令牌: 见 .env 中的 PROXY_ADMIN_TOKEN
echo   进程 PID: %ZERODOMAIN_PID%
echo.
echo   Claude settings 备份路径:
echo   %BACKUP_FILE%
echo.
echo ========================================
echo.
pause