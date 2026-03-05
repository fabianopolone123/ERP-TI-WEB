@echo off
setlocal EnableExtensions

set "SCRIPT_DIR=%~dp0"
set "TARGET_DIR=C:\ProgramData\ERP-TI\bootstrap"
set "LOG_DIR=C:\ProgramData\ERP-TI\logs"
set "LOG_FILE=%LOG_DIR%\gpo_bootstrap.log"

set "SERVER_BASE_URL=%~1"
set "TOKEN=%~2"
set "POLL_INTERVAL=%~3"

if "%SERVER_BASE_URL%"=="" set "SERVER_BASE_URL=http://ti-fabiano:8000"
if "%POLL_INTERVAL%"=="" set "POLL_INTERVAL=45"

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%" >nul 2>&1
echo [%date% %time%] Inicio bootstrap GPO inventario (modo push no logon)>> "%LOG_FILE%"

if "%TOKEN%"=="" (
  echo [%date% %time%] ERRO: token nao informado nos parametros do script.>> "%LOG_FILE%"
  exit /b 2
)

if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%" >nul 2>&1

copy /Y "%SCRIPT_DIR%install_inventory_agent_service.ps1" "%TARGET_DIR%\" >> "%LOG_FILE%" 2>&1
if errorlevel 1 (
  echo [%date% %time%] ERRO: falha ao copiar install_inventory_agent_service.ps1>> "%LOG_FILE%"
  exit /b 3
)

copy /Y "%SCRIPT_DIR%inventory_agent.ps1" "%TARGET_DIR%\" >> "%LOG_FILE%" 2>&1
if errorlevel 1 (
  echo [%date% %time%] ERRO: falha ao copiar inventory_agent.ps1>> "%LOG_FILE%"
  exit /b 4
)

powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-ChildItem -Path '%TARGET_DIR%\*.ps1' -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue" >> "%LOG_FILE%" 2>&1

powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%TARGET_DIR%\install_inventory_agent_service.ps1" -ServerBaseUrl "%SERVER_BASE_URL%" -Token "%TOKEN%" -PollIntervalSec %POLL_INTERVAL% >> "%LOG_FILE%" 2>&1
set "ERR=%ERRORLEVEL%"

if not "%ERR%"=="0" (
  echo [%date% %time%] ERRO: instalador retornou %ERR%.>> "%LOG_FILE%"
  exit /b %ERR%
)

echo [%date% %time%] SUCESSO: bootstrap concluido.>> "%LOG_FILE%"
exit /b 0
