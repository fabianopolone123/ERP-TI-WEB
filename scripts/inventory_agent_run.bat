@echo off
setlocal

set "SERVER_URL=http://ti-fabiano:8000/api/inventory/push/"
set "TOKEN=inv-4303e90894724852b3f2ea858209b010-5f506a1ec1b5"
set "SCRIPT_PATH=%~dp0inventory_agent.ps1"
set "LOG_DIR=%ProgramData%\ERP-TI\logs"
set "LOG_FILE=%LOG_DIR%\inventory_agent.log"

if not "%~1"=="" set "SERVER_URL=%~1"
if not "%~2"=="" set "TOKEN=%~2"

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%" >nul 2>nul

echo ------------------------------------------------------------>> "%LOG_FILE%"
echo [%date% %time%] Iniciando inventario.>> "%LOG_FILE%"
echo [%date% %time%] URL=%SERVER_URL%>> "%LOG_FILE%"
echo [%date% %time%] Script=%SCRIPT_PATH%>> "%LOG_FILE%"

if not exist "%SCRIPT_PATH%" (
  echo [ERRO] Script nao encontrado: %SCRIPT_PATH%
  echo [%date% %time%] [ERRO] Script nao encontrado: %SCRIPT_PATH%>> "%LOG_FILE%"
  exit /b 1
)

echo Executando inventario...
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" -ServerUrl "%SERVER_URL%" -Token "%TOKEN%" >> "%LOG_FILE%" 2>&1
set "ERR=%ERRORLEVEL%"

if not "%ERR%"=="0" (
  echo [ERRO] Falha ao executar inventario. Codigo: %ERR%
  echo [%date% %time%] [ERRO] Falha ao executar inventario. Codigo: %ERR%>> "%LOG_FILE%"
  exit /b %ERR%
)

echo [OK] Inventario enviado.
echo [%date% %time%] [OK] Inventario enviado.>> "%LOG_FILE%"
exit /b 0
