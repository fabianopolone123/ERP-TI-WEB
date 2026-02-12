@echo off
setlocal

set "SERVER_URL=http://ti-fabiano:8000/api/inventory/push/"
set "TOKEN=inv-4303e90894724852b3f2ea858209b010-5f506a1ec1b5"
set "SCRIPT_PATH=%~dp0inventory_agent.ps1"

if not "%~1"=="" set "SERVER_URL=%~1"
if not "%~2"=="" set "TOKEN=%~2"

if not exist "%SCRIPT_PATH%" (
  echo [ERRO] Script nao encontrado: %SCRIPT_PATH%
  exit /b 1
)

echo Executando inventario...
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" -ServerUrl "%SERVER_URL%" -Token "%TOKEN%"
set "ERR=%ERRORLEVEL%"

if not "%ERR%"=="0" (
  echo [ERRO] Falha ao executar inventario. Codigo: %ERR%
  exit /b %ERR%
)

echo [OK] Inventario enviado.
exit /b 0
