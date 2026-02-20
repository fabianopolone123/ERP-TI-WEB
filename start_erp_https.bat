@echo off
setlocal

set "ROOT=S:\TI\Desenvolvimento\ERP-TI-WEB\"
if not exist "%ROOT%manage.py" (
  set "ROOT=%~dp0"
)
cd /d "%ROOT%"

if not exist "%ROOT%.venv\Scripts\activate.bat" (
  echo [ERRO] Ambiente virtual .venv nao encontrado. Execute start_erp_ti_web.bat primeiro.
  pause
  exit /b 1
)

if not exist "%ROOT%Caddyfile" (
  echo [ERRO] Caddyfile nao encontrado.
  echo Execute: powershell -ExecutionPolicy Bypass -File scripts\setup_https.ps1 -HostName erp-ti.local -ServerIP SEU_IP
  pause
  exit /b 1
)

where caddy >nul 2>nul
if errorlevel 1 (
  echo [ERRO] Caddy nao encontrado no PATH.
  echo Instale o Caddy ou rode scripts\setup_https.ps1
  pause
  exit /b 1
)

call "%ROOT%.venv\Scripts\activate.bat"
"%ROOT%.venv\Scripts\python.exe" -m pip install -r requirements.txt

echo [INFO] Iniciando Django em 127.0.0.1:8000...
start "ERP Django" cmd /k "cd /d %ROOT% && .venv\Scripts\activate.bat && .venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000"

echo [INFO] Iniciando HTTPS com Caddy...
caddy run --config "%ROOT%Caddyfile"

endlocal
