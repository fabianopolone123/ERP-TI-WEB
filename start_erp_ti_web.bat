@echo off
setlocal

rem Start ERP-TI-WEB Django server

set "ROOT=S:\TI\Desenvolvimento\ERP-TI-WEB\"
if not exist "%ROOT%manage.py" (
  set "ROOT=%~dp0"
)
cd /d "%ROOT%"

if not exist "%ROOT%.venv\Scripts\activate.bat" (
  echo [INFO] Criando ambiente virtual .venv...
  python -m venv .venv
  if errorlevel 1 (
    echo [ERRO] Falha ao criar .venv.
    pause
    exit /b 1
  )
  echo [INFO] Instalando dependencias...
)

call "%ROOT%.venv\Scripts\activate.bat"
"%ROOT%.venv\Scripts\python.exe" -m pip install --upgrade pip
"%ROOT%.venv\Scripts\python.exe" -m pip install -r requirements.txt

"%ROOT%.venv\Scripts\python.exe" -c "from config import settings; import sys; sys.exit(0 if settings.AD_LDAP_BIND_PASSWORD else 2)"
if errorlevel 1 (
  echo [ERRO] ERP_LDAP_BIND_PASSWORD nao encontrado no .env
  echo Crie o arquivo .env com: ERP_LDAP_BIND_PASSWORD=SUASENHA
  pause
  exit /b 1
)

if exist "%ROOT%Caddyfile" (
  where caddy >nul 2>nul
  if errorlevel 1 (
    echo [AVISO] Caddyfile encontrado, mas Caddy nao esta no PATH.
    echo [INFO] Iniciando em HTTP ^(fallback^): http://0.0.0.0:8000
    "%ROOT%.venv\Scripts\python.exe" manage.py runserver 0.0.0.0:8000
    if errorlevel 1 (
      echo.
      echo [ERRO] O servidor encerrou com erro.
      pause
    )
  ) else (
    echo [INFO] Modo HTTPS detectado ^(Caddyfile encontrado^).
    echo [INFO] Iniciando Django em 127.0.0.1:8000...
    start "ERP Django" cmd /k "cd /d %ROOT% && .venv\Scripts\activate.bat && .venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000"
    echo [INFO] Iniciando Caddy...
    caddy run --config "%ROOT%Caddyfile"
    if errorlevel 1 (
      echo.
      echo [ERRO] Caddy encerrou com erro.
      pause
    )
  )
) else (
  echo [INFO] Caddyfile nao encontrado. Iniciando em HTTP: http://0.0.0.0:8000
  echo [INFO] Para HTTPS: execute scripts\setup_https.ps1 uma vez.
  "%ROOT%.venv\Scripts\python.exe" manage.py runserver 0.0.0.0:8000
  if errorlevel 1 (
    echo.
    echo [ERRO] O servidor encerrou com erro.
    pause
  )
)

endlocal
