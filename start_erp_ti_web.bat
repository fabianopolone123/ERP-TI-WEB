@echo off
setlocal

rem Start ERP-TI-WEB Django server

set "ROOT=%~dp0"
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
  call "%ROOT%.venv\Scripts\activate.bat"
  python -m pip install --upgrade pip
  python -m pip install -r requirements.txt
) else (
  call "%ROOT%.venv\Scripts\activate.bat"
)

python manage.py runserver 0.0.0.0:8000
if errorlevel 1 (
  echo.
  echo [ERRO] O servidor encerrou com erro.
  pause
)

endlocal
