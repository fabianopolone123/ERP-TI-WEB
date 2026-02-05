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
)

call "%ROOT%.venv\Scripts\activate.bat"
"%ROOT%.venv\Scripts\python.exe" -m pip install --upgrade pip
"%ROOT%.venv\Scripts\python.exe" -m pip install -r requirements.txt

"%ROOT%.venv\Scripts\python.exe" manage.py runserver 0.0.0.0:8000
if errorlevel 1 (
  echo.
  echo [ERRO] O servidor encerrou com erro.
  pause
)

endlocal
