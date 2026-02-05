@echo off
setlocal

rem Start ERP-TI-WEB Django server

set "ROOT=%~dp0"
cd /d "%ROOT%"

if exist "%ROOT%.venv\Scripts\activate.bat" (
  call "%ROOT%.venv\Scripts\activate.bat"
) else (
  echo [ERRO] Ambiente virtual .venv nao encontrado.
  echo Crie com: python -m venv .venv
  pause
  exit /b 1
)

python manage.py runserver 0.0.0.0:8010

endlocal
