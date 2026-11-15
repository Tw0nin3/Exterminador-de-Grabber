@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python nao foi encontrado no PATH.
  echo Instale Python 3.10+ em https://www.python.org/downloads/windows/
  echo Marque "Add python.exe to PATH" durante a instalacao.
  pause
  exit /b 1
)
python discord_grabber_remover.py
if errorlevel 1 pause
