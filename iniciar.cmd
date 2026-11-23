@echo off
setlocal
cd /d "%~dp0"
if not exist "venv\Scripts\python.exe" (
    echo Falta el entorno virtual. Ejecuta setup.ps1 primero.
    pause
    exit /b 1
)
"venv\Scripts\python.exe" -m streamlit run app.py --server.address 127.0.0.1
if errorlevel 1 pause
