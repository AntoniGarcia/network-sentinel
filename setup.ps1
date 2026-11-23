#Requires -Version 5.1
$ErrorActionPreference = "Stop"

Set-Location -Path $PSScriptRoot

Write-Host "==> Creando entorno virtual en .\venv"
python -m venv venv

Write-Host "==> Activando entorno virtual"
& ".\venv\Scripts\Activate.ps1"

Write-Host "==> Actualizando pip"
python -m pip install --upgrade pip

Write-Host "==> Instalando dependencias de requirements.txt"
pip install -r requirements.txt

Write-Host ""
Write-Host "Setup completado." -ForegroundColor Green

$tshark = Get-Command tshark -ErrorAction SilentlyContinue
if (-not $tshark) {
    Write-Host "AVISO: no se encontro 'tshark' en el PATH." -ForegroundColor Yellow
    Write-Host "Instala Wireshark (incluye TShark) desde https://www.wireshark.org/download.html"
    Write-Host "o ejecuta: choco install wireshark"
}

Write-Host ""
Write-Host "Para ejecutar el dashboard:"
Write-Host "  .\venv\Scripts\Activate.ps1"
Write-Host "  streamlit run app.py"
Write-Host ""
Write-Host "Recuerda: ejecuta la terminal como Administrador para que la" -ForegroundColor Yellow
Write-Host "captura de paquetes y la clasificacion por proceso funcionen." -ForegroundColor Yellow
