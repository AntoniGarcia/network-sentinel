#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "==> Creando entorno virtual en ./venv"
"$PYTHON_BIN" -m venv venv

echo "==> Activando entorno virtual"
# shellcheck disable=SC1091
source venv/bin/activate

echo "==> Actualizando pip"
pip install --upgrade pip

echo "==> Instalando dependencias de requirements.txt"
pip install -r requirements.txt

echo ""
echo "Setup completado."
if ! command -v tshark >/dev/null 2>&1; then
    echo "AVISO: no se encontró 'tshark' en el PATH. Instálalo antes de continuar:"
    echo "  - Debian/Ubuntu: sudo apt install tshark"
    echo "  - macOS:         brew install wireshark"
fi
echo ""
echo "Para ejecutar el dashboard:"
echo "  source venv/bin/activate"
echo "  streamlit run app.py"
echo ""
echo "Recuerda: la captura de paquetes requiere privilegios de root/sudo"
echo "o permisos configurados para dumpcap/tshark."
