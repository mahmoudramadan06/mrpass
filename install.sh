#!/usr/bin/env bash
# mrpass installer - no root required.
# Prefers pipx; falls back to a local venv in ~/.local/share/mrpass-venv
# with a launcher symlinked into ~/.local/bin.
set -euo pipefail

cd "$(dirname "$0")"

echo "[+] Installing mrpass..."

if command -v pipx >/dev/null 2>&1; then
    pipx install --force .
    echo "[✓] Installed via pipx. Run: mrpass -h"
    exit 0
fi

VENV="$HOME/.local/share/mrpass-venv"
BIN_DIR="$HOME/.local/bin"

python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet .

mkdir -p "$BIN_DIR"
ln -sf "$VENV/bin/mrpass" "$BIN_DIR/mrpass"

echo "[✓] Installed to $VENV and linked as $BIN_DIR/mrpass"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        echo "[!] $BIN_DIR is not in your PATH. Add it with:"
        echo "      echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
        ;;
esac

echo "[✓] Run: mrpass -h"
