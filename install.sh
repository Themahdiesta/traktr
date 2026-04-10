#!/usr/bin/env bash
# TRAKTR Quick Installer
# Usage: curl -sL https://raw.githubusercontent.com/Themahdiesta/traktr/main/install.sh | bash
#    or: git clone https://github.com/Themahdiesta/traktr.git && cd traktr && ./install.sh
set -euo pipefail

REPO="https://github.com/Themahdiesta/traktr.git"
INSTALL_DIR="${TRAKTR_HOME:-${HOME}/.traktr}"
BIN_DIR="${HOME}/.local/bin"

banner() {
  cat << 'EOF'

  ___________              __    __
  \__    ___/___________  |  | _/  |________
    |    |  \_  __ \__  \ |  |/ \   __\_  __ \
    |    |   |  | \// __ \|    < |  |  |  | \/
    |____|   |__|  (____  |__|_ \|__|  |__|
                        \/     \/
       ~ plowing the web ~    v2.0
            <3 By @mahdiesta

EOF
}

banner

# ── Step 1: Clone or detect local repo ──────────────────────────────────
TRAKTR_ROOT=""
if [[ -f "$(pwd)/src/core/traktr.sh" ]]; then
  TRAKTR_ROOT="$(pwd)"
  echo "[*] Using local repository: $TRAKTR_ROOT"
elif [[ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/src/core/traktr.sh" ]]; then
  TRAKTR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  echo "[*] Using script directory: $TRAKTR_ROOT"
else
  echo "[*] Cloning traktr repository..."
  git clone --depth 1 "$REPO" "${INSTALL_DIR}/repo"
  TRAKTR_ROOT="${INSTALL_DIR}/repo"
fi

# ── Step 2: Run the full installer ──────────────────────────────────────
echo "[*] Running dependency installer..."
export TRAKTR_ROOT
bash "${TRAKTR_ROOT}/src/core/installer.sh" "$@"

# ── Step 3: Create traktr command ───────────────────────────────────────
mkdir -p "$BIN_DIR"
cat > "${BIN_DIR}/traktr" << WRAPPER
#!/usr/bin/env bash
export TRAKTR_ROOT="${TRAKTR_ROOT}"
export PATH="\${HOME}/go/bin:/usr/local/go/bin:\${HOME}/.local/bin:\${PATH}"
exec bash "\${TRAKTR_ROOT}/src/core/traktr.sh" "\$@"
WRAPPER
chmod +x "${BIN_DIR}/traktr"

# ── Step 4: Ensure PATH includes ~/.local/bin ───────────────────────────
PATH_LINE='export PATH="${HOME}/.local/bin:${PATH}"'
for rc in "${HOME}/.bashrc" "${HOME}/.zshrc"; do
  if [[ -f "$rc" ]] && ! grep -qF '.local/bin' "$rc" 2>/dev/null; then
    echo "$PATH_LINE" >> "$rc"
  fi
done
export PATH="${BIN_DIR}:${PATH}"

echo ""
echo "============================================"
echo "  Traktr installed successfully!"
echo ""
echo "  Usage:"
echo "    traktr https://target.com"
echo "    traktr https://target.com --oscp"
echo "    traktr -r burp_request.txt"
echo ""
echo "  If 'traktr' is not found, run:"
echo "    source ~/.bashrc   # or ~/.zshrc"
echo "============================================"
