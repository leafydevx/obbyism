#!/usr/bin/env bash
# ──────────────────────────────────────────────────
#  Obbyism Installer
#  Usage:
#    Local:   cd obbyism && ./install.sh
#    Remote:  curl -sSL <your-raw-url>/install.sh | bash
# ──────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
  ___  ____  ____  _  _ ___ ____ _  _
 / _ \| __ )| __ )| \/ |_ _/ ___| \/ |
| | | |  _ \|  _ \| |\/| || |\___ | |\/| |
| |_| | |_) | |_) | |  | || |___) | |  | |
 \___/|____/|____/|_|  |_|___|____/|_|  |_|
EOF
    echo -e "${NC}"
    echo -e "  ${BOLD}Ethical Hacking Framework — Installer${NC}"
    echo ""
}

info()    { echo -e "  ${CYAN}[*]${NC} $1"; }
success() { echo -e "  ${GREEN}[+]${NC} $1"; }
warn()    { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail()    { echo -e "  ${RED}[-]${NC} $1"; exit 1; }

banner

# ── Check Python ─────────────────────────────────
info "Checking Python..."
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
        major=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo 0)
        minor=$("$cmd" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo 0)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    fail "Python 3.8+ is required. Install it and retry."
fi
success "Found $PYTHON ($ver)"

# ── Locate source ────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SRC_DIR=""

if [ -f "$SCRIPT_DIR/pyproject.toml" ] && [ -d "$SCRIPT_DIR/obbyism" ]; then
    SRC_DIR="$SCRIPT_DIR"
    info "Installing from local source: $SRC_DIR"
elif [ -f "./pyproject.toml" ] && [ -d "./obbyism" ]; then
    SRC_DIR="$(pwd)"
    info "Installing from current directory: $SRC_DIR"
else
    info "No local source found. Cloning from git..."
    REPO_URL="${OBBYISM_REPO:-}"
    if [ -z "$REPO_URL" ]; then
        fail "Set OBBYISM_REPO=<git-url> or run this script from the obbyism directory."
    fi
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    git clone --depth 1 "$REPO_URL" "$TMPDIR/obbyism"
    SRC_DIR="$TMPDIR/obbyism"
fi

# ── Install ──────────────────────────────────────
INSTALL_DIR="${HOME}/.local/share/obbyism"
BIN_DIR="${HOME}/.local/bin"

info "Installing Obbyism to $INSTALL_DIR"

# Try pip first, fall back to direct install
USED_PIP=false
if "$PYTHON" -m pip --version &>/dev/null; then
    info "pip found — installing via pip..."
    if "$PYTHON" -m pip install "$SRC_DIR" --break-system-packages 2>/dev/null \
        || "$PYTHON" -m pip install "$SRC_DIR" --user 2>/dev/null \
        || "$PYTHON" -m pip install "$SRC_DIR" 2>/dev/null; then
        USED_PIP=true
        success "Installed via pip"
        # Try optional deps
        "$PYTHON" -m pip install dnspython --break-system-packages 2>/dev/null \
            || "$PYTHON" -m pip install dnspython --user 2>/dev/null \
            || true
    fi
fi

if [ "$USED_PIP" = false ]; then
    info "pip not available — installing directly..."

    # Copy source to install directory
    rm -rf "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    cp -r "$SRC_DIR/obbyism" "$INSTALL_DIR/obbyism"

    # Create launcher script
    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/obbyism" << LAUNCHER
#!/usr/bin/env bash
export PYTHONPATH="$INSTALL_DIR:\${PYTHONPATH:-}"
exec $PYTHON -m obbyism "\$@"
LAUNCHER
    chmod +x "$BIN_DIR/obbyism"
    success "Installed to $INSTALL_DIR"
    success "Launcher created at $BIN_DIR/obbyism"
fi

# ── Create data directory ────────────────────────
DATADIR="${HOME}/.obbyism"
mkdir -p "$DATADIR/sessions" "$DATADIR/reports" "$DATADIR/auth_logs"
success "Data directory: $DATADIR"

# ── Ensure PATH ──────────────────────────────────
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    # Add to shell rc files
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -f "$rc" ]; then
            if ! grep -q 'local/bin' "$rc" 2>/dev/null; then
                echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"
                info "Added ~/.local/bin to PATH in $(basename "$rc")"
            fi
        fi
    done
    export PATH="$BIN_DIR:$PATH"
fi

# ── Verify ───────────────────────────────────────
echo ""
if command -v obbyism &>/dev/null; then
    success "Obbyism installed successfully!"
    echo ""
    obbyism --version
else
    warn "Installed but 'obbyism' may not be in PATH for this shell."
    warn "Restart your terminal or run: export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo ""
echo -e "  ${DIM}────────────────────────────────────────${NC}"
echo -e "  ${BOLD}Quick start:${NC}"
echo -e "    ${CYAN}obbyism modules${NC}          List available modules"
echo -e "    ${CYAN}obbyism recon <target>${NC}   Run reconnaissance"
echo -e "    ${CYAN}obbyism scan <target>${NC}    Port scan a target"
echo -e "    ${CYAN}obbyism vuln <target>${NC}    Vulnerability assessment"
echo -e "    ${CYAN}obbyism full <target>${NC}    Full assessment pipeline"
echo -e "  ${DIM}────────────────────────────────────────${NC}"
echo ""
echo -e "  ${YELLOW}Only use against targets you have authorization to test.${NC}"
echo ""
