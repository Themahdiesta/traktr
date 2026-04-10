#!/usr/bin/env bash
# TRAKTR Installer v1.0 -- Installs all dependencies, tools, payloads, wordlists
# Usage: ./installer.sh [--dry-run] [--repair] [--upgrade]
set -euo pipefail

TRAKTR_HOME="${HOME}/.traktr"
TRAKTR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_FILE="${TRAKTR_ROOT}/logs/install.log"
GO_VERSION="1.22.2"
INSTALLED=0; SKIPPED=0; FAILED=0
DRY_RUN=false; REPAIR=false; UPGRADE=false

# ── Flags ────────────────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --repair)  REPAIR=true ;;
    --upgrade) UPGRADE=true ;;
    -h|--help) echo "Usage: installer.sh [--dry-run] [--repair] [--upgrade]"; exit 0 ;;
    *) echo "[!] Unknown flag: $arg"; exit 1 ;;
  esac
done

# ── Helpers ──────────────────────────────────────────────────────────────────
mkdir -p "${TRAKTR_ROOT}/logs" "${TRAKTR_HOME}/payloads"

log()  { local msg; msg="[$(date '+%H:%M:%S')] $1"; echo "$msg" | tee -a "$LOG_FILE"; }
ok()   { log "  [+] $1"; }
warn() { log "  [!] $1"; }
fail() { log "  [-] $1"; }

run() {
  if $DRY_RUN; then log "  [DRY-RUN] $*"; return 0; fi
  "$@" >> "$LOG_FILE" 2>&1
}

retry() {
  local max=$1 delay=3; shift
  for attempt in $(seq 1 "$max"); do
    if run "$@"; then return 0; fi
    warn "Attempt $attempt/$max failed: $*"
    sleep "$delay"; delay=$((delay * 2))
  done
  return 1
}

has_tool() { command -v "$1" &>/dev/null; }

tool_install() {
  local name=$1 check=$2; shift 2
  if has_tool "$check" && ! $REPAIR && ! $UPGRADE; then
    ok "$name already installed ($(command -v "$check"))"
    ((SKIPPED++)) || true; return 0
  fi
  log "  [~] Installing $name..."
  if retry 3 "$@"; then
    ok "$name installed"; ((INSTALLED++)) || true
  else
    fail "$name FAILED"; ((FAILED++)) || true
  fi
}

# ── Detect OS & Package Manager ─────────────────────────────────────────────
detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
      kali|ubuntu|debian|pop) PKG="apt-get"; PKG_INSTALL="sudo $PKG install -y" ;;
      arch|manjaro)           PKG="pacman";  PKG_INSTALL="sudo $PKG -S --noconfirm" ;;
      fedora)                 PKG="dnf";     PKG_INSTALL="sudo $PKG install -y" ;;
      *) warn "Unknown distro: $ID, trying apt"; PKG="apt-get"; PKG_INSTALL="sudo $PKG install -y" ;;
    esac
    log "[*] OS: $PRETTY_NAME | Pkg: $PKG"
  elif [[ "$(uname)" == "Darwin" ]]; then
    PKG="brew"; PKG_INSTALL="brew install"
    log "[*] OS: macOS $(sw_vers -productVersion) | Pkg: brew"
  else
    warn "Could not detect OS, defaulting to apt"
    PKG="apt-get"; PKG_INSTALL="sudo $PKG install -y"
  fi
}

# ── Step 1: System Dependencies ─────────────────────────────────────────────
install_system_deps() {
  log "[*] Step 1: System dependencies"
  for dep in jq curl git wget chromium python3 pip; do
    local check="$dep"
    [[ "$dep" == "pip" ]] && check="pip3"
    [[ "$dep" == "chromium" ]] && { has_tool chromium-browser && check="chromium-browser" || check="chromium"; }
    if has_tool "$check" && ! $REPAIR; then
      ok "$dep present"; ((SKIPPED++)) || true
    else
      log "  [~] Installing $dep..."
      if $DRY_RUN; then log "  [DRY-RUN] $PKG_INSTALL $dep"
      elif retry 2 "$PKG_INSTALL" "$dep"; then ok "$dep installed"; ((INSTALLED++)) || true
      else fail "$dep FAILED"; ((FAILED++)) || true
      fi
    fi
  done
}

# ── Step 2: Go ───────────────────────────────────────────────────────────────
install_go() {
  log "[*] Step 2: Go ${GO_VERSION}"
  if has_tool go && ! $REPAIR; then
    local cur; cur=$(go version | grep -oP 'go\K[0-9.]+')
    if [[ "$(printf '%s\n' "$GO_VERSION" "$cur" | sort -V | head -1)" == "$GO_VERSION" ]]; then
      ok "Go $cur >= $GO_VERSION"; ((SKIPPED++)) || true; return 0
    fi
  fi
  local arch; arch=$(uname -m)
  case "$arch" in
    x86_64)  arch="amd64" ;;
    aarch64) arch="arm64" ;;
    armv*)   arch="armv6l" ;;
  esac
  local os; os=$(uname -s | tr '[:upper:]' '[:lower:]')
  local tarball="go${GO_VERSION}.${os}-${arch}.tar.gz"
  local url="https://go.dev/dl/${tarball}"
  log "  [~] Downloading $url"
  if $DRY_RUN; then log "  [DRY-RUN] Download + extract Go"; return 0; fi
  retry 3 wget -q -O "/tmp/$tarball" "$url"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "/tmp/$tarball"
  rm -f "/tmp/$tarball"
  # Ensure PATH includes go binary dirs
  export PATH="/usr/local/go/bin:${HOME}/go/bin:$PATH"
  # shellcheck disable=SC2016
  if ! grep -q '/usr/local/go/bin' "${HOME}/.bashrc" 2>/dev/null; then
    echo 'export PATH="/usr/local/go/bin:${HOME}/go/bin:$PATH"' >> "${HOME}/.bashrc"
  fi
  # shellcheck disable=SC2016
  if ! grep -q '/usr/local/go/bin' "${HOME}/.zshrc" 2>/dev/null; then
    echo 'export PATH="/usr/local/go/bin:${HOME}/go/bin:$PATH"' >> "${HOME}/.zshrc"
  fi
  ok "Go $(go version | grep -oP 'go\K[0-9.]+') installed"
  ((INSTALLED++)) || true
}

# ── Step 3: Go Tools ────────────────────────────────────────────────────────
install_go_tools() {
  log "[*] Step 3: Go-based tools"
  export PATH="/usr/local/go/bin:${HOME}/go/bin:$PATH"
  declare -A GO_TOOLS=(
    [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
    [ffuf]="github.com/ffuf/ffuf/v2@latest"
    [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    [gau]="github.com/lc/gau/v2/cmd/gau@latest"
    [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [waybackurls]="github.com/tomnomnom/waybackurls@latest"
    [dalfox]="github.com/hahwul/dalfox/v2@latest"
  )
  for tool in "${!GO_TOOLS[@]}"; do
    # httpx: Kali ships Python httpx at /usr/bin/httpx; we need ProjectDiscovery's Go version
    if [[ "$tool" == "httpx" ]] && has_tool httpx && ! httpx -version 2>&1 | grep -qi 'projectdiscovery\|current'; then
      log "  [~] /usr/bin/httpx is Python httpx, installing PD httpx to ~/go/bin..."
      if retry 3 go install -v "${GO_TOOLS[$tool]}"; then ok "httpx (PD) installed to ~/go/bin"; ((INSTALLED++)) || true; else fail "httpx FAILED"; ((FAILED++)) || true; fi
      continue
    fi
    tool_install "$tool" "$tool" go install -v "${GO_TOOLS[$tool]}"
  done
}

# ── Step 4: Pip Tools ────────────────────────────────────────────────────────
install_pip_tools() {
  log "[*] Step 4: Python tools"
  for pkg in arjun commix; do
    tool_install "$pkg" "$pkg" pip3 install --break-system-packages "$pkg"
  done
}

# ── Step 5: Nuclei Templates ────────────────────────────────────────────────
update_nuclei_templates() {
  log "[*] Step 5: Nuclei templates"
  if has_tool nuclei; then
    run nuclei -update-templates
    ok "Nuclei templates updated"
  else
    warn "Nuclei not found, skipping template update"
  fi
}

# ── Step 6: Payload Repos ───────────────────────────────────────────────────
clone_payloads() {
  log "[*] Step 6: Payload repositories"
  declare -A REPOS=(
    [PayloadsAllTheThings]="https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    [SecLists]="https://github.com/danielmiessler/SecLists.git"
    [fuzzdb]="https://github.com/fuzzdb-project/fuzzdb.git"
  )
  for name in "${!REPOS[@]}"; do
    local dest="${TRAKTR_HOME}/payloads/${name}"
    if [ -d "$dest/.git" ] && ! $REPAIR && ! $UPGRADE; then
      ok "$name already cloned"; ((SKIPPED++)) || true
    elif [ -d "$dest/.git" ] && $UPGRADE; then
      log "  [~] Updating $name..."
      if retry 2 git -C "$dest" pull --depth 1; then ok "$name updated"; ((INSTALLED++)) || true
      else fail "$name update FAILED"; ((FAILED++)) || true; fi
    else
      log "  [~] Cloning $name (shallow)..."
      rm -rf "$dest"
      if retry 3 git clone --depth 1 "${REPOS[$name]}" "$dest"; then
        ok "$name cloned"; ((INSTALLED++)) || true
      else fail "$name FAILED"; ((FAILED++)) || true; fi
    fi
  done
}

# ── Step 7: Symlink Payloads ────────────────────────────────────────────────
organize_payloads() {
  log "[*] Step 7: Organizing payloads"
  local patt="${TRAKTR_HOME}/payloads/PayloadsAllTheThings"
  local sec="${TRAKTR_HOME}/payloads/SecLists"
  local dst="${TRAKTR_ROOT}/payloads"

  link_if_exists() {
    local src=$1 target=$2
    if [ -e "$src" ] && [ ! -e "$target" ]; then
      ln -sf "$src" "$target"
      ok "Linked $(basename "$target")"
    fi
  }

  # LFI
  link_if_exists "$patt/File Inclusion/Intruders" "$dst/lfi/patt_intruders"
  link_if_exists "$sec/Fuzzing/LFI" "$dst/lfi/seclists_lfi"

  # SQLi
  link_if_exists "$patt/SQL Injection/Intruder" "$dst/sqli/patt_sqli"
  link_if_exists "$sec/Fuzzing/SQLi" "$dst/sqli/seclists_sqli"

  # XSS
  link_if_exists "$patt/XSS Injection" "$dst/xss/patt_xss"
  link_if_exists "$sec/Fuzzing/XSS" "$dst/xss/seclists_xss"

  # RCE
  link_if_exists "$patt/Command Injection/Intruder" "$dst/rce/patt_rce"

  # SSRF
  link_if_exists "$patt/Server Side Request Forgery" "$dst/ssrf/patt_ssrf"

  # XXE
  link_if_exists "$patt/XXE Injection" "$dst/xxe/patt_xxe"

  # WAF Bypass
  link_if_exists "$sec/Fuzzing/Unicode" "$dst/waf_bypass/unicode"

  ok "Payload organization complete"
}

# ── Step 8: Wordlists ───────────────────────────────────────────────────────
build_wordlists() {
  log "[*] Step 8: Building wordlists"
  local wl="${TRAKTR_ROOT}/wordlists"
  mkdir -p "$wl"

  # Params wordlist -- top parameter names for brute-forcing
  if [ ! -f "$wl/params_common.txt" ] || $REPAIR || $UPGRADE; then
    local src_params="${TRAKTR_HOME}/payloads/SecLists/Discovery/Web-Content/burp-parameter-names.txt"
    if [ -f "$src_params" ]; then
      head -2000 "$src_params" > "$wl/params_common.txt"
      ok "params_common.txt: $(wc -l < "$wl/params_common.txt") entries"
    else
      # Fallback: generate essential params inline
      cat > "$wl/params_common.txt" << 'PARAMS'
id
page
file
path
url
search
q
query
redirect
next
return
goto
callback
action
cmd
exec
command
include
require
template
view
content
load
read
dir
folder
resource
src
ref
doc
document
download
filename
data
conf
config
log
type
name
user
username
email
password
pass
token
key
api_key
apikey
secret
auth
session
admin
debug
test
mode
lang
locale
format
output
sort
order
limit
offset
start
count
per_page
category
tag
status
role
access
level
group
filter
from
to
date
year
month
day
version
v
callback
jsonp
_method
_token
csrf
nonce
state
code
error
message
target
host
port
ip
domain
site
origin
referer
PARAMS
      ok "params_common.txt: fallback list generated"
    fi
  fi

  # Directories wordlist -- merged from SecLists
  if [ ! -f "$wl/dirs_common.txt" ] || $REPAIR || $UPGRADE; then
    local raft="${TRAKTR_HOME}/payloads/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
    local common="${TRAKTR_HOME}/payloads/SecLists/Discovery/Web-Content/common.txt"
    if [ -f "$raft" ] || [ -f "$common" ]; then
      cat "$raft" "$common" 2>/dev/null | sort -u > "$wl/dirs_common.txt"
      ok "dirs_common.txt: $(wc -l < "$wl/dirs_common.txt") entries"
    else
      warn "SecLists not found, dirs_common.txt skipped"
    fi
  fi

  # Secret patterns
  if [ ! -f "${TRAKTR_ROOT}/payloads/secrets/patterns.txt" ] || $REPAIR || $UPGRADE; then
    cat > "${TRAKTR_ROOT}/payloads/secrets/patterns.txt" << 'SECRETS'
# TRAKTR Secret Detection Patterns
# Format: LABEL<TAB>REGEX<TAB>CONFIDENCE
aws_access_key	AKIA[0-9A-Z]{16}	CONFIRMED
aws_secret_key	(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]	HIGH
gcp_api_key	AIza[0-9A-Za-z\-_]{35}	CONFIRMED
github_token	gh[ps]_[A-Za-z0-9_]{36,}	CONFIRMED
gitlab_token	glpat-[A-Za-z0-9\-]{20,}	CONFIRMED
slack_token	xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}	CONFIRMED
stripe_key	[rs]k_(live|test)_[A-Za-z0-9]{20,}	CONFIRMED
twilio_sid	SK[a-f0-9]{32}	CONFIRMED
sendgrid_key	SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}	CONFIRMED
mailgun_key	key-[0-9a-zA-Z]{32}	HIGH
firebase	AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}	HIGH
jwt	eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*	HIGH
basic_auth	Basic [A-Za-z0-9+/]{10,}={0,2}	POSSIBLE
bearer_token	Bearer [A-Za-z0-9_\-\.]{20,}	HIGH
private_key	-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----	CONFIRMED
api_key_assign	(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"][^\s'\"]{8,}	HIGH
password_assign	(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^\s'\"]{4,}	HIGH
token_assign	(?i)(token|secret|access[_-]?key)\s*[=:]\s*['\"][^\s'\"]{8,}	HIGH
connection_string	(?i)(mysql|postgres|mongodb|redis|amqp)://[^\s'\"]{10,}	CONFIRMED
internal_ip	https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[^\s'\"]+	POSSIBLE
internal_host	(?i)https?://[a-z0-9-]+\.(internal|local|corp|intranet|dev)[^\s'\"]*	POSSIBLE
s3_bucket	[a-z0-9.-]+\.s3\.amazonaws\.com	HIGH
html_comment_secret	<!--[\s\S]*?(password|key|token|secret|admin|config|debug)[\s\S]*?-->	POSSIBLE
todo_secret	(?i)(TODO|FIXME|HACK|XXX).*?(password|key|token|secret|cred)	POSSIBLE
SECRETS
    ok "Secret patterns: $(grep -c '^[^#]' "${TRAKTR_ROOT}/payloads/secrets/patterns.txt") rules"
  fi
}

# ── Step 9: Config Init ─────────────────────────────────────────────────────
init_config() {
  log "[*] Step 9: Config initialization"
  mkdir -p "$TRAKTR_HOME"
  if [ ! -f "${TRAKTR_HOME}/traktr.json" ] || $REPAIR; then
    cp "${TRAKTR_ROOT}/config/traktr.json" "${TRAKTR_HOME}/traktr.json"
    ok "Config copied to ${TRAKTR_HOME}/traktr.json"
  else
    ok "Config already exists"
  fi
}

# ── Step 10: Verify ─────────────────────────────────────────────────────────
verify_all() {
  log ""
  log "╔══════════════════════════════════════════════════════════╗"
  log "║               TRAKTR Tool Verification                  ║"
  log "╠═══════════════════╦═══════════════╦══════════════════════╣"
  log "║ Tool              ║ Status        ║ Version              ║"
  log "╠═══════════════════╬═══════════════╬══════════════════════╣"

  local tools=(katana ffuf nuclei httpx gau subfinder waybackurls dalfox arjun commix jq curl git)
  for t in "${tools[@]}"; do
    local ver="—" status="MISSING"
    if has_tool "$t"; then
      status="OK"
      ver=$(
        case "$t" in
          ffuf)     ffuf -V 2>&1 ;;
          httpx)    httpx -version 2>&1 || dpkg -s httpx-toolkit 2>&1 | grep Version ;;
          katana|nuclei|subfinder|dalfox) "$t" -version 2>&1 ;;
          arjun)    pip3 show arjun 2>&1 | grep -i version ;;
          commix)   commix --version 2>&1 ;;
          jq)       jq --version 2>&1 ;;
          curl)     curl --version 2>&1 | head -1 ;;
          git)      git --version 2>&1 ;;
          *)        echo "installed" ;;
        esac | grep -oP '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1
      ) || ver="?"
      [[ -z "$ver" ]] && ver="installed"
    fi
    printf "║ %-17s ║ %-13s ║ %-20s ║\n" "$t" "$status" "$ver" | tee -a "$LOG_FILE"
  done

  log "╠═══════════════════╩═══════════════╩══════════════════════╣"
  log "║  Payloads                                                ║"
  log "╠══════════════════════════════════════════════════════════╣"

  for repo in PayloadsAllTheThings SecLists fuzzdb; do
    local s="MISSING"
    [ -d "${TRAKTR_HOME}/payloads/${repo}/.git" ] && s="OK"
    printf "║ %-17s ║ %-36s ║\n" "$repo" "$s" | tee -a "$LOG_FILE"
  done

  log "╚══════════════════════════════════════════════════════════╝"
  log ""
  log "[*] Summary: $INSTALLED installed | $SKIPPED skipped | $FAILED failed"

  if [ "$FAILED" -gt 0 ]; then
    warn "Some tools failed. Run with --repair to retry."
    exit 1
  fi
  ok "Traktr is ready. Run: traktr <target>"
}

# ── Banner ───────────────────────────────────────────────────────────────────
banner() {
  cat << 'EOF'
  ___________              __    __
  \__    ___/___________  |  | _/  |________
    |    |  \_  __ \__  \ |  |/ \   __\_  __ \
    |    |   |  | \// __ \|    < |  |  |  | \/
    |____|   |__|  (____  |__|_ \|__|  |__|
                        \/     \/
        [ Intelligent Web Pentest Orchestrator ]
                   INSTALLER v1.0
EOF
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  banner
  log "[*] Traktr Installer started $(date '+%Y-%m-%d %H:%M:%S')"
  $DRY_RUN && log "[*] DRY-RUN MODE: No changes will be made"
  $REPAIR  && log "[*] REPAIR MODE: Reinstalling broken tools"
  $UPGRADE && log "[*] UPGRADE MODE: Updating all tools"
  log ""

  detect_os
  install_system_deps
  install_go
  install_go_tools
  install_pip_tools
  update_nuclei_templates
  clone_payloads
  organize_payloads
  build_wordlists
  init_config
  verify_all
}

main "$@"
