#!/usr/bin/env bash
# TRAKTR Common Utilities v1.0
# Logging, encoding, retry, User-Agent rotation, state management
# Usage: source helpers.sh (sourced by traktr.sh)

# ── Color codes ──────────────────────────────────────────────────────────────
_CLR_RED='\033[1;31m'
_CLR_YEL='\033[1;33m'
_CLR_GRN='\033[1;32m'
_CLR_BLU='\033[1;34m'
_CLR_CYN='\033[1;36m'
_CLR_RST='\033[0m'

# ═══════════════════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════════════════
log() {
  local level="${1:-INFO}" msg="${2:-}"
  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
  local logline="[${ts}] [${level}] ${msg}"

  # Write to log file
  echo "$logline" >> "${LOGFILE:-/dev/null}" 2>/dev/null || true

  # Terminal output (respect QUIET)
  [[ "${QUIET:-false}" == true ]] && [[ "$level" != "CRITICAL" ]] && return || true

  case "$level" in
    OK|SUCCESS) echo -e "${_CLR_GRN}  [+] ${msg}${_CLR_RST}" ;;
    WARN)       echo -e "${_CLR_YEL}  [!] ${msg}${_CLR_RST}" ;;
    ERROR|FAIL) echo -e "${_CLR_RED}  [-] ${msg}${_CLR_RST}" ;;
    CRITICAL)   echo -e "${_CLR_RED}  [!!!] ${msg}${_CLR_RST}" ;;
    DEBUG)      [[ "${DEBUG:-false}" == true ]] && echo -e "${_CLR_CYN}  [DBG] ${msg}${_CLR_RST}" || true ;;
    INFO|*)     echo "[$(date '+%H:%M:%S')] ${msg}" ;;
  esac
}

# OSCP-compliant request logger (every request with timestamp)
log_request() {
  local method="$1" url="$2" status="${3:-}" extra="${4:-}"
  [[ "${OSCP:-false}" != true ]] && return || true
  echo "$(date '+%Y-%m-%d %H:%M:%S') | ${method} | ${url} | ${status} | ${extra}" >> "${OUTDIR:-/tmp}/requests.log"
}

color_print() {
  local color="$1" msg="$2"
  case "$color" in
    red)    echo -e "${_CLR_RED}${msg}${_CLR_RST}" ;;
    yellow) echo -e "${_CLR_YEL}${msg}${_CLR_RST}" ;;
    green)  echo -e "${_CLR_GRN}${msg}${_CLR_RST}" ;;
    blue)   echo -e "${_CLR_BLU}${msg}${_CLR_RST}" ;;
    cyan)   echo -e "${_CLR_CYN}${msg}${_CLR_RST}" ;;
    *)      echo "$msg" ;;
  esac
}

# ═══════════════════════════════════════════════════════════════════════════
#  TOOL CHECK
# ═══════════════════════════════════════════════════════════════════════════
check_tool() {
  local name="$1"
  if command -v "$name" &>/dev/null; then
    local ver
    ver=$("$name" --version 2>&1 | grep -oP '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1) || ver="?"
    echo "$ver"
    return 0
  fi
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════
#  RETRY WITH EXPONENTIAL BACKOFF
# ═══════════════════════════════════════════════════════════════════════════
retry() {
  local max="${1:-3}" delay="${2:-2}"
  shift 2
  local attempt=1
  while [[ $attempt -le $max ]]; do
    if "$@" 2>/dev/null; then
      return 0
    fi
    log "WARN" "Attempt $attempt/$max failed: $*"
    sleep "$delay"
    delay=$(( delay * 2 ))
    ((attempt++)) || true
  done
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════
#  ENCODING UTILITIES
# ═══════════════════════════════════════════════════════════════════════════
url_encode() {
  local string="$1"
  python3 -c "import urllib.parse; print(urllib.parse.quote('$string', safe=''))" 2>/dev/null || \
    printf '%s' "$string" | while IFS= read -r -n1 char; do
      case "$char" in
        [a-zA-Z0-9.~_-]) printf '%s' "$char" ;;
        *) printf '%%%02X' "'$char" ;;
      esac
    done
}

url_decode() {
  local string="$1"
  python3 -c "import urllib.parse; print(urllib.parse.unquote('$string'))" 2>/dev/null || \
    printf '%b' "${string//%/\\x}"
}

normalize_url() {
  local url="$1"
  # Lowercase scheme and host
  local scheme; scheme=$(echo "$url" | grep -oP '^https?' | tr '[:upper:]' '[:lower:]')
  local rest; rest=$(echo "$url" | sed 's|^https\?://||')
  local host; host=$(echo "$rest" | cut -d/ -f1 | tr '[:upper:]' '[:lower:]')
  local path; path=$(echo "$rest" | sed 's|^[^/]*||')
  # Strip fragment
  path="${path%%#*}"
  # Sort query params
  if [[ "$path" == *"?"* ]]; then
    local base_path="${path%%\?*}"
    local query="${path#*\?}"
    local sorted_query; sorted_query=$(echo "$query" | tr '&' '\n' | sort | tr '\n' '&' | sed 's/&$//')
    path="${base_path}?${sorted_query}"
  fi
  echo "${scheme}://${host}${path}"
}

# ═══════════════════════════════════════════════════════════════════════════
#  USER-AGENT ROTATION
# ═══════════════════════════════════════════════════════════════════════════
_UA_LIST=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.144"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"
  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
  "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
)

random_ua() {
  echo "${_UA_LIST[$((RANDOM % ${#_UA_LIST[@]}))]}"
}

# ═══════════════════════════════════════════════════════════════════════════
#  STATE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════
save_state() {
  local step="$1" extra="${2:-{}}"
  local state_file="${OUTDIR:-/tmp}/.traktr_state.json"
  cat > "$state_file" << STEOF
{
  "step": "${step}",
  "target": "${TARGET:-}",
  "outdir": "${OUTDIR:-}",
  "timestamp": $(date +%s),
  "framework": "${FRAMEWORK:-generic}",
  "waf": "${WAF_DETECTED:-none}",
  "extra": ${extra}
}
STEOF
}

load_state() {
  local file="$1"
  [[ ! -f "$file" ]] && return 1
  # Return step name for the caller to use
  jq -r '.step' "$file" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════════════════
#  TEMP FILE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════
_TRAKTR_TMPFILES=()

temp_file() {
  local prefix="${1:-traktr}"
  local tmpf; tmpf=$(mktemp "${OUTDIR:-/tmp}/${prefix}_XXXXX")
  _TRAKTR_TMPFILES+=("$tmpf")
  echo "$tmpf"
}

cleanup_temp() {
  for f in "${_TRAKTR_TMPFILES[@]+"${_TRAKTR_TMPFILES[@]}"}"; do
    rm -f "$f" 2>/dev/null
  done
  _TRAKTR_TMPFILES=()
}

# Register cleanup on exit
trap cleanup_temp EXIT 2>/dev/null || true
