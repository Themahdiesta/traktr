#!/usr/bin/env bash
# ╔════════════════════════════════════════════════════════════════════╗
# ║  TRAKTR v1.0 -- Intelligent Web Pentest Orchestrator             ║
# ║  Usage: traktr <target> [flags]  |  traktr -r request.txt        ║
# ╚════════════════════════════════════════════════════════════════════╝
set -euo pipefail

TRAKTR_VERSION="1.0.0"
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
for _mod in lfi_engine param_miner secret_scanner; do
  [[ -f "${TRAKTR_ROOT}/src/intel/${_mod}.sh" ]] && source "${TRAKTR_ROOT}/src/intel/${_mod}.sh" 2>/dev/null || true
done
for _mod in scope_guard helpers reporter; do
  [[ -f "${TRAKTR_ROOT}/src/utils/${_mod}.sh" ]] && source "${TRAKTR_ROOT}/src/utils/${_mod}.sh" 2>/dev/null || true
done
[[ -f "${TRAKTR_ROOT}/src/core/plugin_loader.sh" ]] && source "${TRAKTR_ROOT}/src/core/plugin_loader.sh" 2>/dev/null || true

# ── Minimal helpers (until helpers.sh is built in Phase 3) ───────────────────
_log()  { [[ "$QUIET" == true ]] && return; echo "[$(date '+%H:%M:%S')] $1" | tee -a "${LOGFILE:-/dev/null}"; }
_ok()   { _log "  [+] $1"; }
_warn() { _log "  [!] $1"; }
_fail() { _log "  [-] $1"; }
_debug(){ [[ "$DEBUG" == true ]] && _log "  [DBG] $1" || true; }
_die()  { _fail "$1"; exit 1; }

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
  curl "${args[@]}" "$@" "$url" 2>/dev/null
}

# ── Banner ──────────────────────────────────────────────────────────────────
_banner() {
  [[ "$QUIET" == true ]] && return
  cat << 'EOF'
  ___________              __    __
  \__    ___/___________  |  | _/  |________
    |    |  \_  __ \__  \ |  |/ \   __\_  __ \
    |    |   |  | \// __ \|    < |  |  |  | \/
    |____|   |__|  (____  |__|_ \|__|  |__|
                        \/     \/
      Intelligent Web Pentest Orchestrator v1.0
EOF
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
      --dry-run)       DRY_RUN=true; shift ;;
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

  # Normalize target (ensure scheme)
  [[ "$TARGET" != http://* ]] && [[ "$TARGET" != https://* ]] && TARGET="https://${TARGET}"
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

  # Trap signals for clean shutdown
  trap '_warn "Interrupted! Saving state..."; _save_state "interrupted"; exit 130' INT TERM

  _save_state "init"
  _json_event "scan_start" "{\"target\":\"$TARGET\",\"threads\":$THREADS}"
  _ok "Output: $OUTDIR"
}

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 1: RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════════
step1_recon() {
  _log "[*] STEP 1: Reconnaissance"

  # WAF + tech detection in parallel
  _detect_waf &
  local waf_pid=$!
  _detect_tech_stack &
  local tech_pid=$!
  wait "$waf_pid" "$tech_pid" 2>/dev/null || true

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
    _debug "Launching katana"
    (
      katana -u "$TARGET" -jc -d "$CRAWL_DEPTH" -js-crawl -known-files all \
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

  # ── GAU (historical URLs) ──
  if command -v gau &>/dev/null; then
    _debug "Launching gau"
    (
      gau --threads 5 "$domain" > "${OUTDIR}/crawl/gau.txt" 2>/dev/null || true
    ) &
    pids+=($!)
  fi

  # ── Waybackurls ──
  if command -v waybackurls &>/dev/null; then
    _debug "Launching waybackurls"
    (
      echo "$domain" | waybackurls > "${OUTDIR}/crawl/wayback.txt" 2>/dev/null || true
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
    _debug "Launching ffuf directory scan"
    local ffuf_rate_flag=()
    [[ "$RATE_LIMIT" -gt 0 ]] && ffuf_rate_flag+=(-rate "$RATE_LIMIT")
    (
      # -ac = auto-calibrate: filters out catch-all responses (try_files fallbacks)
      ffuf -u "${TARGET}/FUZZ" -w "$wordlist" \
        -mc 200,201,301,302,307,401,403,500 -ac \
        -t 10 -s "${ffuf_rate_flag[@]+"${ffuf_rate_flag[@]}"}" \
        "${ffuf_hdrs[@]+"${ffuf_hdrs[@]}"}" 2>/dev/null | \
        while IFS= read -r word; do
          [[ -n "$word" ]] && echo "${TARGET}/${word}"
        done > "${OUTDIR}/crawl/ffuf_dirs.txt" || true
    ) &
    pids+=($!)
  fi

  # Wait for all crawlers
  _log "  Waiting for ${#pids[@]} crawlers..."
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done

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
  _log "[*] STEP 3: Endpoint Probing"
  local endpoints="${OUTDIR}/all_endpoints.txt"
  [[ ! -s "$endpoints" ]] && { _warn "No endpoints to probe"; return; }

  # Use PD httpx if available
  local httpx_bin=""
  [[ -f "${HOME}/go/bin/httpx" ]] && httpx_bin="${HOME}/go/bin/httpx"
  [[ -z "$httpx_bin" ]] && command -v httpx &>/dev/null && httpx_bin="httpx"

  if [[ -n "$httpx_bin" ]] && "$httpx_bin" -version 2>&1 | grep -qi 'projectdiscovery\|current' 2>/dev/null; then
    _debug "Probing with httpx (PD)"
    "$httpx_bin" -silent -status-code -title -content-length -tech-detect \
      -json -threads "$THREADS" -follow-redirects -timeout "$REQ_TIMEOUT" \
      < "$endpoints" > "${OUTDIR}/probed.json" 2>/dev/null || true
  else
    # Fallback: curl-based probing
    _log "  PD httpx not available, using curl probe"
    > "${OUTDIR}/probed.json"
    while IFS= read -r url; do
      local result
      result=$(_curl "$url" -o /dev/null -w '{"url":"%{url_effective}","status_code":%{http_code},"content_length":%{size_download},"time_total":%{time_total}}' 2>/dev/null) || continue
      echo "$result" >> "${OUTDIR}/probed.json"
    done < <(head -500 "$endpoints")
  fi

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
  _log "[*] STEP 4: Deep Parameter Discovery"
  local probed="${OUTDIR}/probed_urls.txt"
  [[ ! -s "$probed" ]] && { _warn "No live endpoints for param discovery"; return; }

  # Use Phase 3 mine_params() if available
  if declare -f mine_params &>/dev/null; then
    mine_params "${OUTDIR}/probed_urls.txt" "$OUTDIR" 2>/dev/null || true
    local total; total=$(wc -l < "${OUTDIR}/active_params.txt" 2>/dev/null || echo 0)
    _ok "Parameters discovered: $total (see ${OUTDIR}/active_params.txt)"
    _save_state "params"
    return
  fi

  # Fallback: inline implementation

  local pids=()

  # ── SOURCE 1: Arjun ──
  if command -v arjun &>/dev/null; then
    _debug "Launching arjun"
    (
      > "${OUTDIR}/params_arjun.txt"
      head -50 "$probed" | while IFS= read -r url; do
        local result; result=$(arjun -u "$url" -t 10 --stable 2>/dev/null) || continue
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
    > "${OUTDIR}/params_html.txt"
    while IFS= read -r url; do
      local body; body=$(_curl "$url" 2>/dev/null) || continue

      # All <input name="..."> (including hidden)
      echo "$body" | grep -oiP '<input\b[^>]*\bname\s*=\s*["\x27]([^"\x27]+)["\x27]' | \
        grep -oiP 'name\s*=\s*["\x27]\K[^"\x27]+' | while IFS= read -r p; do
          echo "${url}|${p}|html_input|GET|extracted"
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
    done < <(head -100 "$probed") > "${OUTDIR}/params_html.txt" 2>/dev/null || true
  ) &
  pids+=($!)

  # ── SOURCE 3: JS static analysis ──
  (
    _debug "Analyzing JavaScript files for params + API endpoints"
    > "${OUTDIR}/params_js.txt"
    # Collect JS URLs
    grep -hiE '\.js(\?|$|#)' "${OUTDIR}/all_endpoints.txt" 2>/dev/null | \
      grep -v '\.json' | sort -u | head -100 | \
    while IFS= read -r js_url; do
      local js; js=$(_curl "$js_url" 2>/dev/null) || continue

      # Save JS for secret scanning later
      local safe_name; safe_name=$(echo "$js_url" | md5sum | cut -c1-16)
      echo "$js" > "${OUTDIR}/responses/js_${safe_name}.txt"

      # fetch/axios/XHR URL patterns → extract API endpoints + params
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

  # Wait for all param sources
  _log "  Waiting for ${#pids[@]} param discovery sources..."
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done

  # ── MERGE + DEDUPE ──
  _log "  Merging parameters..."
  cat "${OUTDIR}"/params_*.txt 2>/dev/null | \
    sort -t'|' -k1,2 -u > "${OUTDIR}/active_params.txt" 2>/dev/null || true

  # Tag LFI candidate params (file/path operation names)
  local lfi_keywords='file\|path\|page\|include\|template\|doc\|folder\|view\|load\|read\|dir\|resource\|filename\|download\|src\|conf\|log\|url\|action\|cat\|type\|content\|prefix\|require\|pg\|document\|root\|data'
  grep -i "$lfi_keywords" "${OUTDIR}/active_params.txt" 2>/dev/null | \
    sort -u > "${OUTDIR}/lfi_candidates.txt" 2>/dev/null || true

  # Tag open redirect candidate params
  local redir_keywords='redirect\|redir\|next\|return\|goto\|url\|callback\|continue\|dest\|destination\|target\|rurl\|forward\|out\|link\|jump'
  grep -i "$redir_keywords" "${OUTDIR}/active_params.txt" 2>/dev/null | \
    sort -u > "${OUTDIR}/redirect_candidates.txt" 2>/dev/null || true

  local total; total=$(wc -l < "${OUTDIR}/active_params.txt" 2>/dev/null || echo 0)
  local lfi_c; lfi_c=$(wc -l < "${OUTDIR}/lfi_candidates.txt" 2>/dev/null || echo 0)
  local redir_c; redir_c=$(wc -l < "${OUTDIR}/redirect_candidates.txt" 2>/dev/null || echo 0)

  _ok "Params: $total total | $lfi_c LFI-candidates | $redir_c redirect-candidates"

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
  > "$secrets_file"

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
      matches=$(grep -oP "$pattern" "$resp_file" 2>/dev/null | head -5) || continue
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
  _log "[*] STEP 5: Vulnerability Testing (threads: $THREADS)"
  local probed="${OUTDIR}/probed_urls.txt"
  [[ ! -s "$probed" ]] && { _warn "No probed URLs for vuln testing"; return; }

  mkdir -p "${OUTDIR}/vuln"
  local pids=()

  # ── NUCLEI ──
  if command -v nuclei &>/dev/null && [[ "$SKIP_NUCLEI" != true ]]; then
    _debug "Launching nuclei"
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
    _debug "Launching LFI testing ($(wc -l < "${OUTDIR}/lfi_candidates.txt") candidates)"
    (
      if declare -f detect_lfi &>/dev/null; then
        # Phase 3 engine (when built)
        while IFS='|' read -r url param source method _; do
          detect_lfi "$url" "$param" "$method" 2>/dev/null
        done < "${OUTDIR}/lfi_candidates.txt" > "${OUTDIR}/vuln/lfi.json" || true
      else
        _lfi_basic_test > "${OUTDIR}/vuln/lfi.json"
      fi
    ) &
    pids+=($!)
  fi

  # ── XSS (dalfox) ──
  if command -v dalfox &>/dev/null && [[ -s "${OUTDIR}/active_params.txt" ]]; then
    _debug "Launching dalfox XSS scan"
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
    _debug "Launching commix"
    local clevel=3
    [[ "$OSCP" == true ]] && clevel=1
    (
      while IFS='|' read -r url param source method _; do
        [[ -z "$url" ]] || [[ -z "$param" ]] && continue
        # Build proper test URL (strip existing query params from base)
        local base_url="${url%%\?*}"
        local tgt="${base_url}?${param}=test"
        timeout 30 commix --batch --level "$clevel" -u "$tgt" \
          --output-dir="${OUTDIR}/vuln/commix_out" </dev/null 2>/dev/null || true
      done < <(head -20 "${OUTDIR}/active_params.txt")
    ) &
    pids+=($!)
  fi

  # ── Open Redirect ──
  if [[ -s "${OUTDIR}/redirect_candidates.txt" ]]; then
    _debug "Testing open redirects"
    (
      > "${OUTDIR}/vuln/redirects.json"
      local payloads=("https://evil.com" "//evil.com" "/\\\\evil.com" "//evil%00.com" "https:evil.com")
      while IFS='|' read -r url param _ method _; do
        [[ -z "$url" ]] || [[ -z "$param" ]] && continue
        for payload in "${payloads[@]}"; do
          local encoded; encoded=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
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

  # Wait for all scanners
  _log "  Waiting for ${#pids[@]} vuln scanners..."
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done

  # ── MERGE FINDINGS ──
  _merge_findings
  _save_state "vulntest"
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
      local encoded; encoded=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$payload',safe=''))" 2>/dev/null || echo "$payload")
      local test_url="${url}?${param}=${encoded}"
      local tmpfile; tmpfile=$(mktemp)
      local resp_code
      resp_code=$(_curl "$test_url" -o "$tmpfile" -w '%{http_code}|%{size_download}' 2>/dev/null) || { rm -f "$tmpfile"; continue; }
      local status="${resp_code%%|*}"
      local size="${resp_code##*|}"

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
        [[ $signals -ge 2 ]] && conf="HIGH"
        [[ $signals -eq 1 ]] && conf="MEDIUM"
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
  echo ""
  echo "================================================================"
  echo "  TRAKTR SCAN COMPLETE"
  echo "================================================================"
  echo "  Target:     $TARGET"
  echo "  Duration:   ${duration}s | Requests: ${REQUEST_COUNT}"
  echo "  Endpoints:  ${total_endpoints}"
  echo "  Parameters: ${total_params}"
  echo ""
  if [[ "$total_findings" -gt 0 ]]; then
    local high; high=$(jq '[.[] | select(.confidence == "HIGH")] | length' "$findings" 2>/dev/null || echo 0)
    local med; med=$(jq '[.[] | select(.confidence == "MEDIUM")] | length' "$findings" 2>/dev/null || echo 0)
    local low; low=$(jq '[.[] | select(.confidence == "LOW")] | length' "$findings" 2>/dev/null || echo 0)
    echo "  Findings:   $total_findings (HIGH:$high MED:$med LOW:$low)"
  else
    echo "  Findings:   0"
  fi
  echo "  Secrets:    ${total_secrets}"
  echo "  WAF:        ${WAF_DETECTED} | Framework: ${FRAMEWORK}"
  echo "----------------------------------------------------------------"
  echo "  Report:     ${OUTDIR}/REPORT.md"
  [[ -f "${OUTDIR}/REPORT.html" ]] && echo "  HTML:       ${OUTDIR}/REPORT.html" || true
  echo "  Findings:   ${OUTDIR}/findings.json"
  echo "  PoC cmds:   ${OUTDIR}/poc_commands.txt"
  echo "  Secrets:    ${OUTDIR}/secrets.json"
  echo "  Params:     ${OUTDIR}/active_params.txt"
  echo "  Full log:   ${LOGFILE}"
  echo "================================================================"

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
  step6_report
}

main "$@"
