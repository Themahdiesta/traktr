#!/usr/bin/env bash
# TRAKTR - Burp Request Parser v2.0
# Parses raw HTTP request files (Burp Suite export) into reusable scan context
# Usage: source request_parser.sh; parse_burp_request /path/to/request.txt
# Note: No set -e here -- this is a sourced library, caller controls error handling

# ── Output variables (populated by parse_burp_request) ──────────────────────
BURP_TARGET=""
BURP_METHOD=""
BURP_PATH=""
BURP_HTTP_VER=""
BURP_HOST=""
BURP_BODY=""
BURP_BODY_TYPE="none"          # none|form|json|xml|multipart
BURP_AUTH_TYPE="none"          # none|cookie|bearer|basic|custom
export BURP_CURL_BASE=""
BURP_IS_API=false
BURP_CSRF_FIELD=""
BURP_CSRF_VALUE=""
declare -gA BURP_HEADERS=()
declare -gA BURP_COOKIES=()
declare -ga BURP_PARAMS=()       # All discovered param names (unified)
declare -ga BURP_QUERY_PARAMS=() # From URL query string only

# ── Main parser ─────────────────────────────────────────────────────────────
parse_burp_request() {
  local file="$1"
  [[ ! -f "$file" ]] && { echo "[-] Request file not found: $file"; return 1; }

  # Reset state
  BURP_HEADERS=(); BURP_COOKIES=(); BURP_PARAMS=(); BURP_QUERY_PARAMS=()
  BURP_BODY=""; BURP_BODY_TYPE="none"; BURP_AUTH_TYPE="none"
  BURP_IS_API=false; BURP_CSRF_FIELD=""; BURP_CSRF_VALUE=""

  local line_num=0 in_body=false body_lines=""

  # Normalize line endings (Burp on Windows uses \r\n)
  local clean_file; clean_file=$(mktemp)
  sed 's/\r$//' "$file" > "$clean_file"

  while IFS= read -r line || [[ -n "$line" ]]; do
    (( ++line_num ))

    # Line 1: Request line (METHOD PATH HTTP/x.x)
    if [[ $line_num -eq 1 ]]; then
      BURP_METHOD=$(echo "$line" | awk '{print $1}')
      local full_path; full_path=$(echo "$line" | awk '{print $2}')
      export BURP_HTTP_VER; BURP_HTTP_VER=$(echo "$line" | awk '{print $3}')
      # Split path and query string
      BURP_PATH="${full_path%%\?*}"
      if [[ "$full_path" == *"?"* ]]; then
        _parse_query_string "${full_path#*\?}"
      fi
      continue
    fi

    # Empty line = boundary between headers and body
    if [[ -z "$line" ]] && ! $in_body; then
      in_body=true
      continue
    fi

    # Body collection
    if $in_body; then
      [[ -n "$body_lines" ]] && body_lines+=$'\n'
      body_lines+="$line"
      continue
    fi

    # Header parsing (skip Burp-injected headers)
    if [[ "$line" == X-Burp-* ]] || [[ "$line" == Proxy-Connection:* ]]; then
      continue
    fi

    # Handle multiline headers (continuation line starts with space/tab)
    if [[ "$line" =~ ^[[:space:]] ]] && [[ ${#BURP_HEADERS[@]} -gt 0 ]]; then
      local _keys=("${!BURP_HEADERS[@]}")
      local last_key="${_keys[${#_keys[@]}-1]}"
      local _trimmed="${line#"${line%%[! ]*}"}"
      BURP_HEADERS["$last_key"]+=" ${_trimmed}"
      continue
    fi

    local h_name="${line%%:*}"
    local h_value="${line#*: }"
    # Normalize header name to lowercase for matching, store original
    local h_lower; h_lower=$(echo "$h_name" | tr '[:upper:]' '[:lower:]')
    BURP_HEADERS["$h_name"]="$h_value"

    # Special header handling
    case "$h_lower" in
      host)
        BURP_HOST="$h_value"
        ;;
      cookie)
        _parse_cookies "$h_value"
        BURP_AUTH_TYPE="cookie"
        ;;
      authorization)
        if [[ "$h_value" == Bearer* ]]; then
          BURP_AUTH_TYPE="bearer"
        elif [[ "$h_value" == Basic* ]]; then
          BURP_AUTH_TYPE="basic"
        else
          BURP_AUTH_TYPE="custom"
        fi
        ;;
      content-type)
        _detect_body_type "$h_value"
        ;;
    esac
  done < "$clean_file"
  rm -f "$clean_file"

  # Store body
  BURP_BODY="$body_lines"

  # Parse body params based on detected type
  if [[ -n "$BURP_BODY" ]]; then
    _parse_body_params
  fi

  # Reconstruct target URL
  local proto="https"
  # If port 80 or no indication of HTTPS, use http
  if [[ "$BURP_HOST" == *":80" ]] && [[ "$BURP_HOST" != *":8080" ]]; then
    proto="http"
  fi
  BURP_TARGET="${proto}://${BURP_HOST}${BURP_PATH}"

  # Detect API endpoint
  _detect_api

  # Detect CSRF tokens
  _detect_csrf

  # Decode JWT if present in cookies or auth header
  _detect_jwt

  # Build base curl command
  _build_curl_base

  # Deduplicate params
  _dedup_params

  echo "[+] Parsed: ${BURP_METHOD} ${BURP_TARGET}"
  echo "    Auth: ${BURP_AUTH_TYPE} | Body: ${BURP_BODY_TYPE} | API: ${BURP_IS_API}"
  echo "    Params found: ${#BURP_PARAMS[@]} | Cookies: ${#BURP_COOKIES[@]}"
}

# ── Query string parser ────────────────────────────────────────────────────
_parse_query_string() {
  local qs="$1"
  IFS='&' read -ra pairs <<< "$qs"
  for pair in "${pairs[@]}"; do
    local key="${pair%%=*}"
    [[ -n "$key" ]] && BURP_QUERY_PARAMS+=("$key") && BURP_PARAMS+=("$key")
  done
}

# ── Cookie parser ───────────────────────────────────────────────────────────
_parse_cookies() {
  local cookie_str="$1"
  IFS=';' read -ra cookies <<< "$cookie_str"
  for c in "${cookies[@]}"; do
    c="${c#"${c%%[! ]*}"}"
    local name="${c%%=*}"
    local value="${c#*=}"
    [[ -n "$name" ]] && BURP_COOKIES["$name"]="$value"
    # Cookies are testable params too
    BURP_PARAMS+=("cookie:${name}")
  done
}

# ── Body type detection ─────────────────────────────────────────────────────
_detect_body_type() {
  local ct="$1"
  case "$ct" in
    *json*)            BURP_BODY_TYPE="json" ;;
    *xml*)             BURP_BODY_TYPE="xml" ;;
    *form-urlencoded*) BURP_BODY_TYPE="form" ;;
    *multipart*)       BURP_BODY_TYPE="multipart" ;;
    *)                 BURP_BODY_TYPE="other" ;;
  esac
}

# ── Body parameter extraction ──────────────────────────────────────────────
_parse_body_params() {
  case "$BURP_BODY_TYPE" in
    form)
      # key=value&key2=value2
      IFS='&' read -ra pairs <<< "$BURP_BODY"
      for pair in "${pairs[@]}"; do
        local key="${pair%%=*}"
        [[ -n "$key" ]] && BURP_PARAMS+=("body:${key}")
      done
      ;;
    json)
      # Extract top-level keys using jq (if available) or regex fallback
      if command -v jq &>/dev/null; then
        while IFS= read -r key; do
          [[ -n "$key" ]] && BURP_PARAMS+=("json:${key}")
        done < <(echo "$BURP_BODY" | jq -r 'keys[]' 2>/dev/null || true)
        # Also extract nested keys for deeper param discovery
        while IFS= read -r key; do
          [[ -n "$key" ]] && BURP_PARAMS+=("json:${key}")
        done < <(echo "$BURP_BODY" | jq -r '[paths(scalars)] | .[] | .[-1] | select(type == "string")' 2>/dev/null | sort -u || true)
      else
        # Regex fallback: extract "key": patterns
        while IFS= read -r key; do
          [[ -n "$key" ]] && BURP_PARAMS+=("json:${key}")
        done < <(echo "$BURP_BODY" | grep -oP '"([^"]+)"\s*:' | sed 's/"//g; s/\s*://' || true)
      fi
      ;;
    xml)
      # Extract element and attribute names
      while IFS= read -r tag; do
        [[ -n "$tag" ]] && BURP_PARAMS+=("xml:${tag}")
      done < <(echo "$BURP_BODY" | grep -oP '<([a-zA-Z_][a-zA-Z0-9_:-]*)' | sed 's/<//; s/\?//' | sort -u || true)
      # Attributes
      while IFS= read -r attr; do
        [[ -n "$attr" ]] && BURP_PARAMS+=("xml_attr:${attr}")
      done < <(echo "$BURP_BODY" | grep -oP '[a-zA-Z_][a-zA-Z0-9_:-]*=' | sed 's/=//' | sort -u || true)
      ;;
    multipart)
      # Extract field names from Content-Disposition headers
      while IFS= read -r name; do
        [[ -n "$name" ]] && BURP_PARAMS+=("multipart:${name}")
      done < <(echo "$BURP_BODY" | grep -oP 'name="([^"]+)"' | sed 's/name="//; s/"//' || true)
      ;;
  esac
}

# ── API detection ──────────────────────────────────────────────────────────
_detect_api() {
  # Check multiple signals for API endpoint
  local signals=0
  [[ "$BURP_PATH" == */api/* ]] || [[ "$BURP_PATH" == */v[0-9]/* ]] && ((signals++)) || true
  [[ "$BURP_BODY_TYPE" == "json" ]] && ((signals++)) || true
  [[ "${BURP_HEADERS[Accept]:-}" == *json* ]] && ((signals++)) || true
  [[ "${BURP_HEADERS[Content-Type]:-}" == *json* ]] && ((signals++)) || true
  [[ "$BURP_METHOD" == "PUT" ]] || [[ "$BURP_METHOD" == "PATCH" ]] || [[ "$BURP_METHOD" == "DELETE" ]] && ((signals++)) || true
  [[ $signals -ge 2 ]] && BURP_IS_API=true || true
}

# ── CSRF token detection ──────────────────────────────────────────────────
_detect_csrf() {
  local csrf_names=("csrf" "csrftoken" "csrf_token" "csrfmiddlewaretoken" "_token"
                    "authenticity_token" "antiforgery" "__RequestVerificationToken"
                    "nonce" "csrf-token" "x-csrf-token" "xsrf-token")
  # Check body params
  for param in "${BURP_PARAMS[@]}"; do
    local pname="${param#*:}"
    local pname_lower; pname_lower=$(echo "$pname" | tr '[:upper:]' '[:lower:]')
    for csrf in "${csrf_names[@]}"; do
      if [[ "$pname_lower" == "$csrf" ]]; then
        BURP_CSRF_FIELD="$pname"
        # Extract value from body
        case "$BURP_BODY_TYPE" in
          form) BURP_CSRF_VALUE=$(echo "$BURP_BODY" | tr '&' '\n' | grep "^${pname}=" | head -1 | cut -d= -f2-) ;;
          json) BURP_CSRF_VALUE=$(echo "$BURP_BODY" | jq -r ".\"${pname}\" // empty" 2>/dev/null) ;;
        esac
        echo "    CSRF detected: ${BURP_CSRF_FIELD}=${BURP_CSRF_VALUE:0:20}..."
        return
      fi
    done
  done
  # Check headers
  for hdr in "${!BURP_HEADERS[@]}"; do
    local hdr_lower; hdr_lower=$(echo "$hdr" | tr '[:upper:]' '[:lower:]')
    for csrf in "${csrf_names[@]}"; do
      if [[ "$hdr_lower" == "$csrf" ]] || [[ "$hdr_lower" == "x-$csrf" ]]; then
        BURP_CSRF_FIELD="header:${hdr}"
        BURP_CSRF_VALUE="${BURP_HEADERS[$hdr]}"
        echo "    CSRF header detected: ${hdr}"
        return
      fi
    done
  done
}

# ── JWT detection & decode ─────────────────────────────────────────────────
_detect_jwt() {
  local jwt_pattern='eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
  # Check cookies
  for cname in "${!BURP_COOKIES[@]}"; do
    local cval="${BURP_COOKIES[$cname]}"
    if [[ "$cval" =~ $jwt_pattern ]]; then
      local jwt="${BASH_REMATCH[0]}"
      echo "    JWT found in cookie: $cname"
      _decode_jwt_payload "$jwt"
      return
    fi
  done
  # Check Authorization header
  local auth="${BURP_HEADERS[Authorization]:-}"
  if [[ "$auth" =~ $jwt_pattern ]]; then
    local jwt="${BASH_REMATCH[0]}"
    echo "    JWT found in Authorization header"
    _decode_jwt_payload "$jwt"
  fi
}

_decode_jwt_payload() {
  local jwt="$1"
  local payload; payload=$(echo "$jwt" | cut -d. -f2)
  # Add padding
  local pad=$((4 - ${#payload} % 4))
  [[ $pad -ne 4 ]] && payload+=$(printf '=%.0s' $(seq 1 $pad))
  # Replace URL-safe chars
  payload=$(echo "$payload" | tr '_-' '/+')
  local decoded; decoded=$(echo "$payload" | base64 -d 2>/dev/null) || return
  if command -v jq &>/dev/null; then
    local exp; exp=$(echo "$decoded" | jq -r '.exp // empty' 2>/dev/null)
    if [[ -n "$exp" ]]; then
      local now; now=$(date +%s)
      if [[ "$exp" -lt "$now" ]]; then
        echo "    [!] JWT EXPIRED (exp: $(date -d @"$exp" 2>/dev/null || date -r "$exp" 2>/dev/null || echo "$exp"))"
      else
        echo "    JWT valid until: $(date -d @"$exp" 2>/dev/null || date -r "$exp" 2>/dev/null || echo "$exp")"
      fi
    fi
    local sub; sub=$(echo "$decoded" | jq -r '.sub // .user // .username // empty' 2>/dev/null)
    [[ -n "$sub" ]] && echo "    JWT subject: $sub" || true
  fi
}

# ── Build base curl command ────────────────────────────────────────────────
_build_curl_base() {
  local cmd="curl -sk -X ${BURP_METHOD}"
  # Add headers (skip Host, it's implied by URL)
  for hdr in "${!BURP_HEADERS[@]}"; do
    [[ "$hdr" == "Host" ]] && continue
    [[ "$hdr" == "Content-Length" ]] && continue
    cmd+=" -H '${hdr}: ${BURP_HEADERS[$hdr]}'"
  done
  # Add body if present
  if [[ -n "$BURP_BODY" ]]; then
    # Escape single quotes in body
    local escaped_body="${BURP_BODY//\'/\'\\\'\'}"
    cmd+=" -d '${escaped_body}'"
  fi
  # Append URL with query string
  if [[ ${#BURP_QUERY_PARAMS[@]} -gt 0 ]]; then
    # Rebuild query string from parsed params
    local qs_parts=()
    for qp in "${BURP_QUERY_PARAMS[@]}"; do
      qs_parts+=("${qp}=FUZZ")
    done
    local qs; qs=$(IFS='&'; echo "${qs_parts[*]}")
    cmd+=" '${BURP_TARGET}?${qs}'"
  else
    cmd+=" '${BURP_TARGET}'"
  fi
  BURP_CURL_BASE="$cmd"
}

# ── Deduplicate params ─────────────────────────────────────────────────────
_dedup_params() {
  if [[ ${#BURP_PARAMS[@]} -eq 0 ]]; then return; fi
  local -A seen=()
  local unique=()
  for p in "${BURP_PARAMS[@]}"; do
    local key; key=$(echo "$p" | tr '[:upper:]' '[:lower:]')
    if [[ -z "${seen[$key]:-}" ]]; then
      seen["$key"]=1
      unique+=("$p")
    fi
  done
  BURP_PARAMS=("${unique[@]}")
}

# ── Multi-request directory mode ───────────────────────────────────────────
parse_burp_directory() {
  local dir="$1"
  [[ ! -d "$dir" ]] && { echo "[-] Directory not found: $dir"; return 1; }
  local count=0
  echo "[*] Parsing request files from: $dir"
  for f in "$dir"/*.txt "$dir"/*.req "$dir"/*.http; do
    [[ ! -f "$f" ]] && continue
    echo "--- Parsing: $(basename "$f") ---"
    parse_burp_request "$f"
    ((count++))
  done
  echo "[+] Parsed $count request files"
}

# ── Export params to file (for integration with traktr.sh) ─────────────────
export_params_to_file() {
  local outfile="$1"
  for p in "${BURP_PARAMS[@]}"; do
    local source="${p%%:*}"
    local name="${p#*:}"
    local method="$BURP_METHOD"
    [[ "$source" == "cookie" ]] && method="COOKIE"
    echo "${BURP_TARGET}|${name}|${source}|${method}|burp_import"
  done | sort -u > "$outfile"
  echo "[+] Exported ${#BURP_PARAMS[@]} params to $outfile"
}
