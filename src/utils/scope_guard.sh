#!/usr/bin/env bash
# TRAKTR Scope Enforcement & Ban Detection v2.0
# Prevents out-of-scope scanning, detects WAF blocks/rate limits
# Usage: source scope_guard.sh; init_scope <target> [scope_pattern]

# ── State ────────────────────────────────────────────────────────────────────
_SCOPE_DOMAIN=""
_SCOPE_PATTERNS=()
_CONSECUTIVE_FAILURES=0
_CURRENT_DELAY=0
_EVASION_LOG=""

# ═══════════════════════════════════════════════════════════════════════════
#  SCOPE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════
init_scope() {
  local target="$1" scope_arg="${2:-}"
  _EVASION_LOG="${OUTDIR:-/tmp}/evasion.log"

  # Extract base domain from target
  _SCOPE_DOMAIN=$(echo "$target" | sed 's|https\?://||; s|/.*||; s|:.*||')

  if [[ -n "$scope_arg" ]]; then
    if [[ -f "$scope_arg" ]]; then
      # Load scope patterns from file (one regex per line)
      while IFS= read -r pattern; do
        [[ -n "$pattern" ]] && [[ "$pattern" != \#* ]] && _SCOPE_PATTERNS+=("$pattern")
      done < "$scope_arg"
    else
      # Single regex pattern
      _SCOPE_PATTERNS+=("$scope_arg")
    fi
  else
    # Default: target domain + subdomains
    local escaped="${_SCOPE_DOMAIN//./\\.}"
    _SCOPE_PATTERNS+=("(^|\\.)${escaped}$")
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
#  SCOPE CHECKING
# ═══════════════════════════════════════════════════════════════════════════
check_scope() {
  local url="$1"
  local domain; domain=$(echo "$url" | sed 's|https\?://||; s|/.*||; s|:.*||')

  # Always allow target domain
  [[ "$domain" == "$_SCOPE_DOMAIN" ]] && return 0

  # Check against scope patterns
  for pattern in "${_SCOPE_PATTERNS[@]+"${_SCOPE_PATTERNS[@]}"}"; do
    if echo "$domain" | grep -qP "$pattern" 2>/dev/null; then
      return 0
    fi
  done

  # Out of scope
  echo "[SCOPE] BLOCKED: $url (domain $domain not in scope)" >> "$_EVASION_LOG" 2>/dev/null || true
  return 1
}

# Filter stdin URLs through scope check (for piping)
scope_filter() {
  while IFS= read -r url; do
    check_scope "$url" && echo "$url"
  done
}

# ═══════════════════════════════════════════════════════════════════════════
#  BAN / RATE-LIMIT DETECTION
# ═══════════════════════════════════════════════════════════════════════════
ban_detector() {
  local status_code="${1:-200}" response_headers="${2:-}" response_body="${3:-}"

  # ── 429 Too Many Requests ──
  if [[ "$status_code" == "429" ]]; then
    _throttle "429 rate limited"
    # Check Retry-After header
    local retry_after; retry_after=$(echo "$response_headers" | grep -oi 'retry-after:\s*[0-9]*' | grep -oP '[0-9]+' | head -1) || true
    if [[ -n "$retry_after" ]] && [[ "$retry_after" -gt 0 ]]; then
      echo "[BAN] 429 with Retry-After: ${retry_after}s" >> "$_EVASION_LOG" 2>/dev/null || true
      sleep "$retry_after"
    fi
    echo "throttle"
    return
  fi

  # ── 503 Service Unavailable ──
  if [[ "$status_code" == "503" ]]; then
    local retry_after; retry_after=$(echo "$response_headers" | grep -oi 'retry-after:\s*[0-9]*' | grep -oP '[0-9]+' | head -1) || true
    if [[ -n "$retry_after" ]]; then
      echo "[BAN] 503 with Retry-After: ${retry_after}s" >> "$_EVASION_LOG" 2>/dev/null || true
      sleep "$retry_after"
    else
      _throttle "503 service unavailable"
    fi
    echo "throttle"
    return
  fi

  # ── 403 + WAF signatures ──
  if [[ "$status_code" == "403" ]] || [[ "$status_code" == "406" ]]; then
    local is_waf=false
    # Cloudflare challenge
    echo "$response_body" | grep -qi 'cf-browser-verification\|Checking your browser\|cf-challenge' && is_waf=true || true
    # Generic WAF block
    echo "$response_body" | grep -qi 'Request blocked\|Access Denied\|Forbidden.*WAF\|ModSecurity\|Web Application Firewall' && is_waf=true || true
    # Imperva
    echo "$response_body" | grep -qi 'Incapsula\|_Incapsula_Resource' && is_waf=true || true

    if $is_waf; then
      echo "[BAN] WAF block detected (HTTP $status_code)" >> "$_EVASION_LOG" 2>/dev/null || true
      _throttle "WAF block ($status_code)"
      echo "throttle"
      return
    fi
  fi

  # ── CAPTCHA detection ──
  if echo "$response_body" | grep -qi 'recaptcha\|hcaptcha\|captcha.*challenge\|g-recaptcha\|h-captcha'; then
    echo "[BAN] CAPTCHA detected -- manual intervention may be needed" >> "$_EVASION_LOG" 2>/dev/null || true
    echo -e "\033[1;31m  [!!!] CAPTCHA detected! Pausing. Consider reducing rate.\033[0m" >&2
    echo "abort"
    return
  fi

  # ── Consecutive failure tracking ──
  if [[ "$status_code" -ge 400 ]] && [[ "$status_code" != "404" ]]; then
    ((_CONSECUTIVE_FAILURES++)) || true
    if [[ $_CONSECUTIVE_FAILURES -ge 10 ]]; then
      echo "[BAN] 10 consecutive non-200 responses, pausing 30s" >> "$_EVASION_LOG" 2>/dev/null || true
      echo -e "\033[1;33m  [!] 10 consecutive errors, pausing 30s...\033[0m" >&2
      sleep 30
      _CONSECUTIVE_FAILURES=0
      echo "skip"
      return
    fi
  else
    _CONSECUTIVE_FAILURES=0
  fi

  echo "continue"
}

# ── Auto-throttle helper ────────────────────────────────────────────────────
_throttle() {
  local reason="$1"
  # Double the delay, max 10s
  if [[ $_CURRENT_DELAY -eq 0 ]]; then
    _CURRENT_DELAY=1
  else
    _CURRENT_DELAY=$(( _CURRENT_DELAY * 2 ))
    [[ $_CURRENT_DELAY -gt 10 ]] && _CURRENT_DELAY=10
  fi
  echo "[THROTTLE] ${reason} -- delay now ${_CURRENT_DELAY}s" >> "$_EVASION_LOG" 2>/dev/null || true
  echo -e "\033[1;33m  [!] Throttled: ${reason} (delay: ${_CURRENT_DELAY}s)\033[0m" >&2
  sleep "$_CURRENT_DELAY"
}

# Reset throttle (call after successful requests)
reset_throttle() {
  _CONSECUTIVE_FAILURES=0
  _CURRENT_DELAY=0
}

# Check if redirect goes out of scope
check_redirect_scope() {
  local original_url="$1" redirect_url="$2"
  if [[ -n "$redirect_url" ]] && ! check_scope "$redirect_url"; then
    echo "[SCOPE] Redirect out of scope: $original_url -> $redirect_url" >> "$_EVASION_LOG" 2>/dev/null || true
    return 1
  fi
  return 0
}
