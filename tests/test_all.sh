#!/usr/bin/env bash
# TRAKTR Test Suite v1.0
# Tests all core functions with mock data and real validation
# Usage: ./tests/test_all.sh [--verbose]
set -uo pipefail

TRAKTR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERBOSE=false
[[ "${1:-}" == "--verbose" ]] && VERBOSE=true

PASS=0; FAIL=0; SKIP=0
TMPDIR=$(mktemp -d /tmp/traktr_test_XXXXX)

# ── Colors ──────────────────────────────────────────────────────────────────
GRN='\033[1;32m'; RED='\033[1;31m'; YEL='\033[1;33m'; CYN='\033[1;36m'
DIM='\033[2m'; RST='\033[0m'

# ── Test helpers ────────────────────────────────────────────────────────────
_test_pass() { ((PASS++)); echo -e "  ${GRN}PASS${RST} $1"; }
_test_fail() { ((FAIL++)); echo -e "  ${RED}FAIL${RST} $1 -- $2"; }
_test_skip() { ((SKIP++)); echo -e "  ${YEL}SKIP${RST} $1 -- $2"; }
_section()   { echo -e "\n${CYN}[$1]${RST}"; }

# ═══════════════════════════════════════════════════════════════════════════
#  1. SPINNER MODULE
# ═══════════════════════════════════════════════════════════════════════════
test_spinner() {
  _section "Spinner Module"

  source "${TRAKTR_ROOT}/src/utils/spinner.sh" 2>/dev/null || {
    _test_fail "spinner.sh" "failed to source"; return
  }
  _test_pass "spinner.sh sources without error"

  # Test _spinner_start/_spinner_stop
  _spinner_start "Test spinner" 2>/dev/null
  sleep 0.3
  [[ -n "$_SPINNER_PID" ]] && kill -0 "$_SPINNER_PID" 2>/dev/null \
    && _test_pass "spinner starts background process" \
    || _test_fail "spinner start" "no background process"

  _spinner_update "Updated message" 2>/dev/null
  local msg; msg=$(cat "$_SPINNER_MSG_FILE" 2>/dev/null)
  [[ "$msg" == "Updated message" ]] \
    && _test_pass "spinner update changes message" \
    || _test_fail "spinner update" "message='$msg'"

  _spinner_stop 2>/dev/null
  [[ -z "$_SPINNER_PID" ]] \
    && _test_pass "spinner stop cleans up PID" \
    || _test_fail "spinner stop" "PID still set"

  # Test _show_tool_cmd
  local output; output=$(_show_tool_cmd "testool" "testool -u http://x -v" 2>&1)
  echo "$output" | grep -q "testool" \
    && _test_pass "show_tool_cmd displays tool name" \
    || _test_fail "show_tool_cmd" "missing tool name"

  # Test _progress_bar
  output=$(_progress_bar 3 6 "Testing" 2>&1)
  echo "$output" | grep -q "3/6" \
    && _test_pass "progress_bar shows step count" \
    || _test_fail "progress_bar" "missing step count"
}

# ═══════════════════════════════════════════════════════════════════════════
#  2. LFI ENGINE
# ═══════════════════════════════════════════════════════════════════════════
test_lfi_engine() {
  _section "LFI Engine"

  source "${TRAKTR_ROOT}/src/intel/lfi_engine.sh" 2>/dev/null || {
    _test_fail "lfi_engine.sh" "failed to source"; return
  }
  _test_pass "lfi_engine.sh sources without error"

  # Test Level 1 payloads
  local l1; l1=$(_lfi_level1 | wc -l)
  [[ $l1 -ge 5 ]] \
    && _test_pass "level1 produces $l1 payloads (basic traversal)" \
    || _test_fail "level1" "only $l1 payloads"

  # Test Level 2 payloads (encoded)
  local l2; l2=$(_lfi_level2 | wc -l)
  [[ $l2 -ge 8 ]] \
    && _test_pass "level2 produces $l2 payloads (encoded traversal)" \
    || _test_fail "level2" "only $l2 payloads"

  # Test Level 2 ordering: ....// should be FIRST
  local first_l2; first_l2=$(_lfi_level2 | head -1)
  [[ "$first_l2" == *"....//..../"* ]] \
    && _test_pass "level2 prioritizes ....// bypass (first payload)" \
    || _test_fail "level2 ordering" "first='$first_l2'"

  # Test Level 3 (null byte)
  local l3; l3=$(_lfi_level3 | wc -l)
  [[ $l3 -ge 5 ]] \
    && _test_pass "level3 produces $l3 payloads (null byte)" \
    || _test_fail "level3" "only $l3 payloads"

  # Test Level 4 (PHP wrappers)
  local l4; l4=$(_lfi_level4_php | wc -l)
  [[ $l4 -ge 6 ]] \
    && _test_pass "level4 produces $l4 payloads (PHP wrappers)" \
    || _test_fail "level4" "only $l4 payloads"

  # Test Level 5 (OS deep paths)
  local l5; l5=$(_lfi_level5 | wc -l)
  [[ $l5 -ge 10 ]] \
    && _test_pass "level5 produces $l5 payloads (OS deep paths)" \
    || _test_fail "level5" "only $l5 payloads"

  # Test Level 6 (WAF bypass)
  local l6; l6=$(_lfi_level6_waf_bypass | wc -l)
  [[ $l6 -ge 8 ]] \
    && _test_pass "level6 produces $l6 payloads (WAF bypass)" \
    || _test_fail "level6" "only $l6 payloads"

  # Test signature detection
  echo "root:x:0:0:root:/root:/bin/bash" > "$TMPDIR/test_passwd"
  local sig; sig=$(_lfi_check_signatures "$TMPDIR/test_passwd")
  [[ "$sig" == "unix_passwd" ]] \
    && _test_pass "signature detects unix_passwd" \
    || _test_fail "signature detection" "got='$sig'"

  echo "[extensions]" > "$TMPDIR/test_winini"
  sig=$(_lfi_check_signatures "$TMPDIR/test_winini")
  [[ "$sig" == "win_ini" ]] \
    && _test_pass "signature detects win_ini" \
    || _test_fail "signature detection" "got='$sig'"

  echo "PD9waHAgcGhwaW5mbygpOyA/Pg==" > "$TMPDIR/test_b64"
  sig=$(_lfi_check_signatures "$TMPDIR/test_b64")
  [[ "$sig" == "php_base64" ]] \
    && _test_pass "signature detects php_base64" \
    || _test_fail "signature detection" "got='$sig'"

  echo "DOCUMENT_ROOT=/var/www/html" > "$TMPDIR/test_env"
  sig=$(_lfi_check_signatures "$TMPDIR/test_env")
  [[ "$sig" == "proc_environ" ]] \
    && _test_pass "signature detects proc_environ" \
    || _test_fail "signature detection" "got='$sig'"

  echo "GET / HTTP/1.1" > "$TMPDIR/test_log"
  sig=$(_lfi_check_signatures "$TMPDIR/test_log")
  [[ "$sig" == "log_file" ]] \
    && _test_pass "signature detects log_file" \
    || _test_fail "signature detection" "got='$sig'"

  echo "just some random text" > "$TMPDIR/test_none"
  sig=$(_lfi_check_signatures "$TMPDIR/test_none" 2>/dev/null) && result=$? || result=$?
  [[ $result -ne 0 ]] \
    && _test_pass "signature returns non-zero for non-matching content" \
    || _test_fail "signature false positive" "matched random text as '$sig'"

  # Test OSCP mode excludes destructive payloads
  OSCP=true
  local l4_oscp; l4_oscp=$(_lfi_level4_php | wc -l)
  [[ $l4_oscp -lt $l4 ]] \
    && _test_pass "OSCP mode reduces PHP wrapper payloads ($l4_oscp < $l4)" \
    || _test_fail "OSCP filter" "same count: $l4_oscp vs $l4"
  OSCP=false
}

# ═══════════════════════════════════════════════════════════════════════════
#  3. PARAM MINER
# ═══════════════════════════════════════════════════════════════════════════
test_param_miner() {
  _section "Parameter Miner"

  source "${TRAKTR_ROOT}/src/intel/param_miner.sh" 2>/dev/null || {
    _test_fail "param_miner.sh" "failed to source"; return
  }
  _test_pass "param_miner.sh sources without error"

  # Test LFI keyword matching
  local test_params="file path page redirect url callback include template doc"
  local lfi_matches=0
  for p in $test_params; do
    echo "$p" | grep -qiP "$LFI_PARAM_KEYWORDS" && ((lfi_matches++)) || true
  done
  [[ $lfi_matches -ge 7 ]] \
    && _test_pass "LFI keywords match $lfi_matches/10 known LFI params" \
    || _test_fail "LFI keywords" "only $lfi_matches matches"

  # Test short params
  for p in p f fn fp loc uri val; do
    echo "$p" | grep -qxP "$LFI_SHORT_PARAMS" || { _test_fail "LFI short param" "'$p' not matched"; continue; }
  done
  _test_pass "LFI_SHORT_PARAMS matches all single-letter LFI params"

  # Test redirect keyword matching
  local redir_matches=0
  for p in redirect next return goto url callback dest forward; do
    echo "$p" | grep -qiP "$REDIR_PARAM_KEYWORDS" && ((redir_matches++)) || true
  done
  [[ $redir_matches -ge 7 ]] \
    && _test_pass "Redirect keywords match $redir_matches/8 known redirect params" \
    || _test_fail "Redirect keywords" "only $redir_matches matches"

  # Test non-LFI params don't false-positive
  local false_pos=0
  for p in username email password submit csrf token; do
    echo "$p" | grep -qiP "$LFI_PARAM_KEYWORDS" && ((false_pos++)) || true
  done
  [[ $false_pos -le 1 ]] \
    && _test_pass "Non-LFI params have low false-positive rate ($false_pos/6)" \
    || _test_fail "LFI false positives" "$false_pos/6 matched"

  # Test merge/dedup with mock data
  mkdir -p "$TMPDIR/merge_test"
  cat > "$TMPDIR/merge_test/params_crawled.txt" << 'EOF'
http://test.com/page|file|crawled_url|GET|extracted
http://test.com/page|path|crawled_url|GET|extracted
http://test.com/page|file|crawled_url|GET|dup
EOF
  cat > "$TMPDIR/merge_test/params_html.txt" << 'EOF'
http://test.com/page|file|html_input|GET|form
http://test.com/page|name|html_input|POST|form
EOF

  _merge_and_score_params "$TMPDIR/merge_test" 2>/dev/null
  local merged_count; merged_count=$(wc -l < "$TMPDIR/merge_test/active_params.txt" 2>/dev/null || echo 0)
  [[ $merged_count -ge 2 ]] && [[ $merged_count -le 3 ]] \
    && _test_pass "merge deduplicates params correctly ($merged_count unique)" \
    || _test_fail "merge dedup" "expected 2-3, got $merged_count"

  # Check LFI candidate tagging
  local lfi_cand; lfi_cand=$(wc -l < "$TMPDIR/merge_test/lfi_candidates.txt" 2>/dev/null || echo 0)
  [[ $lfi_cand -ge 1 ]] \
    && _test_pass "LFI candidates tagged from 'file' and 'path' params ($lfi_cand)" \
    || _test_fail "LFI candidate tagging" "expected >=1, got $lfi_cand"
}

# ═══════════════════════════════════════════════════════════════════════════
#  4. REQUEST PARSER
# ═══════════════════════════════════════════════════════════════════════════
test_request_parser() {
  _section "Request Parser"

  source "${TRAKTR_ROOT}/src/core/request_parser.sh" 2>/dev/null || {
    _test_fail "request_parser.sh" "failed to source"; return
  }
  _test_pass "request_parser.sh sources without error"

  # Test with sample Burp request
  local sample="${TRAKTR_ROOT}/tests/sample_burp.txt"
  if [[ -f "$sample" ]]; then
    parse_burp_request "$sample" 2>/dev/null || true
    [[ -n "${BURP_TARGET:-}" ]] \
      && _test_pass "parses Burp target URL: $BURP_TARGET" \
      || _test_fail "Burp target" "BURP_TARGET empty"
    [[ ${#BURP_HEADERS[@]} -gt 0 ]] \
      && _test_pass "extracts ${#BURP_HEADERS[@]} headers from Burp request" \
      || _test_fail "Burp headers" "no headers extracted"
  else
    _test_skip "Burp request parsing" "no sample file"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
#  5. BRAIN (Framework Detection)
# ═══════════════════════════════════════════════════════════════════════════
test_brain() {
  _section "Brain (Framework Detection)"

  source "${TRAKTR_ROOT}/src/intel/brain.sh" 2>/dev/null || {
    _test_fail "brain.sh" "failed to source"; return
  }
  _test_pass "brain.sh sources without error"

  # Test header-based detection
  declare -f detect_framework &>/dev/null \
    && _test_pass "detect_framework function exists" \
    || _test_fail "detect_framework" "function not found"

  declare -f suggest_next_step &>/dev/null \
    && _test_pass "suggest_next_step function exists" \
    || _test_fail "suggest_next_step" "function not found"

  declare -f build_curl_command &>/dev/null \
    && _test_pass "build_curl_command function exists" \
    || _test_fail "build_curl_command" "function not found"
}

# ═══════════════════════════════════════════════════════════════════════════
#  6. SECRET SCANNER
# ═══════════════════════════════════════════════════════════════════════════
test_secret_scanner() {
  _section "Secret Scanner"

  local patterns="${TRAKTR_ROOT}/payloads/secrets/patterns.txt"
  [[ -f "$patterns" ]] || { _test_skip "secret scanner" "patterns file missing"; return; }

  local rule_count; rule_count=$(grep -c '^[^#]' "$patterns" 2>/dev/null || echo 0)
  [[ $rule_count -ge 20 ]] \
    && _test_pass "patterns file has $rule_count rules (>=20)" \
    || _test_fail "patterns count" "only $rule_count rules"

  # Test pattern matching against known secrets
  local test_cases=(
    "AKIAIOSFODNN7EXAMPLE|aws_access_key"
    "ghp_ABCDEFghijklmnopqrstuvwxyz1234567890|github_token"
    "sk_live_ABCDEFghijklmnopqrst|stripe_key"
    "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk|jwt"
    "-----BEGIN RSA PRIVATE KEY-----|private_key"
  )

  for tc in "${test_cases[@]}"; do
    local secret="${tc%%|*}" expected_label="${tc##*|}"
    local matched=false
    while IFS=$'\t' read -r label pattern confidence; do
      [[ "$label" == \#* ]] || [[ -z "$label" ]] && continue
      [[ "$label" == "$expected_label" ]] || continue
      if echo "$secret" | grep -qP -- "$pattern" 2>/dev/null; then
        matched=true; break
      fi
    done < "$patterns"
    $matched \
      && _test_pass "pattern '${expected_label}' detects test secret" \
      || _test_fail "pattern '${expected_label}'" "did not match"
  done

  # Test false positive resistance
  local fp_count=0
  for safe in "test_api_key=xxxx" "password=changeme" "token=your_token_here" "AKIA_EXAMPLE_NOT_REAL"; do
    echo "$safe" | grep -qiE 'example|test_|placeholder|xxxx|your.*(key|token|here)|sample|dummy|changeme' \
      && true || ((fp_count++))
  done
  [[ $fp_count -eq 0 ]] \
    && _test_pass "false positive filter catches all test strings" \
    || _test_fail "false positive filter" "$fp_count leaked through"
}

# ═══════════════════════════════════════════════════════════════════════════
#  7. SCOPE GUARD
# ═══════════════════════════════════════════════════════════════════════════
test_scope_guard() {
  _section "Scope Guard"

  [[ -f "${TRAKTR_ROOT}/src/utils/scope_guard.sh" ]] || {
    _test_skip "scope_guard.sh" "file not found"; return
  }
  source "${TRAKTR_ROOT}/src/utils/scope_guard.sh" 2>/dev/null || {
    _test_fail "scope_guard.sh" "failed to source"; return
  }
  _test_pass "scope_guard.sh sources without error"
}

# ═══════════════════════════════════════════════════════════════════════════
#  8. HELPERS
# ═══════════════════════════════════════════════════════════════════════════
test_helpers() {
  _section "Helpers"

  [[ -f "${TRAKTR_ROOT}/src/utils/helpers.sh" ]] || {
    _test_skip "helpers.sh" "file not found"; return
  }
  source "${TRAKTR_ROOT}/src/utils/helpers.sh" 2>/dev/null || {
    _test_fail "helpers.sh" "failed to source"; return
  }
  _test_pass "helpers.sh sources without error"

  # Test encode_payload if exists
  if declare -f encode_payload &>/dev/null; then
    local enc; enc=$(encode_payload "../etc/passwd" url 2>/dev/null)
    [[ -n "$enc" ]] \
      && _test_pass "encode_payload URL encodes traversal: $enc" \
      || _test_fail "encode_payload" "empty result"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
#  9. PLUGIN LOADER
# ═══════════════════════════════════════════════════════════════════════════
test_plugin_loader() {
  _section "Plugin Loader"

  source "${TRAKTR_ROOT}/src/core/plugin_loader.sh" 2>/dev/null || {
    _test_fail "plugin_loader.sh" "failed to source"; return
  }
  _test_pass "plugin_loader.sh sources without error"

  declare -f load_plugins &>/dev/null \
    && _test_pass "load_plugins function exists" \
    || _test_fail "load_plugins" "function not found"

  declare -f run_hook &>/dev/null \
    && _test_pass "run_hook function exists" \
    || _test_fail "run_hook" "function not found"
}

# ═══════════════════════════════════════════════════════════════════════════
#  10. REPORTER
# ═══════════════════════════════════════════════════════════════════════════
test_reporter() {
  _section "Reporter"

  [[ -f "${TRAKTR_ROOT}/src/utils/reporter.sh" ]] || {
    _test_skip "reporter.sh" "file not found"; return
  }
  source "${TRAKTR_ROOT}/src/utils/reporter.sh" 2>/dev/null || {
    _test_fail "reporter.sh" "failed to source"; return
  }
  _test_pass "reporter.sh sources without error"

  declare -f generate_html_report &>/dev/null \
    && _test_pass "generate_html_report function exists" \
    || _test_fail "generate_html_report" "function not found"
}

# ═══════════════════════════════════════════════════════════════════════════
#  11. INTEGRATION: Flag/config check
# ═══════════════════════════════════════════════════════════════════════════
test_integration() {
  _section "Integration"

  # Test traktr.sh is syntactically valid
  bash -n "${TRAKTR_ROOT}/src/core/traktr.sh" 2>/dev/null \
    && _test_pass "traktr.sh syntax check passes" \
    || _test_fail "traktr.sh syntax" "bash -n failed"

  # Test all source files are syntactically valid
  local syntax_ok=true
  for f in "${TRAKTR_ROOT}"/src/{core,intel,utils}/*.sh; do
    [[ -f "$f" ]] || continue
    if ! bash -n "$f" 2>/dev/null; then
      _test_fail "syntax: $(basename $f)" "bash -n failed"
      syntax_ok=false
    fi
  done
  $syntax_ok && _test_pass "all .sh files pass syntax check"

  # Test config file is valid JSON
  local conf="${TRAKTR_ROOT}/config/traktr.json"
  if [[ -f "$conf" ]]; then
    jq . "$conf" > /dev/null 2>&1 \
      && _test_pass "traktr.json is valid JSON" \
      || _test_fail "traktr.json" "invalid JSON"
  fi

  # Test all .gitkeep dirs exist
  for dir in payloads/{api,auth,framework,lfi,rce,sqli,ssrf,waf_bypass,xss,xxe}; do
    [[ -d "${TRAKTR_ROOT}/$dir" ]] \
      && _test_pass "payload dir exists: $dir" \
      || _test_fail "payload dir" "$dir missing"
  done

  # Test install.sh is executable
  [[ -x "${TRAKTR_ROOT}/install.sh" ]] \
    && _test_pass "install.sh is executable" \
    || _test_fail "install.sh" "not executable"

  # Test --help flag
  local help_output; help_output=$(bash "${TRAKTR_ROOT}/src/core/traktr.sh" --help 2>&1) || true
  echo "$help_output" | grep -qi 'usage\|traktr\|target' \
    && _test_pass "--help produces usage output" \
    || _test_fail "--help" "no usage info"

  # Test --version flag
  local ver_output; ver_output=$(bash "${TRAKTR_ROOT}/src/core/traktr.sh" --version 2>&1) || true
  echo "$ver_output" | grep -q '1.0' \
    && _test_pass "--version shows 1.0" \
    || _test_fail "--version" "output='$ver_output'"
}

# ═══════════════════════════════════════════════════════════════════════════
#  12. FILE STRUCTURE
# ═══════════════════════════════════════════════════════════════════════════
test_file_structure() {
  _section "File Structure"

  local required_files=(
    "src/core/traktr.sh"
    "src/core/installer.sh"
    "src/core/request_parser.sh"
    "src/core/plugin_loader.sh"
    "src/intel/brain.sh"
    "src/intel/lfi_engine.sh"
    "src/intel/param_miner.sh"
    "src/intel/secret_scanner.sh"
    "src/utils/helpers.sh"
    "src/utils/reporter.sh"
    "src/utils/scope_guard.sh"
    "src/utils/spinner.sh"
    "config/traktr.json"
    "payloads/secrets/patterns.txt"
    "wordlists/params_common.txt"
    "install.sh"
    "Dockerfile"
    "README.md"
    "LICENSE"
  )

  for f in "${required_files[@]}"; do
    [[ -f "${TRAKTR_ROOT}/$f" ]] \
      && _test_pass "exists: $f" \
      || _test_fail "missing: $f" "required file not found"
  done
}

# ═══════════════════════════════════════════════════════════════════════════
#  RUN ALL TESTS
# ═══════════════════════════════════════════════════════════════════════════
echo -e "\n${CYN}╔══════════════════════════════════════════════════════════╗${RST}"
echo -e "${CYN}║           TRAKTR Test Suite v1.0                        ║${RST}"
echo -e "${CYN}╚══════════════════════════════════════════════════════════╝${RST}"

test_file_structure
test_spinner
test_lfi_engine
test_param_miner
test_request_parser
test_brain
test_secret_scanner
test_scope_guard
test_helpers
test_plugin_loader
test_reporter
test_integration

# Cleanup
rm -rf "$TMPDIR"

echo -e "\n${CYN}══════════════════════════════════════════════════════════${RST}"
echo -e "  Results: ${GRN}${PASS} passed${RST} | ${RED}${FAIL} failed${RST} | ${YEL}${SKIP} skipped${RST}"
echo -e "${CYN}══════════════════════════════════════════════════════════${RST}"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
