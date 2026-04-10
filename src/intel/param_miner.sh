#!/usr/bin/env bash
# TRAKTR Deep Parameter Discovery v1.0
# 6-source param mining: arjun, HTML forms, JS analysis, historical, wordlist, Burp
# Usage: source param_miner.sh; mine_params <endpoints_file> <outdir>

# ── LFI/redirect keyword lists ──────────────────────────────────────────────
LFI_PARAM_KEYWORDS='file|path|page|include|template|doc|folder|view|load|read|dir|resource|filename|download|src|conf|log|url|action|cat|type|content|prefix|require|pg|document|root|data|img|image|open|nav|site|import'
# Short single-letter params commonly used for file operations
LFI_SHORT_PARAMS='p|f|fn|fp|loc|uri|val'
REDIR_PARAM_KEYWORDS='redirect|redir|next|return|goto|url|callback|continue|dest|destination|target|rurl|forward|out|link|jump|checkout|return_to|login_url|image_url|return_url|next_page'

# ═══════════════════════════════════════════════════════════════════════════
#  MAIN PARAM MINING FUNCTION
# ═══════════════════════════════════════════════════════════════════════════
mine_params() {
  local endpoints_file="$1" outdir="${2:-${OUTDIR:-/tmp}}"
  local root="${TRAKTR_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
  [[ ! -s "$endpoints_file" ]] && return

  local pids=()

  # ── SOURCE 0: Extract params from already-crawled URLs ──
  (
    > "${outdir}/params_crawled.txt"
    cat "$endpoints_file" "${outdir}/all_endpoints.txt" 2>/dev/null | \
      grep '?' | sort -u | while IFS= read -r crawled_url; do
        local base="${crawled_url%%\?*}"
        echo "${crawled_url#*\?}" | tr '&' '\n' | while IFS='=' read -r p val; do
          [[ -z "$p" ]] && continue
          [[ ${#p} -gt 50 ]] && continue
          echo "${base}|${p}|crawled_url|GET|extracted(val=${val:0:20})"
        done
      done | sort -t'|' -k1,2 -u > "${outdir}/params_crawled.txt" 2>/dev/null || true
  ) &
  pids+=($!)

  # ── SOURCE 1: Arjun active brute ──
  if command -v arjun &>/dev/null; then
    (
      > "${outdir}/params_arjun.txt"
      # Prioritize pages with extensions (.php, .asp, .jsp) or query strings
      # These are real endpoints, not directory brute-force noise
      {
        grep -iE '\.(php|asp|aspx|jsp|do|action|cgi|pl)(\?|$)' "$endpoints_file" 2>/dev/null
        grep '\?' "$endpoints_file" 2>/dev/null | sed 's/\?.*//'
        head -10 "$endpoints_file"
      } | sort -u | head -20 | while IFS= read -r url; do
        local tmpout; tmpout=$(mktemp)
        timeout 60 arjun -u "$url" -t 10 --stable -oT "$tmpout" 2>/dev/null || true
        [[ -s "$tmpout" ]] && while IFS= read -r line; do
          [[ -n "$line" ]] && echo "${url}|${line}|arjun|GET|brute"
        done < "$tmpout" >> "${outdir}/params_arjun.txt"
        rm -f "$tmpout"
      done
    ) &
    pids+=($!)
  fi

  # ── SOURCE 2: HTML form extraction ──
  (
    > "${outdir}/params_html.txt"
    while IFS= read -r url; do
      local body; body=$(_curl "$url" 2>/dev/null) || continue

      # All input fields (name attribute)
      echo "$body" | grep -oiP '<input\b[^>]*\bname\s*=\s*["\x27]([^"\x27]+)' | \
        grep -oiP 'name\s*=\s*["\x27]\K[^"\x27]+' | while IFS= read -r p; do
          echo "${url}|${p}|html_input|GET|form"
        done

      # Hidden inputs (special tag)
      echo "$body" | grep -oiP '<input\b[^>]*type\s*=\s*["\x27]hidden["\x27][^>]*' | \
        grep -oiP 'name\s*=\s*["\x27]\K[^"\x27]+' | while IFS= read -r p; do
          echo "${url}|${p}|hidden_field|POST|hidden"
        done
      echo "$body" | grep -oiP '<input\b[^>]*name\s*=\s*["\x27]([^"\x27]+)["\x27][^>]*type\s*=\s*["\x27]hidden' | \
        grep -oiP 'name\s*=\s*["\x27]\K[^"\x27]+' | while IFS= read -r p; do
          echo "${url}|${p}|hidden_field|POST|hidden"
        done

      # Select, textarea, button
      echo "$body" | grep -oiP '<(?:select|textarea|button)\b[^>]*\bname\s*=\s*["\x27]([^"\x27]+)' | \
        grep -oiP 'name\s*=\s*["\x27]\K[^"\x27]+' | while IFS= read -r p; do
          echo "${url}|${p}|html_form|POST|form_element"
        done

      # Disabled fields
      echo "$body" | grep -oiP '<input\b[^>]*disabled[^>]*name\s*=\s*["\x27]([^"\x27]+)' | \
        grep -oiP 'name\s*=\s*["\x27]\K[^"\x27]+' | while IFS= read -r p; do
          echo "${url}|${p}|disabled_field|POST|disabled"
        done

      # data-param, data-field, data-name, data-key
      echo "$body" | grep -oiP 'data-(?:param|field|name|key|endpoint)\s*=\s*["\x27]([^"\x27]+)' | \
        grep -oiP '=\s*["\x27]\K[^"\x27]+' | while IFS= read -r p; do
          echo "${url}|${p}|data_attr|GET|data_attribute"
        done

      # Form actions → new endpoint discovery
      echo "$body" | grep -oiP '<form\b[^>]*action\s*=\s*["\x27]([^"\x27]+)' | \
        grep -oiP 'action\s*=\s*["\x27]\K[^"\x27]+' | while IFS= read -r path; do
          if [[ "$path" == /* ]]; then
            local base; base=$(echo "$url" | grep -oP 'https?://[^/]+')
            echo "${base}${path}" >> "$endpoints_file"
          elif [[ "$path" == http* ]]; then
            echo "$path" >> "$endpoints_file"
          fi
        done

      # JavaScript-set values in inline scripts
      echo "$body" | grep -oiP '\.(?:value|name)\s*=\s*["\x27](\w+)' | \
        grep -oiP '=\s*["\x27]\K\w+' | while IFS= read -r p; do
          echo "${url}|${p}|js_inline|POST|js_set"
        done

    done < <(head -100 "$endpoints_file") > "${outdir}/params_html.txt" 2>/dev/null || true
  ) &
  pids+=($!)

  # ── SOURCE 3: JS static analysis ──
  (
    > "${outdir}/params_js.txt"
    local target_base; target_base=$(echo "${TARGET:-}" | grep -oP 'https?://[^/]+') || true
    grep -hiE '\.js(\?|$|#)' "$endpoints_file" 2>/dev/null | grep -v '\.json' | sort -u | head -100 | \
    while IFS= read -r js_url; do
      local js; js=$(_curl "$js_url" 2>/dev/null) || continue
      [[ ${#js} -lt 50 ]] && continue

      # Save for secret scanning
      local safe; safe=$(echo "$js_url" | md5sum | cut -c1-16)
      echo "$js" > "${outdir}/responses/js_${safe}.txt" 2>/dev/null || true

      # fetch/axios/XHR → API endpoints + params
      echo "$js" | grep -oP '(?:fetch|axios[^(]*|\.open)\s*\(\s*["\x27`]([^"\x27`\s]{3,})' | \
        grep -oP '["\x27`]\K[^"\x27`]+' | while IFS= read -r path; do
          [[ "$path" == /* ]] && [[ -n "$target_base" ]] && echo "${target_base}${path}" >> "$endpoints_file"
          if [[ "$path" == *"?"* ]]; then
            local base="${path%%\?*}"
            echo "${path#*\?}" | tr '&' '\n' | cut -d= -f1 | while IFS= read -r p; do
              [[ -n "$p" ]] && [[ ${#p} -lt 50 ]] && echo "${target_base}${base}|${p}|js_fetch|GET|js"
            done
          fi
        done

      # URLSearchParams / searchParams / params
      echo "$js" | grep -oP "(?:URLSearchParams|searchParams|params)[^;]{0,100}(?:append|set|get)\s*\(\s*['\"](\w+)" | \
        grep -oP "['\"](\w{2,})['\"]" | tr -d "\"'" | sort -u | while IFS= read -r p; do
          echo "${js_url}|${p}|js_urlsearchparams|GET|js"
        done

      # JSON body keys near request calls
      echo "$js" | grep -oP '(?:body|data|params|payload)\s*[:=]\s*\{[^}]{1,500}\}' | \
        grep -oP '"(\w{2,})"\s*:' | sed 's/"//g; s/\s*://' | sort -u | while IFS= read -r p; do
          echo "${js_url}|${p}|js_body_key|POST|js"
        done

      # GraphQL query patterns
      echo "$js" | grep -oP '(?:query|mutation)\s*[({][^}]{0,500}' | \
        grep -oP '\b(\w{3,})\s*[({:]' | sed 's/[({:]//; s/^\s*//' | sort -u | while IFS= read -r p; do
          echo "${js_url}|${p}|js_graphql|POST|graphql"
        done

      # .env / config key references → potential params + secrets flag
      echo "$js" | grep -oP '(?:process\.env\.|config\.|settings\.)(\w{2,})' | \
        grep -oP '\.(\w+)$' | sed 's/^\.//' | sort -u | while IFS= read -r p; do
          echo "${js_url}|${p}|js_config|GET|config_key"
        done

    done > "${outdir}/params_js.txt" 2>/dev/null || true
  ) &
  pids+=($!)

  # ── SOURCE 4: Historical params ──
  (
    > "${outdir}/params_historical.txt"
    {
      cat "${outdir}/crawl/gau.txt" 2>/dev/null
      cat "${outdir}/crawl/wayback.txt" 2>/dev/null
    } | grep '?' | while IFS= read -r hist_url; do
      local base="${hist_url%%\?*}"
      echo "${hist_url#*\?}" | tr '&' '\n' | cut -d= -f1 | while IFS= read -r p; do
        [[ -n "$p" ]] && [[ ${#p} -lt 50 ]] && echo "${base}|${p}|historical|GET|archive"
      done
    done | sort -t'|' -k1,2 -u > "${outdir}/params_historical.txt" 2>/dev/null || true

    # Also extract path params: /api/v1/users/{id} → id
    cat "${outdir}/crawl/gau.txt" "${outdir}/crawl/wayback.txt" 2>/dev/null | \
      grep -oP '/\d+(?=/|$)' | sort -u | head -5 > /dev/null  # Detect numeric path params exist
  ) &
  pids+=($!)

  # ── SOURCE 5: Wordlist brute (top endpoints only) ──
  local wordlist="$root/wordlists/params_common.txt"
  if [[ -f "$wordlist" ]]; then
    (
      > "${outdir}/params_wordlist.txt"
      # Pick real page endpoints (with extensions), not directory brute noise
      {
        grep -iE '\.(php|asp|aspx|jsp|do|action|cgi|pl)(\?|$)' "$endpoints_file" 2>/dev/null
        head -5 "$endpoints_file"
      } | sed 's/\?.*$//' | sort -u | head -10 | while IFS= read -r url; do
        # Skip non-HTML responses (images, CSS, JS) -- they'll cause false positives
        local content_type
        content_type=$(_curl "$url" -o /dev/null -w '%{content_type}' 2>/dev/null) || continue
        echo "$content_type" | grep -qiE 'image/|audio/|video/|font/|css|javascript' && continue
        local baseline_size
        baseline_size=$(_curl "${url}?traktr_canary_param=traktr_canary_value" -o /dev/null -w '%{size_download}' 2>/dev/null) || continue
        # Test first 500 params from wordlist
        head -500 "$wordlist" | while IFS= read -r p; do
          [[ -z "$p" ]] && continue
          local test_size
          test_size=$(_curl "${url}?${p}=traktr_canary" -o /dev/null -w '%{size_download}' 2>/dev/null) || continue
          local delta=$(( ${test_size:-0} - ${baseline_size:-0} ))
          if [[ ${delta#-} -gt 50 ]]; then
            echo "${url}|${p}|wordlist_brute|GET|response_diff(${delta})"
          fi
        done
      done > "${outdir}/params_wordlist.txt" 2>/dev/null || true
    ) &
    pids+=($!)
  fi

  # ── SOURCE 6: Burp request params (already in params_burp.txt) ──
  # No action needed; handled by traktr.sh calling export_params_to_file

  # Wait for all sources
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done

  # ── MERGE + DEDUPE + PRIORITY SCORING ──
  _merge_and_score_params "$outdir"
}

# ═══════════════════════════════════════════════════════════════════════════
#  MERGE, DEDUPE, AND PRIORITY SCORING
# ═══════════════════════════════════════════════════════════════════════════
_merge_and_score_params() {
  local outdir="$1"
  local merged="${outdir}/active_params.txt"
  local tmpfile; tmpfile=$(mktemp)

  # Combine all sources (normalize URL: strip query string for dedup key)
  cat "${outdir}"/params_*.txt 2>/dev/null | \
    grep -v '^$' > "$tmpfile" 2>/dev/null || true

  # Deduplicate by base_url + param name, count sources
  > "$merged"
  declare -A _seen_params=()
  declare -A _param_sources=()
  declare -A _param_lines=()
  declare -A _param_counts=()

  while IFS='|' read -r url param source method note; do
    [[ -z "$param" ]] && continue
    # Normalize: strip query string from URL for dedup
    local base_url="${url%%\?*}"
    local key; key=$(echo "${base_url}|${param}" | tr '[:upper:]' '[:lower:]')

    if [[ -z "${_seen_params[$key]:-}" ]]; then
      _seen_params[$key]=1
      _param_sources[$key]="$source"
      _param_lines[$key]="${base_url}|${param}|${source}|${method}|${note}"
      _param_counts[$key]=1
    else
      _param_counts[$key]=$(( ${_param_counts[$key]} + 1 ))
      _param_sources[$key]="${_param_sources[$key]},${source}"
    fi
  done < "$tmpfile"

  # Output with priority scoring
  for key in "${!_seen_params[@]}"; do
    local count=${_param_counts[$key]}
    local priority="MEDIUM"
    [[ $count -ge 3 ]] && priority="CRITICAL"
    [[ $count -ge 2 ]] && [[ $count -lt 3 ]] && priority="HIGH"
    echo "${_param_lines[$key]}|${priority}|${_param_sources[$key]}"
  done | sort -t'|' -k1,2 >> "$merged"

  rm -f "$tmpfile"

  # ── Tag special params (match on param field, second pipe-delimited column) ──
  > "${outdir}/lfi_candidates.txt"
  > "${outdir}/redirect_candidates.txt"
  while IFS='|' read -r url param rest; do
    [[ -z "$param" ]] && continue
    local lp; lp=$(echo "$param" | tr '[:upper:]' '[:lower:]')
    # Match long keywords anywhere in param name
    if echo "$lp" | grep -qiP "$LFI_PARAM_KEYWORDS"; then
      echo "${url}|${param}|${rest}" >> "${outdir}/lfi_candidates.txt"
    # Match short exact params (p, f, fn, etc.)
    elif echo "$lp" | grep -qxP "$LFI_SHORT_PARAMS"; then
      echo "${url}|${param}|${rest}" >> "${outdir}/lfi_candidates.txt"
    fi
    if echo "$lp" | grep -qiP "$REDIR_PARAM_KEYWORDS"; then
      echo "${url}|${param}|${rest}" >> "${outdir}/redirect_candidates.txt"
    fi
  done < "$merged"
}
