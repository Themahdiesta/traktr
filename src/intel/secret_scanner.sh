#!/usr/bin/env bash
# TRAKTR Secret & Credential Scanner v1.0
# Regex-based scanning of JS, HTML, error pages for leaked keys/tokens/secrets
# Usage: source secret_scanner.sh; scan_secrets <outdir>

# ═══════════════════════════════════════════════════════════════════════════
#  FALSE POSITIVE FILTER
# ═══════════════════════════════════════════════════════════════════════════
_is_false_positive() {
  local match="$1"
  # Known test/example patterns
  echo "$match" | grep -qiE 'example|test_?key|placeholder|xxxx|your.*(key|token|here)|sample|dummy|changeme|abc123|000000|AAAAAA|INSERT|TODO|REPLACE' && return 0
  # Too short to be real
  [[ ${#match} -lt 8 ]] && return 0
  # All same character
  [[ "$match" =~ ^(.)\1+$ ]] && return 0
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════
#  MAIN SECRET SCANNING FUNCTION
# ═══════════════════════════════════════════════════════════════════════════
scan_secrets() {
  local outdir="${1:-${OUTDIR:-/tmp}}"
  local root="${TRAKTR_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
  local patterns_file="$root/payloads/secrets/patterns.txt"
  [[ ! -f "$patterns_file" ]] && return

  local secrets_found=0
  local tmpfindings; tmpfindings=$(mktemp)

  # ── Collect files to scan ──
  # JS files (already fetched during crawl/param mining)
  # HTML responses, error pages
  local scan_files=()
  for f in "${outdir}"/responses/*.txt "${outdir}"/responses/*.html; do
    [[ -f "$f" ]] && scan_files+=("$f")
  done

  # Fetch any JS files not yet downloaded
  if [[ -f "${outdir}/all_endpoints.txt" ]]; then
    grep -hiE '\.js(\?|$)' "${outdir}/all_endpoints.txt" 2>/dev/null | \
      grep -v '\.json' | sort -u | head -50 | while IFS= read -r js_url; do
        local safe; safe=$(echo "$js_url" | md5sum | cut -c1-16)
        if [[ ! -f "${outdir}/responses/js_${safe}.txt" ]]; then
          _curl "$js_url" > "${outdir}/responses/js_${safe}.txt" 2>/dev/null || true
        fi
      done
    # Refresh file list
    scan_files=()
    for f in "${outdir}"/responses/*.txt "${outdir}"/responses/*.html; do
      [[ -f "$f" ]] && scan_files+=("$f")
    done
  fi

  # Fetch error pages for stack trace / config leak scanning
  if [[ -f "${outdir}/error_pages.txt" ]]; then
    head -20 "${outdir}/error_pages.txt" | while IFS= read -r err_url; do
      local safe; safe=$(echo "$err_url" | md5sum | cut -c1-16)
      if [[ ! -f "${outdir}/responses/err_${safe}.txt" ]]; then
        _curl "$err_url" > "${outdir}/responses/err_${safe}.txt" 2>/dev/null || true
      fi
    done
    # Refresh again
    scan_files=()
    for f in "${outdir}"/responses/*.txt "${outdir}"/responses/*.html; do
      [[ -f "$f" ]] && scan_files+=("$f")
    done
  fi

  [[ ${#scan_files[@]} -eq 0 ]] && { echo "[]" > "${outdir}/secrets.json"; return; }

  # ── Scan patterns ──
  while IFS=$'\t' read -r label pattern confidence; do
    [[ "$label" == \#* ]] || [[ -z "$label" ]] && continue
    [[ -z "$pattern" ]] && continue

    for resp_file in "${scan_files[@]}"; do
      local matches
      matches=$(grep -oP "$pattern" "$resp_file" 2>/dev/null | head -5) || continue
      [[ -z "$matches" ]] && continue

      while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        _is_false_positive "$match" && continue

        # Redact for safe output
        local redacted
        if [[ ${#match} -gt 16 ]]; then
          redacted="${match:0:8}...${match: -4}"
        elif [[ ${#match} -gt 8 ]]; then
          redacted="${match:0:4}****"
        else
          redacted="****"
        fi

        # Get context (surrounding line)
        local context
        context=$(grep -m1 -F "$match" "$resp_file" 2>/dev/null | head -c 200 | sed 's/"/\\"/g') || true

        # Determine source file/URL
        local location; location=$(basename "$resp_file")

        # Output JSON line
        echo "{\"type\":\"${label}\",\"value_redacted\":\"${redacted}\",\"location\":\"${location}\",\"confidence\":\"${confidence}\",\"context\":\"${context}\"}" >> "$tmpfindings"
        ((secrets_found++)) || true

        # Immediate terminal alert for CONFIRMED/HIGH
        if [[ "$confidence" == "CONFIRMED" ]]; then
          echo -e "\033[1;31m  [!!!] SECRET: ${label} = ${redacted} in ${location} [CONFIRMED]\033[0m" >&2
        elif [[ "$confidence" == "HIGH" ]]; then
          echo -e "\033[1;33m  [!!] SECRET: ${label} = ${redacted} in ${location} [HIGH]\033[0m" >&2
        fi

      done <<< "$matches"
    done
  done < "$patterns_file"

  # ── Additional: scan HTML comments for leaked info ──
  for resp_file in "${scan_files[@]}"; do
    grep -oP '<!--[\s\S]{5,500}?-->' "$resp_file" 2>/dev/null | \
      grep -iP 'password|secret|key|token|api|admin|config|debug|todo|fixme|hack|credential|internal' | \
      head -10 | while IFS= read -r comment; do
        local safe_comment; safe_comment=$(echo "$comment" | head -c 150 | sed 's/"/\\"/g')
        echo "{\"type\":\"html_comment_leak\",\"value_redacted\":\"$(echo "$comment" | head -c 40 | sed 's/"/\\"/g')...\",\"location\":\"$(basename "$resp_file")\",\"confidence\":\"POSSIBLE\",\"context\":\"${safe_comment}\"}" >> "$tmpfindings"
        ((secrets_found++)) || true
      done
  done

  # ── Build JSON output ──
  if [[ -s "$tmpfindings" ]]; then
    jq -s '.' "$tmpfindings" > "${outdir}/secrets.json" 2>/dev/null || {
      # jq fallback
      echo "["
      local first=true
      while IFS= read -r line; do
        $first && first=false || echo ","
        echo "  $line"
      done < "$tmpfindings"
      echo "]"
    } > "${outdir}/secrets.json"
  else
    echo "[]" > "${outdir}/secrets.json"
  fi

  rm -f "$tmpfindings"
  echo "$secrets_found"
}
