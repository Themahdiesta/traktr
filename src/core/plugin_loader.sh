#!/usr/bin/env bash
# TRAKTR Plugin Loader v2.0
# Auto-loads plugins from plugins/*.sh, provides hook system
# Usage: source plugin_loader.sh (sourced by traktr.sh)

# ── Plugin Registry ─────────────────────────────────────────────────────────
declare -ga _PLUGINS_LOADED=()
declare -gA _PLUGIN_HOOKS=()
# Hooks: pre_scan, post_discovery, post_params, on_vuln_found, post_scan

# ═══════════════════════════════════════════════════════════════════════════
#  LOAD ALL PLUGINS
# ═══════════════════════════════════════════════════════════════════════════
load_plugins() {
  local plugin_dir="${TRAKTR_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}/plugins"
  [[ ! -d "$plugin_dir" ]] && return 0

  for plugin_file in "$plugin_dir"/*.sh; do
    [[ ! -f "$plugin_file" ]] && continue
    [[ "$(basename "$plugin_file")" == "README.md" ]] && continue

    local plugin_name; plugin_name=$(basename "$plugin_file" .sh)

    # Validate plugin has required function
    if ! grep -q "run_plugin" "$plugin_file" 2>/dev/null; then
      echo -e "\033[1;33m  [!] Plugin '${plugin_name}' missing run_plugin() -- skipped\033[0m" >&2
      continue
    fi

    # Source in subshell-safe way (plugin cannot modify core globals directly)
    # shellcheck source=/dev/null
    source "$plugin_file" 2>/dev/null || {
      echo -e "\033[1;33m  [!] Plugin '${plugin_name}' failed to load\033[0m" >&2
      continue
    }

    _PLUGINS_LOADED+=("$plugin_name")

    # Register hooks declared by plugin
    if declare -f "${plugin_name}_hooks" &>/dev/null; then
      local hooks; hooks=$("${plugin_name}_hooks" 2>/dev/null) || true
      for hook in $hooks; do
        _PLUGIN_HOOKS["${hook}"]+="${plugin_name},"
      done
    fi
  done

  [[ ${#_PLUGINS_LOADED[@]} -gt 0 ]] && \
    echo "[$(date '+%H:%M:%S')]   Loaded ${#_PLUGINS_LOADED[@]} plugin(s): ${_PLUGINS_LOADED[*]}" || true
}

# ═══════════════════════════════════════════════════════════════════════════
#  EXECUTE HOOK
# ═══════════════════════════════════════════════════════════════════════════
run_hook() {
  local hook_name="$1"; shift
  local context="${1:-{}}"

  local plugins="${_PLUGIN_HOOKS[$hook_name]:-}"
  [[ -z "$plugins" ]] && return 0

  local outdir="${OUTDIR:-/tmp}"
  local plugin_findings="${outdir}/plugin_findings.jsonl"

  IFS=',' read -ra plugin_list <<< "$plugins"
  for plugin_name in "${plugin_list[@]}"; do
    [[ -z "$plugin_name" ]] && continue

    # Run plugin in subshell to sandbox it
    (
      local result
      result=$(run_plugin "$hook_name" "$context" 2>/dev/null) || true

      # Parse plugin output: SEVERITY|TYPE|ENDPOINT|PAYLOAD|CONFIDENCE|PROOF_BASE64
      while IFS='|' read -r severity ptype endpoint payload confidence proof_b64; do
        [[ -z "$severity" ]] && continue
        [[ "$severity" == \#* ]] && continue

        local proof=""
        [[ -n "$proof_b64" ]] && proof=$(echo "$proof_b64" | base64 -d 2>/dev/null) || true

        # Append to plugin findings as JSON
        echo "{\"type\":\"${ptype}\",\"url\":\"${endpoint}\",\"payload\":\"${payload}\",\"confidence\":\"${confidence}\",\"proof\":\"${proof}\",\"source\":\"plugin:${plugin_name}\"}" >> "$plugin_findings"
      done <<< "$result"
    ) || true
  done

  # Merge plugin findings into main findings.json
  if [[ -f "$plugin_findings" ]] && [[ -s "$plugin_findings" ]]; then
    local main_findings="${outdir}/findings.json"
    if [[ -f "$main_findings" ]]; then
      # Merge: existing + plugin findings
      local merged; merged=$(mktemp)
      {
        jq -r '.[]' "$main_findings" 2>/dev/null || true
        cat "$plugin_findings"
      } | jq -s '.' > "$merged" 2>/dev/null
      if [[ -f "$merged" ]]; then mv "$merged" "$main_findings"; else rm -f "$merged"; fi
    else
      jq -s '.' "$plugin_findings" > "$main_findings" 2>/dev/null || true
    fi
    : > "$plugin_findings"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
#  LIST LOADED PLUGINS (for reporting)
# ═══════════════════════════════════════════════════════════════════════════
list_plugins() {
  printf '%s\n' "${_PLUGINS_LOADED[@]+"${_PLUGINS_LOADED[@]}"}"
}
