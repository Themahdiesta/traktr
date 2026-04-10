#!/usr/bin/env bash
# Example Traktr Plugin -- demonstrates the plugin contract
# Place custom plugins in this directory as *.sh files
#
# REQUIRED: Every plugin must define run_plugin(hook_name, context)
# OPTIONAL: Define <plugin_name>_hooks() returning space-separated hook names
#
# Hook names: pre_scan, post_discovery, post_params, on_vuln_found, post_scan
#
# Output format (one per line):
#   SEVERITY|TYPE|ENDPOINT|PAYLOAD|CONFIDENCE|PROOF_BASE64
#
# Example: HIGH|custom_check|https://target/api|test|HIGH|dGVzdA==

# Declare which hooks this plugin listens on
example_plugin_hooks() {
  echo "post_discovery"
}

# Main plugin entry point
run_plugin() {
  local hook="$1" context="$2"

  case "$hook" in
    post_discovery)
      # Example: check for exposed .git directory
      local target; target=$(echo "$context" | jq -r '.target // empty' 2>/dev/null)
      [[ -z "$target" ]] && return

      local status; status=$(curl -sk -o /dev/null -w '%{http_code}' "${target}/.git/HEAD" 2>/dev/null) || return
      if [[ "$status" == "200" ]]; then
        local proof; proof=$(echo "Exposed .git/HEAD returned 200" | base64 -w0)
        echo "HIGH|exposed_git|${target}/.git/HEAD|N/A|HIGH|${proof}"
      fi
      ;;
  esac
}
