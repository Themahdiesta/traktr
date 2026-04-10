# Contributing to Traktr

## Writing Plugins

Plugins live in `plugins/*.sh` and are auto-loaded at startup.

### Plugin Contract

Every plugin **must** define `run_plugin(hook_name, context)`:

```bash
#!/usr/bin/env bash

# Declare hooks (space-separated)
my_plugin_hooks() {
  echo "post_discovery post_params"
}

# Main entry point -- called once per hook trigger
run_plugin() {
  local hook="$1" context="$2"
  # context is JSON with target, outdir, framework, etc.

  case "$hook" in
    post_discovery)
      # Your logic here
      ;;
    post_params)
      # Your logic here
      ;;
  esac
}
```

### Output Format

One finding per line, pipe-separated:
```
SEVERITY|TYPE|ENDPOINT|PAYLOAD|CONFIDENCE|PROOF_BASE64
```

Example:
```
HIGH|exposed_git|https://target/.git/HEAD|N/A|HIGH|RXhwb3NlZCAuZ2l0
```

### Available Hooks

| Hook | When | Context |
|------|------|---------|
| `pre_scan` | Before scanning starts | `{target, outdir, framework}` |
| `post_discovery` | After crawl + recon | `{target, outdir, endpoints_count}` |
| `post_params` | After parameter mining | `{target, outdir, params_count}` |
| `on_vuln_found` | Each finding | `{type, url, confidence}` |
| `post_scan` | After all scanning | `{target, outdir, findings_count}` |

### Rules

- Plugins run in subshells -- you **cannot** modify core Traktr state
- Use `_curl` for HTTP requests (inherits auth, stealth, rate limiting)
- Respect `$OSCP` mode -- no destructive actions
- Keep plugins focused: one check per plugin

## Adding Payloads

See [PAYLOAD_GUIDE.md](PAYLOAD_GUIDE.md) for payload file format.

Place payload files in:
- `payloads/<vuln_type>/` -- general payloads
- `payloads/framework/<framework>_<vuln_type>.txt` -- framework-specific
- `payloads/waf_bypass/<waf>_<vuln_type>.txt` -- WAF bypass variants

## Code Style

- Bash 4.0+ compatible
- Functions prefixed with `_` are internal
- Use `|| true` guards on `[[ ]] && action` patterns (set -e safety)
- No `set -e` in sourced library files
- Use `local` for all function variables
