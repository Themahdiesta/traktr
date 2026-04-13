# Traktr -- plowing the web

> *"One command. Full enumeration. Smart LFI. OSCP-safe by design."*

Traktr is a bash-based web application penetration testing framework that orchestrates popular security tools into a single automated pipeline. It handles reconnaissance, crawling, parameter discovery, vulnerability testing, and reporting -- all from one command.

## Installation

### Method comparison

| Method | Kali | Ubuntu/Debian | Arch | Fedora | macOS | Any OS |
|--------|:----:|:-------------:|:----:|:------:|:-----:|:------:|
| One-liner (root) | ✓ | ✓ (as root) | ✓ (as root) | ✓ (as root) | ✓ (as root) | — |
| Git clone | ✓ | ✓ | ✓ | ✓ | ✓ (brew required) | — |
| Docker | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### One-liner (root only)

```bash
curl -sL https://raw.githubusercontent.com/Themahdiesta/traktr/main/install.sh | bash
```

> **Note:** The piped `curl | bash` invocation has no interactive TTY, so the installer
> requires **root** to proceed safely (sudo prompts would be silently swallowed in a pipe).
> If you see `No TTY detected` or are not running as root, use the **git clone method** below.

### Git clone (recommended for all platforms)

```bash
git clone https://github.com/Themahdiesta/traktr.git
cd traktr
./install.sh          # Prompts for sudo password once; installs all tools
```

Verify what will be installed without making any changes:

```bash
./install.sh --dry-run
```

Check tool health after install:

```bash
./install.sh --check
# or: traktr --check
```

### Manual

```bash
git clone https://github.com/Themahdiesta/traktr.git
cd traktr
chmod +x src/core/traktr.sh src/core/installer.sh
./src/core/installer.sh          # Installs all dependencies
ln -sf "$(pwd)/src/core/traktr.sh" ~/.local/bin/traktr
```

### Docker (any platform — macOS, Windows, Linux)

The Docker image is self-contained (Debian bookworm base) and works on any machine with Docker installed — no distro requirements.

```bash
docker build -t traktr .
docker run --rm traktr https://target.com
docker run --rm -v $(pwd)/results:/output traktr https://target.com -o /output
```

### Requirements

- **OS**: Kali Linux (recommended), Ubuntu 22.04+, Debian bookworm+, Arch, Fedora, macOS (with Homebrew)
- **Shell**: Bash 4.0+
- **Disk**: ~2 GB (for payload repositories)
- **Go**: 1.21+ (auto-installed if missing)
- Tools auto-installed: katana, ffuf, nuclei, httpx, gau, subfinder, waybackurls, dalfox, arjun, commix, feroxbuster

## Quick Start

```bash
# Standard scan
traktr https://target.com

# OSCP-safe scan (rate-limited, logged, no auto-exploitation)
traktr https://target.com --oscp

# Authenticated scan from Burp Suite saved request
traktr -r burp_request.txt

# Scan with custom scope
traktr https://target.com --scope ".*\.target\.com"
```

## Features

| Feature | Description |
|---------|-------------|
| **Burp Request Import** | `traktr -r request.txt` -- zero-config authenticated scanning with full header replay |
| **Deep Parameter Mining** | 6 sources: HTML forms, hidden fields, JS analysis, Arjun brute, GAU historical, Burp |
| **Smart LFI Engine** | 6-level escalation, multi-signal validation, WAF bypass chains, depth auto-discovery |
| **RCE Escalation Engine** | 7-chain auto-exploitation: upload+include, PHP wrappers, log poison, session poison, environ, upload progress race, SQLi file write. Dynamic bypass detection (double-encode, str_replace), HTML form discovery, PHP source analysis, post-exploitation enumeration |
| **Secret Scanner** | 24+ regex patterns: AWS keys, JWTs, API tokens, private keys, internal URLs |
| **Framework Detection** | 20+ fingerprints: PHP, Laravel, WordPress, Django, Spring, Express, ASP.NET, Next.js... |
| **WAF-Adaptive** | Auto-detects WAF, selects evasion payloads, exponential backoff on blocks |
| **OSCP-Safe Mode** | Request logging, rate limiting, no auto-exploitation, destructive payload filtering |
| **Plugin System** | Drop-in `plugins/*.sh` with 5 hook points |
| **Multi-Signal Validation** | Content match + length delta + status change + time delta + header change |
| **Scope Enforcement** | Domain whitelist, redirect blocking, regex patterns |

## Pipeline Architecture

```
traktr <target>
    |
    v
  [Step 0] Init -------- output dirs, scope, config
  [Step 1] Recon -------- GAU, Wayback, passive discovery
  [Step 2] Crawl -------- Katana (JS-aware), headless Chrome
  [Step 3] Probe -------- httpx live filtering + tech detection
  [Step 4] Params ------- 6-source param mining (parallel)
  [Step 4.5] Secrets ---- JS/HTML/error page scanning
  [Step 5] Vuln Test ---- Nuclei + LFI engine + Dalfox + Commix
  [Step 5.5] RCE ------- 7-chain escalation (upload+include, wrappers, log/session poison...)
  [Step 6] Report ------- MD + HTML + JSON + PoC commands
```

## Usage

```
traktr <target> [flags]
traktr -r request.txt [flags]
traktr -r requests_dir/ [flags]    # Batch mode
```

### Flags

| Flag | Description |
|------|-------------|
| `-r, --request FILE` | Import Burp Suite request file or directory |
| `--scope REGEX` | Restrict scanning to matching URLs |
| `--auth USER:PASS` | HTTP Basic authentication |
| `--cookie "k=v"` | Custom cookie header |
| `--token TOKEN` | Bearer token |
| `--header "K: V"` | Custom header (repeatable) |
| `--oscp` | OSCP-safe mode (exam-compliant) |
| `--stealth` | Stealth mode (delays, UA rotation) |
| `--aggressive` | Aggressive mode (higher concurrency) |
| `--lfi-only` | LFI detection only |
| `--param-only` | Parameter discovery only |
| `--secrets-only` | Secret scanning only |
| `--threads N` | Concurrency level (default: 20) |
| `--rate N` | Max requests per second |
| `--depth N` | Crawl depth (default: 5) |
| `--timeout N` | Request timeout in seconds (default: 10) |
| `--json` | NDJSON output stream to stdout |
| `-o, --output DIR` | Custom output directory |
| `--debug` | Verbose debug logging |
| `--quiet` | Suppress terminal output |
| `--dry-run` | Show what would be done |

## Output

Each scan creates a timestamped directory:

```
scan_results/<target>_<timestamp>/
├── REPORT.md            # Markdown report
├── REPORT.html          # Self-contained HTML report (dark theme)
├── findings.json        # All findings with confidence scores
├── secrets.json         # Detected secrets (redacted values)
├── all_endpoints.txt    # Discovered endpoints
├── active_params.txt    # Discovered parameters with metadata
├── lfi_candidates.txt   # LFI-susceptible parameters
├── poc_commands.txt     # Executable PoC curl commands
├── scan_summary.txt     # Quick summary stats
├── requests.log         # OSCP request log (every request)
└── vuln/                # Per-tool vulnerability output
```

## Examples

```bash
# Full scan with Burp auth
traktr -r login_request.txt --scope ".*\.target\.com"

# LFI-focused scan on OSCP exam
traktr http://10.10.10.100:8080 --oscp --lfi-only

# Stealth scan with custom cookies
traktr https://app.target.com --stealth --cookie "session=abc123"

# JSON pipeline -- filter only confirmed vulns
traktr https://target.com --json | jq 'select(.confidence == "HIGH")'

# Docker with output mount
docker run --rm -v $(pwd)/results:/output traktr https://target.com -o /output
```

## Plugins

Drop `.sh` files into `plugins/` -- they auto-load at startup. Five hook points:

- `pre_scan` -- before scanning starts
- `post_discovery` -- after recon/crawl
- `post_params` -- after parameter mining
- `post_scan` -- after vulnerability testing
- `post_report` -- after report generation

See [CONTRIBUTING.md](CONTRIBUTING.md) for the plugin API and [plugins/example_plugin.sh](plugins/example_plugin.sh) for a working example.

## Project Structure

```
src/core/
  traktr.sh           # Main orchestrator (entry point)
  installer.sh        # Dependency installer
  request_parser.sh   # Burp request import + JWT decode
  plugin_loader.sh    # Plugin system
src/intel/
  brain.sh            # Framework detection, payload selection
  lfi_engine.sh       # 6-level LFI escalation engine
  rce_engine.sh       # 7-chain RCE escalation engine
  param_miner.sh      # Multi-source parameter discovery
  secret_scanner.sh   # Regex-based secret detection
src/utils/
  scope_guard.sh      # Scope enforcement + ban detection
  helpers.sh          # Logging, encoding, retry, UA rotation
  reporter.sh         # HTML report generator
  spinner.sh          # Terminal spinner animations
config/
  traktr.json         # Default configuration
payloads/             # Organized by vuln type
wordlists/            # Parameter wordlists
plugins/              # Custom plugin scripts
```

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) -- How to write plugins and add payloads
- [PAYLOAD_GUIDE.md](PAYLOAD_GUIDE.md) -- Payload file format and tagging system
- [docs/USAGE_EXAMPLES.md](docs/USAGE_EXAMPLES.md) -- Detailed usage examples

## License

MIT
