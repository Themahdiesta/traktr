# PROMPT_MASTER.md: TRAKTR -- ULTIMATE AI INSTRUCTION SET
# Target: Claude Opus 4.6 / Advanced AI Code Generator
# Project: TRAKTR - Intelligent Web Pentest Orchestrator ("#1 Forever Tool")
# Version: 2.0 -- Full Coverage Edition

## YOUR ROLE
You are a senior cybersecurity automation architect with 20+ years of offensive security experience. You specialize in Bash tool orchestration, parallel execution, heuristic vulnerability validation, and building production-grade, extensible pentest frameworks.

## PROJECT GOAL
Build "Traktr" - a meta-tool that:
```
User runs: traktr https://target.com [options]
     -OR-: traktr -r burp_request.txt [options]
Tool does: Crawl -> Enumerate -> Discover Params -> Detect Secrets -> Vuln Scan -> Smart LFI -> Report
Result:    Actionable, reproducible, OSCP-safe findings with exact PoC commands
```

**NO ACTUAL AI/LLM CALLS.** "Intelligence" = deterministic rule engines, heuristic scoring, response diffing, and adaptive payload routing.

---

## CORE PRINCIPLES (NON-NEGOTIABLE)
1. **Orchestrate existing tools** (katana, ffuf, nuclei, httpx, gau, waybackurls, arjun, dalfox, commix, subfinder)
2. **Parallel execution** with concurrency limits (default: 20 threads)
3. **Confidence scoring** over volume (require multi-signal validation before flagging)
4. **Actionable output** (every finding = exact curl command + CVSS + remediation)
5. **Extensible** via plugin system & config-driven behavior
6. **OSCP-Compliant Defaults**: No auto-exploitation, no auto-verification, safe payloads only
7. **Resilient**: graceful error handling, retry/backoff, signal traps, resume capability
8. **Scope-enforced**: Never touch out-of-scope targets, ever
9. **Burp-native**: Accept raw Burp requests as input, auto-parse everything
10. **Full enumeration**: Every parameter, every hidden field, every secret, every path

---

## INPUT MODES

### Mode 1: URL Target (standard)
```
traktr https://target.com [options]
```

### Mode 2: Burp Request Import (authenticated/complex)
```
traktr -r request.txt [options]
```

**Burp Request Parser (`parse_burp_request()`) must auto-extract:**
- Target host + protocol (from Host header + request line)
- HTTP method (GET/POST/PUT/DELETE/PATCH/OPTIONS)
- Full URL path with query parameters
- All headers (Cookie, Authorization, X-CSRF-Token, Content-Type, custom headers)
- Request body (form-data, JSON, XML, multipart -- detect automatically)
- All parameters from ALL sources:
  - URL query string params
  - POST body params (form-urlencoded, JSON keys, XML elements)
  - Cookie name=value pairs (each cookie is a testable param)
  - Custom header values that look dynamic (tokens, session IDs)
- Content-Type to determine payload encoding (JSON payloads for JSON bodies, XML for XML, etc.)
- Authentication type auto-detect:
  - `Cookie: session=` -> cookie-based auth
  - `Authorization: Bearer` -> JWT/token auth
  - `Authorization: Basic` -> basic auth
  - Custom auth headers -> replay as-is

**How it works:** User intercepts any request in Burp, right-click -> Copy to file -> `traktr -r request.txt`. Traktr replays that exact request context for every test, maintaining session state. This is the **killer feature** -- zero config authenticated scanning.

### Mode 3: Multi-Request Pipeline
```
traktr -r requests_dir/ [options]
```
Process a directory of Burp request files, dedupe endpoints, merge auth context.

---

## FULL FLAG REFERENCE
```
traktr <target|url> [flags]

TARGET:
  -r, --request FILE|DIR    Import Burp Suite request file(s)
  -u, --url URL             Target URL (alternative to positional arg)
  --scope REGEX|FILE        Restrict scanning to matching URLs only

AUTH:
  --auth USER:PASS          HTTP Basic auth
  --cookie "name=val"       Custom cookie(s)
  --header "Name: Value"    Custom header(s) (repeatable)
  --token BEARER_TOKEN      Shorthand for Authorization: Bearer

SCAN CONTROL:
  --stealth                 Random delays, UA rotation, referer spoofing
  --oscp                    Safe mode: no destructive payloads, request logging, rate-limited
  --aggressive              Max depth, all payloads, higher concurrency
  --lfi-only                Run only the LFI detection engine
  --param-only              Run only parameter discovery
  --secrets-only            Run only secret scanning
  --skip-lfi                Skip LFI module
  --skip-nuclei             Skip nuclei scanning
  --threads N               Concurrency limit (default: 20)
  --rate N                  Max requests/second (default: unlimited, stealth: 10)
  --depth N                 Crawl depth (default: 5, aggressive: 10)
  --timeout N               Per-request timeout in seconds (default: 10)

OUTPUT:
  --output DIR              Custom output directory (default: scan_results/<target>_<timestamp>/)
  --json                    NDJSON output stream to stdout
  --quiet                   Suppress banner and progress, output findings only
  --debug                   Verbose logging to logs/debug.log

STATE:
  --resume STATE_FILE       Resume interrupted scan from state checkpoint
  --dry-run                 Show what would execute without running anything
```

---

## PROJECT STRUCTURE
```
traktr/
├── src/
│   ├── core/
│   │   ├── installer.sh          # Phase 1: Tool installer + payload manager
│   │   ├── traktr.sh             # Phase 2: Main orchestrator loop
│   │   └── request_parser.sh     # Phase 2: Burp request parser + auth handler
│   ├── intel/
│   │   ├── brain.sh              # Phase 3: Framework detect + payload select + validation
│   │   ├── lfi_engine.sh         # Phase 3: Smart LFI detection engine
│   │   ├── param_miner.sh        # Phase 3: Deep parameter discovery
│   │   └── secret_scanner.sh     # Phase 3: Secret/credential scanner
│   └── utils/
│       ├── scope_guard.sh        # Scope enforcement + ban detection
│       ├── reporter.sh           # Report generation (MD, JSON, HTML)
│       └── helpers.sh            # Logging, colors, common functions
├── plugins/                      # Drop-in .sh plugins
├── payloads/
│   ├── lfi/                      # LFI payloads (unix, windows, wrappers, bypass)
│   ├── sqli/                     # SQL injection
│   ├── xss/                      # Cross-site scripting
│   ├── rce/                      # Remote code execution
│   ├── ssrf/                     # Server-side request forgery
│   ├── xxe/                      # XML external entity
│   ├── auth/                     # Authentication bypass
│   ├── api/                      # API-specific payloads
│   ├── secrets/                  # Secret detection regex patterns
│   ├── params/                   # Parameter wordlists
│   ├── framework/                # Framework-specific payloads
│   └── waf_bypass/               # WAF evasion encodings
├── config/
│   ├── traktr.json               # Main config (renamed from .conf)
│   └── requirements.txt          # Tool version requirements
├── wordlists/                    # Bundled wordlists for param mining
├── scan_results/                 # Per-scan output directories
├── logs/                         # Debug + request logs
├── tests/                        # Test scripts
├── docs/
│   ├── USAGE_EXAMPLES.md
│   ├── CONTRIBUTING.md
│   └── PAYLOAD_GUIDE.md
├── .github/workflows/test.yml
├── Dockerfile
├── README.md
└── PROMPT_MASTER.md
```

---

## BUILD STRATEGY: ITERATIVE MODULAR PROMPTING
Complete ONE phase per response. Do not skip ahead.

---

### PHASE 1: INSTALLER (src/core/installer.sh)

**TASK:** Build ONLY the installer.

**REQUIREMENTS:**
1. Detect OS (Kali/Ubuntu/Debian/Arch/macOS), set package manager
2. Install Go 1.21+ if missing (from official tarball)
3. Install tools from source via `go install`:
   - katana, ffuf, nuclei, httpx, gau, subfinder, waybackurls, dalfox
4. Install pip tools: arjun, commix
5. Install system tools if missing: jq, curl, chromium (for headless crawl)
6. Update nuclei templates: `nuclei -update-templates`
7. Shallow-clone payload repos into `~/.traktr/payloads/`:
   - PayloadsAllTheThings, SecLists, fuzzdb
8. Organize payloads by symlinking relevant files to `payloads/{type}/`
9. Create bundled wordlists in `wordlists/`:
   - `params_common.txt` (top 2000 parameter names)
   - `dirs_common.txt` (merged raft-medium + common.txt)
10. Verify every installation, output version table
11. Create `~/.traktr/` config directory, copy default config

**FLAGS:** `--dry-run`, `--repair` (reinstall broken tools), `--upgrade` (update all)

**ERROR HANDLING:**
- Each install wrapped in retry (3 attempts)
- Skip already-installed tools (check `which` + version)
- Log all actions to `logs/install.log`
- Exit with summary: installed/skipped/failed counts

**TARGET:** ~120 lines, clean functions, idempotent

**OUTPUT:** Single code block + key decisions (3-5 bullets) + testing tip + Phase 2 preview

---

### PHASE 2: CORE ORCHESTRATOR + REQUEST PARSER

**TASK:** Build main scan loop + Burp request parser.

**FILE 1: `src/core/traktr.sh` (main entry point)**

**INPUT:**
```
traktr <target> [flags]
traktr -r request.txt [flags]
```

**EXECUTION PIPELINE (in order):**

```
STEP 0: INIT
├── Parse flags, load config (jq parse traktr.json)
├── If -r: call parse_burp_request() → extract target + auth + params
├── Validate target (DNS resolves, responds to HTTP)
├── Init logging, create output dir: scan_results/<target>_<YmdHMS>/
├── Enforce scope (if --scope provided)
├── Start request logger (if --oscp)
└── Trap signals (SIGINT/SIGTERM → save state → cleanup → exit)

STEP 1: RECONNAISSANCE (parallel)
├── WAF/CDN Detection:
│   ├── Send known-bad request, fingerprint response headers
│   ├── Check: cf-ray (Cloudflare), x-sucuri-id, server: AkamaiGHost, etc.
│   └── Output: waf_detected={cloudflare|akamai|sucuri|modsecurity|none}
├── Tech Stack Fingerprint:
│   ├── httpx -tech-detect on target
│   ├── Check response headers: X-Powered-By, Server, X-AspNet-Version
│   └── Output: tech_stack.json
└── SSL/TLS check (if https): testssl.sh --quiet basic checks

STEP 2: DEEP CRAWL (parallel, merge results)
├── katana -jc -d $DEPTH -js-crawl -known-files all $TARGET
├── katana -headless -d 3 $TARGET (if chromium available)
├── gau --threads 5 $TARGET
├── waybackurls $TARGET
├── Parse robots.txt → extract Disallow paths → add to targets
├── Parse sitemap.xml → extract URLs → add to targets
├── ffuf directory brute: wordlists/dirs_common.txt → $TARGET/FUZZ
├── Extract links from non-HTML responses (JSON, XML, CSV)
├── MERGE: Sort + dedupe by normalized URL → all_endpoints.txt
├── SCOPE CHECK: Filter all_endpoints.txt through scope_guard
└── METRICS: Log total_found, per_source_count, unique_per_source

STEP 3: ENDPOINT PROBING
├── httpx -status-code -title -tech-detect -content-length -json < all_endpoints.txt
├── Output: probed.json (one JSON object per line)
├── Filter: Remove 404s, group by status code
├── Flag interesting: 401/403 (access control), 301/302 (redirects), 500 (errors)
└── Extract: response headers + body snippets for brain.sh analysis

STEP 4: DEEP PARAMETER DISCOVERY (parallel, merge results)
├── SOURCE 1 - Arjun active brute:
│   arjun -u URL -t 20 --stable (for top 50 endpoints)
├── SOURCE 2 - HTML form parsing (custom):
│   Extract from probed responses:
│   - All <input> (including type="hidden"), <select>, <textarea>
│   - name=, id=, data-param=, data-field= attributes
│   - <form action=""> → discover new endpoints
│   - Disabled fields (name + value)
│   - JavaScript-set: .value=, setAttribute("name"
├── SOURCE 3 - JS static analysis (custom):
│   Fetch all .js files found in crawl, extract:
│   - fetch()/XMLHttpRequest/axios URL patterns → params
│   - Object keys in request bodies
│   - URLSearchParams construction
│   - GraphQL query field names
│   - Hardcoded API endpoints
├── SOURCE 4 - Historical params:
│   From gau/waybackurls output, extract unique ?key= patterns
├── SOURCE 5 - Burp request params:
│   If -r mode, include all params from request file
├── MERGE: Normalize (lowercase), dedupe, tag source
│   Format: endpoint|param_name|source|method|sample_value
│   Priority: found_in_2+_sources = HIGH
└── OUTPUT: active_params.txt

STEP 4.5: SECRET SCANNING (parallel with step 4)
├── Scan all fetched JS files, HTML responses, JSON API responses
├── Pattern matching (see SECRET PATTERNS section below)
├── Scan HTML comments: <!-- ... -->
├── Scan inline scripts: <script>...</script>
├── Scan error pages (500s often leak stack traces, paths, versions)
├── Confidence: CONFIRMED (known format match) / POSSIBLE (partial match)
└── OUTPUT: secrets.json + alert to terminal immediately on HIGH findings

STEP 5: VULNERABILITY TESTING (parallel, max $THREADS)
├── Source brain.sh for framework detection + payload selection
├── NUCLEI: nuclei -l probed_urls.txt -severity medium,high,critical -json
├── LFI ENGINE: lfi_engine.sh against all params with path-like names
│   (file, path, page, include, template, doc, folder, pg, view, load,
│    read, content, document, root, dir, resource, prefix, filename,
│    download, data, src, conf, log, start, url, action, cat, type)
├── XSS: dalfox pipe -l endpoints_with_params.txt --skip-bav (if --oscp)
├── COMMAND INJECTION: commix --batch --level 1 (if --oscp, else --level 3)
├── SSRF: Custom test with callback canary (interact.sh-style or Burp Collaborator)
├── OPEN REDIRECT: Test redirect/url/next/return/goto params with external URL
├── For each finding: call validate_finding() for multi-signal confirmation
├── BAN DETECTION: Monitor responses during testing (see BAN DETECTION below)
└── OUTPUT: raw_findings.json

STEP 6: REPORTING
├── Deduplicate findings by (endpoint, param, vuln_type)
├── Score confidence: HIGH (multi-signal) / MEDIUM (single strong) / LOW (heuristic only)
├── Filter by config confidence_threshold
├── Generate:
│   ├── REPORT.md (human-readable, grouped by severity)
│   ├── findings.json (machine-readable, full detail)
│   ├── poc_commands.txt (one curl command per finding, copy-paste ready)
│   ├── secrets.json (if secrets found)
│   └── scan_summary.txt (stats: time, requests, findings by severity)
├── Print summary to terminal with colors
└── If --json: stream NDJSON to stdout during entire scan
```

**CRITICAL REQUIREMENTS:**
- Bash job control: `&` + `wait` for parallel steps, `xargs -P` for per-URL parallelism
- `--stealth`: random delay (0-2s), UA rotation (50+ user agents), referer spoofing, rate limit
- `--oscp`: skip destructive payloads, log every request, rate-limit to 50/s, add "POTENTIAL" prefix to all findings
- State checkpoint after each step → enables `--resume`
- Every external tool call wrapped in timeout + retry (3x with backoff)
- Source brain.sh for intelligent decisions throughout

**FILE 2: `src/core/request_parser.sh`**

```
FUNCTION: parse_burp_request(file)
INPUT: Raw HTTP request file (as copied from Burp Suite)

PARSE STEPS:
1. Line 1: Extract METHOD, PATH, HTTP_VERSION
   "POST /api/v2/users?role=admin HTTP/1.1" → method=POST, path=/api/v2/users, query=role=admin
2. Headers: Read until empty line
   Store as associative array: HEADERS[Host]=target.com, HEADERS[Cookie]=session=abc123, etc.
3. Body: Everything after the empty line
   Auto-detect body type:
   - application/x-www-form-urlencoded → parse key=value&key2=value2
   - application/json → extract keys with jq
   - multipart/form-data → parse boundaries, extract field names
   - text/xml or application/xml → extract element/attribute names
4. Reconstruct target URL: ${protocol}://${HEADERS[Host]}${path}
5. Build curl replay command with ALL original headers + body
6. Extract testable params from ALL sources into unified list

OUTPUT VARIABLES (exported):
  BURP_TARGET, BURP_METHOD, BURP_HEADERS[], BURP_COOKIES[],
  BURP_BODY, BURP_BODY_TYPE, BURP_PARAMS[], BURP_QUERY_PARAMS[],
  BURP_AUTH_TYPE, BURP_CURL_BASE (base curl command for replay)

SMART FEATURES:
- Auto-detect if request is to API endpoint (JSON body, /api/ path, Accept: application/json)
- If API detected: switch to JSON payload injection (wrap payloads in JSON values)
- Auto-detect CSRF token headers/params → extract and auto-refresh on each request
- If cookie contains JWT: decode header+payload, flag expiry, extract claims as context
- Handle multiline headers (continuation lines starting with whitespace)
- Strip Burp-added headers (X-Burp-*, Proxy-Connection)
```

**TARGET:** traktr.sh ~300 lines, request_parser.sh ~100 lines
**OUTPUT:** Code blocks + parallelization strategy + Phase 3 preview

---

### PHASE 3: INTELLIGENCE MODULES

**TASK:** Build brain.sh + lfi_engine.sh + param_miner.sh + secret_scanner.sh

**FILE 1: `src/intel/brain.sh` (~150 lines)**

```
FUNCTION: detect_framework(response_headers, response_body)
  DETECTION RULES:
  - X-Powered-By: PHP → check for wp-content|wp-includes → wordpress
  - X-Powered-By: Express → node/express
  - Server: Apache + .php extensions → php/generic
  - Server: nginx + X-Powered-By missing → check body for Django CSRF, Rails meta tags
  - csrfmiddlewaretoken in forms → django
  - __VIEWSTATE in forms → asp.net
  - laravel_session cookie → laravel
  - JSESSIONID cookie → java/spring
  - _rails meta tags → ruby on rails
  - cf- headers → cloudflare (WAF layer)
  RETURN: framework name string

FUNCTION: select_payloads(vuln_type, framework, waf_detected)
  LOGIC:
  - Base: payloads/{vuln_type}/*.txt
  - If framework known: prepend payloads/framework/{framework}_{vuln_type}.txt
  - If WAF detected: wrap each payload through payloads/waf_bypass/{waf}_encode.sh
  - If --oscp: filter out destructive payloads (tagged with #DESTRUCTIVE comment)
  RETURN: newline-separated file paths

FUNCTION: validate_finding(url, param, vuln_type, response, baseline_response)
  MULTI-SIGNAL VALIDATION (require 2+ signals to confirm):
  Signals:
  - CONTENT_MATCH: Response contains expected vuln signature
    - LFI: "root:x:0:", "[extensions]", "boot loader"
    - XSS: reflected payload in response body (exact match, not encoded)
    - SQLi: SQL error string (mysql_fetch, ORA-01756, syntax error, SQLSTATE)
    - RCE: command output pattern (uid=, whoami output, specific canary string)
    - SSRF: callback received / internal IP in response
  - LENGTH_DELTA: |response_length - baseline_length| > 200 bytes
  - STATUS_CHANGE: HTTP status differs from baseline (200→500 = error-based signal)
  - TIME_DELTA: Response time > 2x baseline (blind/time-based signal)
  - HEADER_CHANGE: New headers appear (X-Debug, Server change, error headers)
  SCORING:
  - 3+ signals → HIGH confidence
  - 2 signals → MEDIUM confidence
  - 1 signal → LOW confidence (log but don't report unless aggressive mode)
  - 0 signals → FALSE_POSITIVE (discard)
  RETURN: HIGH|MEDIUM|LOW|FALSE_POSITIVE

FUNCTION: suggest_next_step(vuln_type, vuln_details)
  CHAINING LOGIC:
  - LFI found → suggest: "Read /etc/shadow, /proc/self/cmdline, app source code"
  - LFI + PHP → suggest: "Try php://filter for source, data:// for RCE, log poisoning"
  - SQLi found → suggest: "Enumerate databases, try UNION-based extraction, check for stacked queries"
  - XSS found → suggest: "Test for stored XSS, check CSP headers, try DOM-based"
  - RCE found → suggest: "Confirm with sleep-based, try reverse shell (manual only)"
  - SSRF found → suggest: "Scan internal ports, access cloud metadata (169.254.169.254)"
  - Auth bypass → suggest: "Check IDOR on other endpoints, test privilege escalation"
  RETURN: recommendation string

FUNCTION: encode_payload(payload, encoding_type)
  TYPES: url, double-url, base64, hex, unicode, html-entity, null-byte-append
  Chainable: encode_payload "$(encode_payload "$p" url)" url → double URL encoding
  RETURN: encoded string

FUNCTION: build_curl_command(url, method, headers_array, body, payload_param, payload_value)
  Build a complete, copy-paste-ready curl command with:
  - Correct method (-X POST)
  - All auth headers (-H "Cookie: ..." -H "Authorization: ...")
  - Payload injected into correct parameter
  - URL-encoded where needed
  - Timeout and follow-redirect flags
  RETURN: curl command string (for poc_commands.txt)
```

**FILE 2: `src/intel/lfi_engine.sh` (~120 lines)**

```
FUNCTION: detect_lfi(url, param, method, auth_headers)

STRATEGY:
  STEP 1 - BASELINE:
    Request with param=traktr_canary_value (innocent value)
    Capture: baseline_status, baseline_length, baseline_hash, baseline_time

  STEP 2 - TRAVERSAL SPRAY (escalating aggressiveness):
    Level 1 - Basic traversal (always run):
      ../../../../etc/passwd
      ../../../../etc/hosts
      ../../../../windows/win.ini
      /etc/passwd (absolute)

    Level 2 - Encoded traversal:
      ..%2f..%2f..%2f..%2fetc/passwd (single URL encode)
      %2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd (full encode)
      ..%252f..%252f..%252fetc/passwd (double URL encode)
      ..%c0%af..%c0%af..%c0%afetc/passwd (overlong UTF-8)
      ....//....//....//etc/passwd (double-dot bypass)
      ..;/..;/..;/etc/passwd (semicolon bypass - Tomcat/Java)

    Level 3 - Null byte + truncation:
      ../../../../etc/passwd%00 (null byte - PHP < 5.3.4)
      ../../../../etc/passwd%00.html (null byte + extension)
      ../../../../etc/passwd....[x256] (path truncation)
      ../../../../etc/passwd\0 (literal null)

    Level 4 - PHP wrappers (if PHP detected):
      php://filter/convert.base64-encode/resource=/etc/passwd
      php://filter/read=string.rot13/resource=/etc/passwd
      php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd
      php://input (with POST body)
      data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
      expect://id (if expect:// enabled)
      phar:// (deserialization vector)
      zip:// (archive inclusion)

    Level 5 - OS-specific deep paths:
      /proc/self/environ (environment variables)
      /proc/self/cmdline (process command line)
      /proc/self/fd/0-9 (file descriptors)
      /proc/version (kernel version)
      /var/log/apache2/access.log (log poisoning vector)
      /var/log/nginx/access.log
      /var/log/auth.log
      C:\Windows\System32\drivers\etc\hosts (Windows)
      C:\inetpub\wwwroot\web.config (IIS)
      WEB-INF/web.xml (Java - path without traversal)

    Level 6 - WAF bypass chains (if WAF detected):
      Use encoding chains from payloads/waf_bypass/
      Combine: double-encode + null-byte + case variation
      Alternate separators: ..\..\..\ (backslash), ..0x2f (hex dot)

  STEP 3 - DETECTION (multi-signal, ANY 2 = CONFIRMED):
    Signal A: Response body contains file signature:
      - "root:x:0:" or "root:*:0:" (unix passwd)
      - "[extensions]" or "[fonts]" (windows win.ini)
      - "boot loader" (windows boot.ini)
      - "PD9" or "<?php" (PHP source via wrapper)
      - "/usr/sbin" or "/bin/bash" (environ/cmdline)
    Signal B: Content-length delta > 200 bytes from baseline
    Signal C: Response time > 2x baseline (file I/O delay)
    Signal D: Status code change (200→500 = path error, 200→403 = WAF block)
    Signal E: New response headers appear (X-Debug, error-related)

  STEP 4 - DEPTH ESCALATION:
    If confirmed: test depth 1 through 15 to find minimum working depth
    If PHP wrapper works: attempt to read application source code
    If log file readable: flag log poisoning potential (manual exploit)

  STEP 5 - OUTPUT:
    For each confirmed LFI:
    {
      "url": "...",
      "param": "...",
      "method": "GET",
      "depth": 7,
      "encoding": "double-url",
      "payload": "..%252f..%252fetc/passwd",
      "signal_count": 3,
      "signals": ["content_match", "length_delta", "status_change"],
      "confidence": "HIGH",
      "proof_snippet": "root:x:0:0:root:/root:/bin/bash",
      "curl_command": "curl -H 'Cookie: ...' 'https://target.com/page?file=..%252f..%252fetc/passwd'",
      "next_steps": ["Read /etc/shadow", "Try PHP filter for source code", "Check log poisoning"]
    }

CONSTRAINTS:
  - Max 50 requests per param per level (abort level on 3 consecutive non-signals)
  - Skip to next level if current level yields no signals after 10 payloads
  - --oscp: Skip Level 4 write payloads (data://, expect://), max Level 3
  - Respect --rate and --stealth settings
  - All requests through scope_guard
```

**FILE 3: `src/intel/param_miner.sh` (~100 lines)**

```
FUNCTION: mine_params(endpoints_file, js_files_list, html_responses_dir)

SOURCE 1 - ARJUN ACTIVE BRUTE:
  For top 50 most interesting endpoints (by response diversity):
  arjun -u $URL -t 20 --stable --json -oJ arjun_results.json
  Extract: param_name, param_type (GET/POST/JSON), evidence

SOURCE 2 - HTML FORM EXTRACTION:
  Parse all HTML responses for:
  - <input name="X"> (all types, especially hidden)
  - <input type="hidden" name="X" value="Y"> → flag as hidden_param
  - <select name="X"> <option value="Y">
  - <textarea name="X">
  - <button name="X" value="Y">
  - disabled="disabled" fields → still testable if enabled
  - data-* attributes on form elements and interactive components
  - <form action="URL" method="POST"> → new endpoint discovery
  - JavaScript-set values: .value=, setAttribute("name", ...)

SOURCE 3 - JS STATIC ANALYSIS:
  Fetch all unique .js URLs, then grep for:
  - /api/[^\s'"]+/ patterns → new API endpoints
  - fetch\(['"]([^'"]+)['"] → URLs called by JS
  - XMLHttpRequest.*open\(['"](\w+)['"],\s*['"]([^'"]+) → method + URL
  - axios\.(get|post|put|delete)\(['"]([^'"]+) → method + URL
  - URLSearchParams.*append\(['"](\w+) → param names
  - \?(\w+)= and &(\w+)= patterns → query param names
  - JSON\.stringify\(\{([^}]+)\}\) → object key names as body params
  - ["'](\w+)["']\s*:\s* in object literals near fetch/ajax calls → JSON body params
  - graphql.*query.*\{([^}]+)\} → GraphQL field names
  - \.env\.|process\.env\.|config\. → configuration keys (also flag as potential secrets)

SOURCE 4 - HISTORICAL PARAMS:
  From gau/waybackurls output:
  - Extract all unique ?key= and &key= parameter names
  - Extract path patterns: /api/v{N}/resource/{id} → id is a param
  - Dedupe with current discoveries

SOURCE 5 - WORDLIST BRUTE (for high-value endpoints):
  If endpoint returns different responses for valid vs invalid params:
  Brute with wordlists/params_common.txt (top 2000 params)
  Method: append ?param=traktr_canary, check if response differs from baseline

SOURCE 6 - BURP REQUEST PARAMS (if -r mode):
  All params already extracted by request_parser.sh
  These get HIGHEST priority (user explicitly tested this request)

MERGE + DEDUP:
  Normalize: lowercase param names, merge duplicates
  Tag each param: source, method (GET/POST/JSON/HEADER/COOKIE), priority
  Priority scoring: found_in_3+_sources=CRITICAL, 2_sources=HIGH, 1_source=MEDIUM
  Special flag: params with names suggesting file ops get routed to LFI engine
    (file, path, page, include, template, doc, load, read, dir, resource, filename,
     download, src, conf, log, url, action, cat, type, view, content, folder, prefix)

OUTPUT: active_params.txt
  Format: endpoint|param_name|method|source_list|priority|sample_value|notes
```

**FILE 4: `src/intel/secret_scanner.sh` (~80 lines)**

```
FUNCTION: scan_secrets(files_list)

INPUT: List of files (fetched JS, HTML, JSON responses, error pages)

PATTERNS (regex, loaded from payloads/secrets/patterns.txt):
  # Cloud Provider Keys
  AWS Access Key:          AKIA[0-9A-Z]{16}
  AWS Secret Key:          (?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]
  GCP API Key:             AIza[0-9A-Za-z\-_]{35}
  Azure Storage Key:       (?i)AccountKey=[0-9a-zA-Z/+=]{86}==

  # API Keys & Tokens
  GitHub Token:            gh[ps]_[A-Za-z0-9_]{36,}
  GitLab Token:            glpat-[A-Za-z0-9\-]{20,}
  Slack Token:             xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}
  Stripe Key:              [rs]k_(live|test)_[A-Za-z0-9]{20,}
  Twilio:                  SK[a-f0-9]{32}
  SendGrid:                SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}
  Mailgun:                 key-[0-9a-zA-Z]{32}
  Firebase:                AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}

  # Authentication
  JWT:                     eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*
  Basic Auth (base64):     Basic [A-Za-z0-9+/]{10,}={0,2}
  Bearer Token:            Bearer [A-Za-z0-9_\-\.]{20,}
  Private Key:             -----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----

  # Generic Secrets
  API Key Assignment:      (?i)(api[_-]?key|apikey|api[_-]?secret)[\s]*[=:]\s*['\"][^\s'"]{8,}
  Password Assignment:     (?i)(password|passwd|pwd|pass)[\s]*[=:]\s*['\"][^\s'"]{4,}
  Token Assignment:        (?i)(token|secret|access[_-]?key)[\s]*[=:]\s*['\"][^\s'"]{8,}
  Connection String:       (?i)(mysql|postgres|mongodb|redis|amqp)://[^\s'"]{10,}

  # Infrastructure
  Internal IP:             https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[^\s'"]+
  Internal Hostname:       (?i)https?://[a-z0-9-]+\.(internal|local|corp|intranet|dev)[^\s'"]*
  S3 Bucket:               [a-z0-9.-]+\.s3\.amazonaws\.com
  Heroku API:              [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}

  # Code Comments (often leak info)
  TODO/FIXME with secrets:  (?i)(TODO|FIXME|HACK|XXX|BUG).*?(password|key|token|secret|cred)
  HTML Comments:           <!--[\s\S]*?(password|key|token|secret|admin|config|debug)[\s\S]*?-->

CONFIDENCE:
  - CONFIRMED: Matches known format exactly (AWS key format, JWT structure)
  - HIGH: Matches generic pattern + looks like real value (not placeholder/example)
  - POSSIBLE: Matches loose pattern (could be false positive)
  Filter out known false positives: "example", "test", "placeholder", "xxx", "your_key_here"

OUTPUT: secrets.json
  [{
    "type": "aws_access_key",
    "value_redacted": "AKIA****EXAMPLE",
    "full_value": "AKIA...", (only in local output, never transmitted)
    "location": "https://target.com/js/config.js:line42",
    "confidence": "CONFIRMED",
    "context": "var AWS_KEY = 'AKIA...'"
  }]

  On CONFIRMED findings: immediate terminal alert (red, bold)
  OSCP-SAFE: Log everything, never use/exfiltrate found credentials
```

**FILE 5: `src/utils/scope_guard.sh` (~60 lines)**

```
FUNCTION: init_scope(target, scope_arg)
  - Extract base domain from target URL
  - If --scope provided (regex or file): load patterns
  - Default scope: target domain + subdomains only

FUNCTION: check_scope(url)
  - Parse domain from URL
  - Check against allowed scope patterns
  - REJECT and log if out of scope
  - WARN if redirect detected to different domain
  RETURN: 0 (in scope) or 1 (out of scope)

FUNCTION: ban_detector(status_code, response_headers, response_body)
  DETECT:
  - 429 Too Many Requests → auto_throttle: double current delay, max 10s
  - 503 with retry-after → sleep for specified duration
  - 403 + WAF signature (Cloudflare challenge page, "Request blocked") → switch to evasion mode
  - CAPTCHA signatures: recaptcha, hcaptcha, cf-challenge → PAUSE + warn user
  - 10 consecutive non-200 responses → pause 30s, retry 3x, then skip endpoint
  ACTIONS:
  - Log all throttle/block events to logs/evasion.log
  - Auto-adjust rate when throttled
  - Notify user when WAF blocks are interfering with results
  RETURN: "continue" | "throttle" | "skip" | "abort"
```

**FILE 6: `src/utils/helpers.sh` (~60 lines)**

```
FUNCTIONS:
  log(level, message) → timestamped log to file + conditional terminal output
  log_request(method, url, status) → OSCP request log (every request made)
  color_print(color, message) → terminal output with ANSI colors
  banner() → Traktr ASCII art banner + version
  check_tool(name) → verify tool is installed + return version
  retry(max, delay, command) → retry with exponential backoff
  url_encode(string) → percent-encode
  url_decode(string) → percent-decode
  normalize_url(url) → strip fragments, sort params, lowercase scheme+host
  random_ua() → return random User-Agent from bundled list
  save_state(step, data) → checkpoint for --resume
  load_state(file) → restore from checkpoint
  temp_file(prefix) → mktemp in scan output dir (auto-cleanup on exit)
```

**TARGET:** brain.sh ~150 lines, lfi_engine.sh ~120 lines, param_miner.sh ~100 lines, secret_scanner.sh ~80 lines, scope_guard.sh ~60 lines, helpers.sh ~60 lines
**OUTPUT:** Code blocks + integration example + Phase 4 preview

---

### PHASE 4: PLUGIN SYSTEM + PRODUCTION POLISH

**TASK:** Make extensible & production-ready.

**ADD:**
1. **Plugin loader** (auto-load `plugins/*.sh`):
   - Hooks: `pre_scan`, `post_discovery`, `post_params`, `on_vuln_found`, `post_scan`
   - Plugin contract: must export `run_plugin(endpoint, context)`
   - Output format: `SEVERITY|TYPE|ENDPOINT|PAYLOAD|CONFIDENCE|PROOF_BASE64`
   - Sandboxed: plugins cannot modify core state, only append to findings

2. **JSON output stream** (`--json` flag):
   - NDJSON to stdout (one JSON object per event)
   - Event types: `scan_start`, `endpoint_found`, `param_found`, `secret_found`, `vuln_found`, `scan_complete`
   - Pipeable: `traktr target.com --json | jq '.type == "vuln_found"'`

3. **Resume capability** (`--resume`):
   - State saved after each step as `.traktr_state_<timestamp>.json`
   - Contains: completed steps, discovered endpoints, params, partial findings
   - On resume: skip completed steps, continue from last checkpoint

4. **HTML Report** (alongside REPORT.md):
   - Self-contained single HTML file with inline CSS
   - Sortable/filterable findings table
   - Expandable PoC sections with curl commands
   - Executive summary with risk chart

5. **Dockerfile** (multi-stage, minimal):
   - Stage 1: Go builder (install Go tools)
   - Stage 2: Runtime (Kali-slim base, copy Go binaries, pip install, add traktr)
   - Entrypoint: traktr

6. **GitHub Actions** (`.github/workflows/test.yml`):
   - Lint: shellcheck on all .sh files
   - Test: run against DVWA/juice-shop in container
   - Build: Docker image

7. **Docs:**
   - Update README.md with full usage, examples, badges
   - CONTRIBUTING.md (how to write plugins, add payloads)
   - PAYLOAD_GUIDE.md (payload format, tagging system)

**OUTPUT:** All files + "Traktr v1.0 Complete!" message

---

## SMART EASY WINS (integrated above, listed here for reference)

These are low-effort, high-impact features already embedded in the design:

| Feature | What It Does | Where |
|---------|-------------|-------|
| **Burp request import** | `traktr -r request.txt` -- zero-config auth scanning | request_parser.sh |
| **CSRF token auto-refresh** | Detect CSRF tokens, re-fetch before each request | request_parser.sh |
| **JWT decode** | Auto-decode JWT from cookies/headers, flag expiry | request_parser.sh |
| **API auto-detect** | If JSON body/API path detected, switch to JSON payloads | brain.sh |
| **Hidden field extraction** | Parse all type="hidden" inputs as testable params | param_miner.sh |
| **Error page mining** | Scan 500 error responses for leaked paths/versions | secret_scanner.sh |
| **Instant alerts** | Print HIGH findings to terminal immediately, don't wait for report | helpers.sh |
| **Request logging** | Full OSCP-compliant request log for exam proof | helpers.sh |
| **Auto-throttle** | Detect 429/block, automatically reduce speed | scope_guard.sh |
| **Smart LFI param routing** | Auto-route params named "file/path/include" to LFI engine | param_miner.sh |
| **Depth auto-escalation** | If LFI works at depth 4, auto-test depths 1-15 for minimum | lfi_engine.sh |
| **PHP wrapper chain** | If PHP detected + LFI confirmed, auto-test filter chains | lfi_engine.sh |
| **Copy-paste PoCs** | Every finding includes exact curl command to reproduce | brain.sh |
| **WAF-adaptive payloads** | Detect WAF → auto-apply encoding bypass chains | brain.sh |
| **Multi-request dir mode** | `traktr -r requests_dir/` -- batch scan from Burp export | request_parser.sh |

---

## SECRET PATTERN FILE (payloads/secrets/patterns.txt)
To be generated in Phase 1 installer as a structured regex file.

## PARAM WORDLIST (wordlists/params_common.txt)
To be generated/downloaded in Phase 1 installer. Top 2000 web parameter names.

---

## OSCP-COMPLIANCE CHECKLIST
- [ ] `--oscp` flag enables all safety controls
- [ ] Never auto-exploit (output PoC commands for manual execution)
- [ ] Every request logged with timestamp to `logs/requests.log`
- [ ] Rate-limited to 50 req/s in OSCP mode
- [ ] Scope-enforced: won't follow redirects to other domains
- [ ] Destructive payloads tagged and filtered out
- [ ] Findings prefixed with "POTENTIAL" -- never claim confirmed exploitation
- [ ] commix limited to `--level 1`
- [ ] dalfox uses `--skip-bav` (skip blind automated verification)
- [ ] All output timestamped and reproducible

---

## CONSTRAINTS (STRICT)
- Bash 4.0+ compatible (associative arrays required)
- Zero interactive prompts (unless --interactive)
- All output to scan_results/ or logs/
- Graceful error handling: set -euo pipefail + trap ERR
- jq required for JSON parsing (installed by installer)
- Respect target limits in stealth/OSCP modes
- NEVER auto-exploit or auto-verify with destructive methods
- Config is JSON (parsed with jq), not bash-sourceable

---

## OUTPUT FORMAT (Per Phase)
1. Code Block (single, complete, ready-to-save per file)
2. Key Decisions (3-5 bullets)
3. Testing Tip (one command to verify)
4. Next Phase Preview (what's coming)
5. Clarifying Question for user

---

## AUDIT & REMINDER DIRECTIVE
Before every response, scan the requirements above. If you detect missing logic, edge cases, or safety gaps, prepend:
```
[REMINDER] <what's missing + why it matters>
```
At the end of each phase, list any assumptions made and flag them for verification.

---

## FINAL WISDOM
"Traktr doesn't find the most bugs. It finds the right bugs, with proof, in minutes, and tells you exactly what to test manually next."

**Prioritize:** Signal > Noise | Reproducibility > Volume | Actionability > Automation

---

CURRENT PHASE: PHASE 1 - INSTALLER
Begin.
