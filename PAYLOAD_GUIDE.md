# Payload Guide

## Directory Structure

```
payloads/
├── lfi/              # Local File Inclusion
├── sqli/             # SQL Injection
├── xss/              # Cross-Site Scripting
├── rce/              # Remote Code Execution
├── ssrf/             # Server-Side Request Forgery
├── xxe/              # XML External Entity
├── api/              # API-specific payloads
├── auth/             # Authentication bypass
├── framework/        # Framework-specific (e.g., laravel_lfi.txt)
├── waf_bypass/       # WAF evasion variants
└── secrets/
    └── patterns.txt  # Secret detection regex patterns
```

## Payload File Format

One payload per line. Lines starting with `#` are comments.

```
# Basic LFI payloads
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
```

### Tags (first 5 lines)

Special comment tags control behavior:

```
#DESTRUCTIVE    -- Filtered out in --oscp mode
#LEVEL:3        -- Escalation level (1-6 for LFI)
#WAF:cloudflare -- Only used when this WAF is detected
#FRAMEWORK:php  -- Only used for this framework
```

## Secret Patterns (patterns.txt)

Tab-separated: `LABEL\tREGEX\tCONFIDENCE`

```
aws_access_key	AKIA[0-9A-Z]{16}	CONFIRMED
github_token	ghp_[A-Za-z0-9_]{36}	CONFIRMED
generic_api_key	["\']?api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9]{16,}["\']	HIGH
```

Confidence levels:
- **CONFIRMED** -- regex is highly specific, almost zero false positives
- **HIGH** -- strong indicator, minor FP possible
- **POSSIBLE** -- needs manual verification

## Adding New Payloads

1. Create a `.txt` file in the appropriate `payloads/<type>/` directory
2. Add tags in the first 5 lines if needed
3. Test with: `traktr <target> --lfi-only` (or relevant flag)
4. Framework-specific: name as `<framework>_<vuln_type>.txt` in `payloads/framework/`

## WAF Bypass Payloads

Named `<waf_name>_<vuln_type>.txt` in `payloads/waf_bypass/`:

```
payloads/waf_bypass/cloudflare_lfi.txt
payloads/waf_bypass/modsecurity_sqli.txt
```

These are automatically loaded when `brain.sh` detects a matching WAF.
