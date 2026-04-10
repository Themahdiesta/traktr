# Usage Examples
## Basic Scan
`./src/core/orchestrator.sh https://example.com`
## Authenticated
`./src/core/orchestrator.sh https://app.target.com --auth user:pass`
## OSCP/Stealth
`./src/core/orchestrator.sh https://lab.vuln.com --oscp --stealth --debug`
## Output
`cat scan_results/REPORT.md | grep "CRITICAL"`
`bash scan_results/manual_verify_commands.sh`
