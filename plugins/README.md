# Plugin System
Drop executable `.sh` files here. Follow the contract in PROMPT_MASTER.md Phase 4.
Each plugin must export: run_plugin(endpoint, context)
Output format: SEVERITY|TYPE|ENDPOINT|PAYLOAD|CONFIDENCE|PROOF_BASE64
