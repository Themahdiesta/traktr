# Changelog

## 2026-04-11 — v2.2
- **Fix**: `$PKG_INSTALL` quoting bug — `sudo apt-get install -y` was treated as a single executable name, silently failing all apt installs (jq, curl, wget, etc.)
- **Fix**: `sudo` password prompt swallowed by `>> logfile 2>&1` redirect — added `sudo -v` credential caching at installer start
- **Fix**: GOPATH ownership guard — auto-detect and fix `~/go/` owned by root from previous `sudo su` installs
- **Fix**: Root detection — warn and strip sudo prefix when running as root instead of double-sudo failures
- **Change**: Go install now tries `apt-get install golang-go` first, falls back to downloading latest stable from go.dev dynamically (no more hardcoded go1.22.2)
- **Change**: Pin Go tool versions explicitly instead of `@latest` to prevent breaking installs from upstream releases
- **Add**: `traktr --check` / `installer.sh --check` health check — validates every tool responds to `--version`
- **Add**: `traktr --update` — updates nuclei templates, subfinder, katana, httpx databases in one command
- **Add**: GitHub Actions CI — lint + dry-run + full install test + weekly scheduled run
- **Add**: `apt-get update` before first package install to prevent stale cache failures

## 2026-04-11 — v2.0
- Initial public release
