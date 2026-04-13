# Changelog

## 2026-04-13 — v2.3.3 (CI Hardening & Multi-Distro Fixes)

- **Fix**: Docker build — switched runtime base from `kalilinux/kali-rolling` to
  `debian:bookworm-slim` (Kali rolling repos unreliable in CI); all tools still install identically
- **Fix**: Docker build — removed `nikto` from apt-get (not in Debian bookworm main repos;
  nikto is a Kali-specific package)
- **Fix**: Docker build — pinned Go tool versions in Stage 1 to match `installer.sh`
  (`@latest` resolved to a broken upstream release and failed the build)
- **Fix**: Installer TTY guard — now correctly skips the check in `--dry-run` mode and in
  CI environments (`CI=true`); real interactive installs on Kali/Ubuntu are unaffected
- **Fix**: DVWA integration test — `vulnerables/web-dvwa` was removed from Docker Hub;
  replaced with `ghcr.io/digininja/dvwa:latest`
- **Fix**: Full Install Test CI job — increased timeout from 15m to 25m; added
  `continue-on-error` on health check step (feroxbuster not in Ubuntu repos is expected)
- **Add**: `--dry-run` flag documented in README install section
- **Add**: `--check` flag documented in README install section
- **Add**: Installation method comparison table in README (Kali / Ubuntu / Arch / Fedora / macOS / Docker)
- **Add**: Docker section clarifies the image is Debian-based and works on any platform

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
