# Changelog
 
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
 
---
 
## [1.0.0] — 2026-03-31
 
### Phase 1 — Foundation
- 24+ security checks across 4 layers: app, webserver, container, host
- HTTP scanner for app + webserver checks
- SSH scanner for host layer checks
- Docker scanner for container checks
- Static file scanners for nginx.conf, Dockerfile, docker-compose.yml
- Security grading A–F based on pass percentage
- Attack path detection and scoring
- Professional PDF report generation (ReportLab)
- JSON export for CI/CD integration
- Role-based OWASP narratives (student, devops, pentester, cto)
- 30-day hardening roadmap simulation
- What-if simulation (`--simulate`)
- Prioritised hardening plan (Day 1 / Day 7 / Day 30)
- `--mode quick` and `--mode full`
 
### Phase 2 — Temporal Drift Engine
- SQLite history database at `~/.stacksentry/history.db`
- Auto-save every scan silently
- Drift engine comparing current vs previous scan
- `--compare-last`, `--history`, `--no-save`, `--db-path` flags
- PDF "Security Posture History" section
- 55 drift engine tests
 
### Phase 3 — Remediation Engine + Auto-Fix
- AI-powered patch generation (Anthropic API, Claude)
- 28 static templates covering all 24+ checks
- LLM-first with static fallback and placeholder
- Concurrent generation (`ThreadPoolExecutor`, 5 workers)
- Exponential back-off retry on rate-limit errors (429/529)
- Per-scan `patches/{target}_{date}_scan{N}/` subfolder
- Identification header in every patch file
- `manifest.json` per patches folder
- `--patch`, `--no-llm`, `--patch-dir` flags
- Auto-fix engine (`--fix`) — context-aware:
  - SSH: HOST + WS layer fixes applied directly on server
  - `--dockerfile`: CONT-USER, CONT-HEALTH, CONT-REG fixes
  - `--compose-file`: CONT-RES resource limit fixes
  - `--nginx-conf`: WS fixes applied to local file
  - APP layer: framework-specific code snippets (Flask/Django/generic)
- Patches and auto-fix results in PDF and JSON
- SSH safety: `prohibit-password` (no lockouts), safe ordering, shared connection
- Path B: APP layer prints exact copy-paste code snippets
- 161 remediation tests (316 total)
 
### Phase 4 — Packaging
- `pip install stacksentry` entry point
- `stacksentry` CLI command
- PyPI classifiers and keywords
- MIT license
- `.env.example` for secure key management
 
### Fixed
- 21 check functions had FAIL silently overwritten by PASS
- `Grade.F` rendering as `Grade.F` — fixed to `.value`
- Duplicate "Prioritised Hardening Plan" section in PDF
- Sequential LLM calls (333s) → concurrent ThreadPoolExecutor (132s)
- TLS snippet conflicted with Let's Encrypt `ssl_session_timeout`
- SSH hardening with `PermitRootLogin no` caused server lockouts
- `generate_owasp_narrative` UnboundLocalError in PDF generator