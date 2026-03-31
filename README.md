# StackSentry 🛡️
 
**Automated web application security assessment, AI-powered remediation, and auto-fix.**
 
[![Tests](https://img.shields.io/badge/tests-316%20passing-brightgreen)](https://github.com/stacksentry/stacksentry)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/stacksentry/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PyPI](https://img.shields.io/badge/pypi-v1.0.0-orange)](https://pypi.org/project/stacksentry/)
 
StackSentry scans your web application stack — Flask/Django app, Nginx/Apache, Docker containers, and Linux host — assigns a security grade, generates AI-powered fix scripts, and can apply fixes automatically via SSH or directly to your config files.
 
---
 
## What it does
 
```bash
stacksentry --target https://your-app.com --mode full --patch --fix \
  --ssh-host your-server-ip --ssh-user root \
  --dockerfile ./Dockerfile \
  --compose-file ./docker-compose.yml
```
 
In one command, StackSentry:
 
- Runs **24+ security checks** across 4 layers of your stack
- Assigns a **security grade** (A–F) with a percentage score
- Generates a **professional PDF report** with OWASP Top 5 mapping
- Creates **AI-powered fix scripts** organised per scan in `patches/`
- **Auto-applies fixes** via SSH (HOST + WS) or directly to your config files (CONT + WS)
- Prints **framework-specific code snippets** for APP layer checks (Flask/Django)
- Tracks **posture drift** — shows what regressed or improved since last scan
- Simulates **what-if scenarios** — projects your grade after specific fixes
 
---
 
## Quick start
 
```bash
pip install stacksentry
 
# Basic HTTP scan
stacksentry --target https://your-app.com
 
# Full stack scan with PDF report
stacksentry --target https://your-app.com --mode full \
  --ssh-host your-server-ip --ssh-user root --ssh-password yourpass \
  --output report.pdf
 
# Generate AI-powered fix scripts + auto-apply
stacksentry --target https://your-app.com --mode full --patch --fix \
  --ssh-host your-server-ip --ssh-user root --ssh-password yourpass \
  --dockerfile ./Dockerfile --compose-file ./docker-compose.yml
 
# Compare against last scan (posture drift)
stacksentry --target https://your-app.com --compare-last
 
# View full scan history
stacksentry --target https://your-app.com --history
```
 
---
 
## Installation
 
**From PyPI:**
```bash
pip install stacksentry
```
 
**From source:**
```bash
git clone https://github.com/stacksentry/stacksentry
cd stacksentry
pip install -e ".[dev]"
```
 
**Optional — AI-powered patch generation:**
 
Create a `.env` file in your project root:
```
ANTHROPIC_API_KEY=sk-ant-your-key-here
```
 
Without the key, StackSentry uses static patch templates. With it, patches are tailored to your specific stack by AI.
 
---
 
## Auto-fix coverage
 
StackSentry uses the context you provide to determine the best fix strategy for every check:
 
| Layer | Check | Auto-fix method |
|---|---|---|
| **HOST** | HOST-FW-001 — Firewall enabled | ✅ SSH (ufw enable) |
| **HOST** | HOST-SSH-001 — SSH hardening | ✅ SSH (prohibit-password, MaxAuthTries) |
| **HOST** | HOST-UPDATE-001 — Auto-updates | ✅ SSH (unattended-upgrades) |
| **HOST** | HOST-PERM-001 — SSH file permissions | ✅ SSH (chmod) |
| **HOST** | HOST-LOG-001 — Logging active | ✅ SSH (rsyslog) |
| **HOST** | HOST-SVC-001 — Minimal services | 📋 Manual guide |
| **HOST** | HOST-SVC-GUNICORN/UWSGI/MYSQL/REDIS | 📋 Manual guide |
| **WS** | WS-HSTS-001 — HSTS header | ✅ SSH or `--nginx-conf` |
| **WS** | WS-SEC-001 — Security headers | ✅ SSH or `--nginx-conf` |
| **WS** | WS-TLS-001 — TLS 1.2+ | ✅ SSH or `--nginx-conf` |
| **WS** | WS-SRV-001 — Server token disclosure | ✅ SSH or `--nginx-conf` |
| **WS** | WS-DIR-001 — Directory listing | ✅ SSH or `--nginx-conf` |
| **WS** | WS-LIMIT-001 — Request size limits | ✅ SSH or `--nginx-conf` |
| **WS** | WS-CONF-HSTS / WS-CONF-CSP | ✅ SSH or `--nginx-conf` |
| **CONT** | CONT-USER-001 — Non-root user | ✅ `--dockerfile` |
| **CONT** | CONT-CONF-HEALTH — HEALTHCHECK | ✅ `--dockerfile` |
| **CONT** | CONT-REG-001 — Pinned base image | ✅ `--dockerfile` |
| **CONT** | CONT-RES-001 / CONT-COMP-RES | ✅ `--compose-file` |
| **CONT** | CONT-PORT-001 — Exposed ports | 📋 Port report + manual |
| **CONT** | CONT-SEC-001 — Secrets in env | 📋 Manual guide |
| **APP** | APP-DEBUG-001 — Debug mode | 📋 Flask/Django snippet |
| **APP** | APP-COOKIE-001 — Secure cookies | 📋 Flask/Django snippet |
| **APP** | APP-CSRF-001 — CSRF protection | 📋 Flask/Django snippet |
| **APP** | APP-ADMIN-001 — Admin endpoints | 📋 Flask/Django snippet |
| **APP** | APP-RATE-001 — Rate limiting | 📋 Flask/Django snippet |
| **APP** | APP-PASS-001 — Password policy | 📋 Flask/Django snippet |
 
**Legend:**
- ✅ **Fully automated** — StackSentry applies the fix and confirms
- 📋 **Code snippet** — StackSentry prints the exact code to add (framework-detected)
 
Every automated fix creates a timestamped backup, validates before applying, and is idempotent.
 
---
 
## What gets scanned
 
### 4-layer architecture
 
```
Web Application  →  Nginx/Apache  →  Docker Container  →  Linux Host
    (HTTP)           (Config)          (Dockerfile)         (SSH)
```
 
StackSentry runs 24+ checks across all four layers in a single command, with SSH access scanning the host layer in real time.
 
---
 
## Output formats
 
### PDF report (`--output report.pdf`)
Professional report including executive summary, attack surface heatmap, OWASP Top 5 mapping, prioritised hardening plan (Day 1/7/30), 30-day simulation roadmap, generated patches table, auto-fix results, security posture history, and server fingerprint.
 
### JSON (`--json results.json`)
Structured output for CI/CD pipelines. Includes all check results, scores, attack paths, generated patches with metadata, auto-fix results, and scan history.
 
### Patch files (`--patch`)
Scripts written to `patches/{target}_{date}_scan{N}/`:
- `.sh` shell scripts for host/server fixes (dry-run by default, `--apply` to apply)
- `.py` Python scripts for app-layer guidance
- `.conf` nginx configuration snippets
- `.dockerfile` Dockerfile patches
- `README.md` with severity-sorted application order
- `manifest.json` for machine-readable processing
 
---
 
## CLI reference
 
```
stacksentry --target URL [options]
 
Core:
  --target, -t URL       Target web application URL
  --mode, -m MODE        quick (HTTP only) | full (HTTP + Docker + SSH)
  --output, -o PATH      PDF report output path
  --json, -j PATH        JSON results output path
  --verbose, -v          Verbose debug output
 
Scanning:
  --ssh-host HOST        SSH target host/IP (enables host layer + auto-fix)
  --ssh-user USER        SSH username (default: root)
  --ssh-password PASS    SSH password
  --ssh-key PATH         SSH private key path
  --docker-host URL      Docker daemon endpoint
  --nginx-conf PATH      nginx.conf for static analysis and local auto-fix
  --dockerfile PATH      Dockerfile for static analysis and auto-fix
  --compose-file PATH    docker-compose.yml for static analysis and auto-fix
 
Reporting:
  --plan                 Print prioritised hardening plan (Day 1/7/30)
  --simulate CHECK_IDS   What-if simulation (comma-separated check IDs)
  --profile ROLE         Narrative: student|devops|pentester|cto|generic
 
Patch generation:
  --patch                Generate AI-powered remediation fix scripts
  --patch-dir DIR        Output directory (default: patches/)
  --no-llm               Use static templates only (no API key needed)
 
Auto-fix:
  --fix                  Auto-apply fixes using available context
 
History:
  --compare-last         Show posture drift vs previous scan
  --history              Print scan history timeline and exit
  --no-save              Do not save this scan to history database
  --db-path PATH         Custom history database path
```
 
---
 
## Using as a library
 
```python
from sec_audit.results import ScanResult
from storage import ScanHistory
from storage.drift import DriftEngine
from remediation import PatchGenerator
from remediation.auto_fix import AutoFixer
 
# Generate patches
generator = PatchGenerator(use_llm=True)
patches   = generator.generate_all(scan_result, output_dir="patches/")
 
# Auto-fix with full context
fixer = AutoFixer(
    ssh_host="1.2.3.4", ssh_password="...",
    dockerfile="./Dockerfile",
    compose_file="./docker-compose.yml",
)
results = fixer.fix_all(scan_result)
 
# History and drift
history = ScanHistory()
history.save(scan_result)
report  = DriftEngine().compare(previous_scan, scan_result)
```
 
---
 
## Architecture
 
```
stacksentry/
├── sec_audit/          CLI, config, results, scoring, narratives
├── checks/             24+ security check functions (4 layers)
├── scanners/           HTTP, SSH, Docker, Nginx, compose scanners
├── reporting/          PDF generator (ReportLab)
├── storage/            SQLite history, drift engine
├── remediation/        Patch generator, LLM integration, auto-fix engine
└── tests/              316 tests, 0 failures
```
 
---
 
## Adding custom checks
 
See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide including check schema, template registration, and test requirements.
 
---
 
## Running tests
 
```bash
pip install -e ".[dev]"
pytest tests/ -v
```
 
---
 
## Roadmap
 
- [x] Phase 1 — 24+ checks, PDF/JSON reports, CLI
- [x] Phase 2 — History, drift detection, posture tracking
- [x] Phase 3 — AI-powered patch generation + auto-fix engine
- [x] Phase 4 — PyPI package, GitHub release *(current)*
- [ ] Phase 5 — SaaS dashboard, team accounts, CI/CD integrations, `--app-path` for application source code auto-fix
 
---
 
## License
 
MIT — see [LICENSE](LICENSE) for details.
 
---
 
*Built by Victor Chukwuemeka Onwuegbuchulem — London Metropolitan University*
 