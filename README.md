# Security Audit Framework
## Automated Web Application Security Configuration Assessment

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Overview

**Security Audit Framework** is an automated tool that performs comprehensive security configuration assessment across web application stacks (**application → web server → container → host**) and generates structured PDF remediation reports.

### Key Features
- ✅ **24 security configuration checks** across 4 layers
- ✅ **Application-aware** (Flask/Django/Node.js framework detection)
- ✅ HTTP/TLS analysis, Docker inspection, SSH host scanning
- ✅ **Professional PDF reports** with priority fixes
- ✅ Designed for **small teams / educational institutions**

---

## 🎯 Use Cases
- Assess security posture of Flask/Django LMS deployments
- Audit Nginx/Apache web server configurations
- Validate Docker container security settings
- Check Linux host hardening compliance
- Generate actionable remediation reports for developers

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Basic scan (HTTP checks only)
python sec_audit.py --target https://your-lms.example.com --output report.pdf

# Full stack scan (HTTP + Docker + SSH)
python sec_audit.py \
  --target https://your-lms.example.com \
  --docker-host unix:///var/run/docker.sock \
  --ssh-key ~/.ssh/id_rsa \
  --ssh-host your-server-ip \
  --mode full \
  --output full_security_report.pdf
```

## 📊 Sample Report Output
```
EXECUTIVE SUMMARY                    SERVER FINGERPRINT
┌─────────────────────────────┐     Flask 2.3.3 + Nginx 1.24.2
│ Overall Score: **C** (14/24)    Docker + Ubuntu 22.04
│ High Risk: 6 findings         Deployment: Docker Compose
│ Medium Risk: 4 findings
│ Quick Fixes: 5 priority items  RISK HEATMAP
└─────────────────────────────┘  🟥🟥🟥🟨🟨 | Web App Layer
                                 🟨🟨🟢🟢🟢 | Web Server Layer
```

## 🛠️ Configuration Checks (24 Total)

| Layer        | # Checks | Security Controls |
|-------------|----------|-------------------|
| Web App     | 6        | Debug mode, secure cookies, CSRF, admin endpoints, rate limiting, password policy |
| Web Server  | 6        | HSTS, security headers, TLS 1.2+, server tokens, directory listing, request limits |
| Container   | 6        | Non-root user, minimal ports, resource limits, health checks, image source, secrets |
| Host/Server | 6        | SSH hardening, unnecessary services, auto-updates, permissions, firewall, logging |


## 💻 Usage Examples
### 1. Quick HTTP Assessment
```
python sec_audit.py --target https://lms.example.com --mode quick --output quick-report.pdf
```

### 2. Full Stack Audit (Production LMS)
```
python sec_audit.py \
  --target https://staging-lms.internal \
  --docker-host tcp://localhost:2375 \
  --ssh-host 192.168.1.100 \
  --ssh-key ~/.ssh/lms-server.key \
  --mode full \
  --output lms-production-audit.pdf
```

### 3. JSON Export for CI/CD
```
python sec_audit.py --target https://app.example.com --json results.json
```

## 📁 Project Structure
```
sec_audit_framework/
├── sec_audit.py              # Main CLI entrypoint
├── sec_audit/               # Core package
│   ├── config.py            # 24 security check definitions
│   ├── cli.py              # Argument parsing
│   └── results.py          # Result models
├── checks/                  # Security check modules
│   ├── app_checks.py       # Flask/Django checks
│   ├── webserver_checks.py # Nginx/Apache
│   ├── container_checks.py # Docker
│   └── host_checks.py      # Linux host
├── scanners/                # Target interaction
│   ├── http_scanner.py     # requests + TLS
│   ├── docker_scanner.py   # docker-py
│   └── ssh_scanner.py      # paramiko
└── reporting/               # PDF generation
    ├── pdf_generator.py    # ReportLab
    └── summary.py          # Executive summary
```

## 🧪 Test Cases (Evaluation)

| Test Case            | Expected Score | Purpose                  |
|----------------------|---------------|--------------------------|
| Weak Flask LMS       | D/F           | Baseline detection       |
| Hardened Flask LMS   | A/B           | Improvement validation   |
| Django Production    | C             | Third-party app          |
| Nginx VPS            | B             | Server-only testing      |

## 📈 Evaluation Metrics

- **Detection accuracy:** 90%+ on known weak configs  
- **False positive rate:** <5%  
- **Scan time:** <2 minutes per target  
- **Report usability:** Developer survey (target 4.5/5)

---

## 🎓 MSc Project Context

**MSc Computer Networking & Cyber Security**  
London Metropolitan University  

**Focus:** Addresses the gap between Nmap (network scanning) and enterprise tools (heavy compliance) by providing lightweight, web-app-centric configuration auditing for small teams.

---

## 📄 License

MIT License – see `LICENSE` file for details.

---

**Built for:** Developers, DevOps, small IT teams, educational institutions  
**Differentiation:** Application-aware + stack-focused + actionable PDF reports  
**Status:** MSc research prototype (v1.0)
