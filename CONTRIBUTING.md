# Contributing to StackSentry
 
Thank you for your interest. The most valuable contributions are new security checks.
 
---
 
## Adding a new check — 5 steps
 
### Step 1 — Choose a layer and assign an ID
 
| Layer | Prefix | File |
|---|---|---|
| Web application | `APP-` | `checks/app_checks.py` |
| Web server | `WS-` | `checks/webserver_checks.py` |
| Container | `CONT-` | `checks/container_checks.py` |
| Host / OS | `HOST-` | `checks/host_checks.py` |
 
IDs follow `LAYER-KEYWORD-NNN` — e.g. `APP-CORS-001`.
 
### Step 2 — Write the check function
 
```python
from sec_audit.results import CheckResult, Status, Severity
 
def check_cors_headers(http_scanner, scan_result=None) -> CheckResult:
    """APP-CORS-001: CORS headers not overly permissive."""
    if not http_scanner:
        return CheckResult(id="APP-CORS-001", layer="app",
                           name="CORS not permissive",
                           status=Status.WARN, severity=Severity.MEDIUM,
                           details="No HTTP scanner available.")
 
    value = http_scanner.get_header("Access-Control-Allow-Origin")
    if value == "*":
        return CheckResult(id="APP-CORS-001", layer="app",
                           name="CORS not permissive",
                           status=Status.FAIL, severity=Severity.MEDIUM,
                           details="Wildcard CORS allows any domain. → Restrict to trusted origins.")
 
    return CheckResult(id="APP-CORS-001", layer="app",
                       name="CORS not permissive",
                       status=Status.PASS, severity=Severity.MEDIUM,
                       details=f"CORS origin restricted to: {value or 'not set'} ✓")
```
 
**Rules:**
- Always guard against missing scanner — return `Status.WARN`, never raise
- `details` must be human-readable with a `→ Fix` hint on failure
- Never raise exceptions from check functions
 
### Step 3 — Register in `sec_audit/config.py`
 
```python
{
    "id":             "APP-CORS-001",
    "layer":          "app",
    "name":           "CORS headers not overly permissive",
    "severity":       "MEDIUM",
    "owasp":          ["A05:2025"],
    "effort":         "LOW",
    "impact_weight":  1.7,
    "recommendation": "Restrict Access-Control-Allow-Origin to specific trusted origins.",
},
```
 
### Step 4 — Add a static patch template in `remediation/templates.py`
 
```python
def patch_app_cors(details="", stack="") -> dict:
    return _patch(
        filename="APP-CORS-001.conf",
        file_type="nginx",
        content="# Remove wildcard and restrict to your domain\nadd_header Access-Control-Allow-Origin 'https://your-domain.com' always;",
        instructions="Replace the wildcard CORS header with your specific trusted origin.",
        verification="curl -sI https://your-app.com | grep -i 'access-control-allow-origin'",
    )
```
 
Register it in `get_template()` registry:
```python
"APP-CORS-001": lambda: patch_app_cors(details, stack),
```
 
### Step 5 — Write tests and run
 
Add to `tests/test_branch_logic.py`:
```python
class TestCORSCheckBranchLogic:
    def test_wildcard_cors_returns_fail(self):
        mock_scanner = MagicMock()
        mock_scanner.get_header.return_value = "*"
        assert check_cors_headers(mock_scanner).status == Status.FAIL
 
    def test_restricted_cors_returns_pass(self):
        mock_scanner = MagicMock()
        mock_scanner.get_header.return_value = "https://trusted.com"
        assert check_cors_headers(mock_scanner).status == Status.PASS
 
    def test_no_scanner_returns_warn(self):
        assert check_cors_headers(None).status == Status.WARN
```
 
Add check ID to `TestTemplates.ALL_CHECK_IDS` in `tests/test_remediation.py`.
 
```bash
pytest tests/ -v   # all 316+ tests must pass
```
 
---
 
## Severity guide
 
| Severity | When to use |
|---|---|
| `CRITICAL` | Directly exploitable without auth |
| `HIGH` | Enables serious attacks or exposes data |
| `MEDIUM` | Increases attack surface |
| `LOW` | Best practice violation, limited direct impact |
 
---
 
## Pull request checklist
 
- [ ] Guard pattern — never raises, returns WARN on missing data
- [ ] Registered in `config.py` with all required fields
- [ ] Static patch template in `remediation/templates.py`
- [ ] Check ID in `TestTemplates.ALL_CHECK_IDS`
- [ ] Branch logic tests (PASS / FAIL / WARN)
- [ ] All existing tests still pass
 
---
 
## Development setup
 
```bash
git clone https://github.com/stacksentry/stacksentry
cd stacksentry
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # add ANTHROPIC_API_KEY
pytest tests/ -v
```