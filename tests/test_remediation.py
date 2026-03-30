"""
test_remediation.py — Tests for the remediation engine.
 
Covers:
- Static template coverage (every check has a template or placeholder)
- PatchResult structure correctness
- Generator LLM-first with static fallback logic
- Placeholder fallback for unknown checks
- Output file writing
- README.md generation
"""
 
import pytest
import pathlib
from unittest.mock import patch, MagicMock
 
from sec_audit.results import CheckResult, ScanResult, Status, Severity
from remediation.generator import PatchGenerator, PatchResult
from remediation.templates import get_template
 
 
# ── Helpers ───────────────────────────────────────────────────────────────────
 
def _check(id: str, layer: str, status: Status,
           severity: Severity = Severity.HIGH,
           details: str = "Test details") -> CheckResult:
    return CheckResult(id=id, layer=layer, name=f"Check {id}",
                       status=status, severity=severity, details=details)
 
 
def _scan(*checks) -> ScanResult:
    return ScanResult(
        target="http://test.example.com",
        mode="quick",
        checks=list(checks),
    )
 
 
# ── Template coverage ─────────────────────────────────────────────────────────
 
class TestTemplates:
 
    ALL_CHECK_IDS = [
        "APP-DEBUG-001", "APP-COOKIE-001", "APP-CSRF-001",
        "APP-ADMIN-001", "APP-RATE-001", "APP-PASS-001",
        "WS-HSTS-001", "WS-SEC-001", "WS-TLS-001",
        "WS-SRV-001", "WS-LIMIT-001", "WS-CONF-HSTS", "WS-CONF-CSP",
        "HOST-SSH-001", "HOST-FW-001", "HOST-UPDATE-001",
        "HOST-PERM-001", "HOST-LOG-001",
        "HOST-SVC-GUNICORN", "HOST-SVC-UWSGI", "HOST-SVC-MYSQL", "HOST-SVC-REDIS",
        "CONT-USER-001", "CONT-CONF-USER", "CONT-CONF-HEALTH",
        "CONT-RES-001", "CONT-COMP-RES", "CONT-SEC-001",
    ]
 
    @pytest.mark.parametrize("check_id", ALL_CHECK_IDS)
    def test_template_exists_for_check(self, check_id):
        """Every known check ID must return a non-None template."""
        result = get_template(check_id)
        assert result is not None, f"No template for {check_id}"
 
    @pytest.mark.parametrize("check_id", ALL_CHECK_IDS)
    def test_template_has_required_keys(self, check_id):
        """Every template must have all five required keys."""
        result = get_template(check_id)
        for key in ("filename", "file_type", "content", "instructions", "verification"):
            assert key in result, f"{check_id} template missing '{key}'"
 
    @pytest.mark.parametrize("check_id", ALL_CHECK_IDS)
    def test_template_filename_not_empty(self, check_id):
        result = get_template(check_id)
        assert result["filename"], f"{check_id} template has empty filename"
 
    @pytest.mark.parametrize("check_id", ALL_CHECK_IDS)
    def test_template_content_not_empty(self, check_id):
        result = get_template(check_id)
        assert len(result["content"]) > 50, f"{check_id} template content too short"
 
    @pytest.mark.parametrize("check_id", ALL_CHECK_IDS)
    def test_template_file_type_valid(self, check_id):
        valid_types = {"python", "shell", "nginx", "dockerfile", "yaml", "text"}
        result = get_template(check_id)
        assert result["file_type"] in valid_types, (
            f"{check_id} has invalid file_type: {result['file_type']}"
        )
 
    def test_unknown_check_returns_none(self):
        """Unknown check IDs must return None, not raise an exception."""
        result = get_template("UNKNOWN-CHECK-999")
        assert result is None
 
    def test_template_accepts_details(self):
        """Templates should accept details without crashing."""
        result = get_template("HOST-SSH-001", details="PermitRootLogin yes", stack="Ubuntu")
        assert result is not None
 
    def test_shell_templates_have_dry_run(self):
        """All shell patches must mention dry run or --apply."""
        shell_ids = ["HOST-SSH-001", "HOST-FW-001", "HOST-UPDATE-001",
                     "HOST-PERM-001", "HOST-LOG-001"]
        for check_id in shell_ids:
            result = get_template(check_id)
            assert "--apply" in result["content"] or "dry" in result["content"].lower(), (
                f"{check_id} shell patch does not have dry-run guard"
            )
 
    def test_shell_templates_have_shebang(self):
        """All shell patches must start with #!/bin/bash."""
        shell_ids = ["HOST-SSH-001", "HOST-FW-001", "HOST-UPDATE-001"]
        for check_id in shell_ids:
            result = get_template(check_id)
            assert result["content"].startswith("#!/bin/bash"), (
                f"{check_id} missing shebang"
            )
 
 
# ── PatchGenerator — static templates ────────────────────────────────────────
 
class TestPatchGeneratorStatic:
 
    @pytest.fixture
    def gen(self):
        """Generator with LLM disabled — always uses static templates."""
        return PatchGenerator(use_llm=False)
 
    def test_generate_all_returns_list(self, gen, tmp_path):
        scan = _scan(
            _check("APP-DEBUG-001", "app", Status.FAIL),
            _check("WS-HSTS-001",   "webserver", Status.FAIL),
        )
        results = gen.generate_all(scan, output_dir=str(tmp_path))
        assert isinstance(results, list)
        assert len(results) == 2
 
    def test_passing_checks_not_patched(self, gen, tmp_path):
        """PASS checks must not generate patches."""
        scan = _scan(
            _check("APP-DEBUG-001", "app", Status.PASS),
            _check("WS-HSTS-001",   "webserver", Status.FAIL),
        )
        results = gen.generate_all(scan, output_dir=str(tmp_path))
        assert len(results) == 1
        assert results[0].check_id == "WS-HSTS-001"
 
    def test_warn_checks_are_patched(self, gen, tmp_path):
        """WARN checks should also get patches — they are not fully secure."""
        scan = _scan(
            _check("APP-COOKIE-001", "app", Status.WARN),
        )
        results = gen.generate_all(scan, output_dir=str(tmp_path))
        assert len(results) == 1
 
    def test_files_are_written(self, gen, tmp_path):
        """Patch files must actually exist on disk after generate_all."""
        scan = _scan(_check("HOST-SSH-001", "host", Status.FAIL))
        results = gen.generate_all(scan, output_dir=str(tmp_path))
        assert results[0].output_path.exists()
 
    def test_readme_is_written(self, gen, tmp_path):
        """README.md must be written alongside the patches."""
        scan = _scan(_check("HOST-SSH-001", "host", Status.FAIL))
        gen.generate_all(scan, output_dir=str(tmp_path))
        assert (tmp_path / "README.md").exists()
 
    def test_readme_contains_target(self, gen, tmp_path):
        scan = _scan(_check("HOST-SSH-001", "host", Status.FAIL))
        gen.generate_all(scan, output_dir=str(tmp_path))
        readme = (tmp_path / "README.md").read_text()
        assert "http://test.example.com" in readme
 
    def test_patch_result_structure(self, gen, tmp_path):
        scan = _scan(_check("WS-HSTS-001", "webserver", Status.FAIL))
        results = gen.generate_all(scan, output_dir=str(tmp_path))
        r = results[0]
        assert r.check_id == "WS-HSTS-001"
        assert r.filename
        assert r.content
        assert r.instructions
        assert r.verification
        assert r.severity
        assert not r.is_llm
 
    def test_patch_file_content_matches_result(self, gen, tmp_path):
        """The content written to disk must match PatchResult.content."""
        scan = _scan(_check("WS-HSTS-001", "webserver", Status.FAIL))
        results = gen.generate_all(scan, output_dir=str(tmp_path))
        r = results[0]
        disk_content = r.output_path.read_text(encoding="utf-8")
        assert disk_content == r.content
 
    def test_unknown_check_gets_placeholder(self, gen, tmp_path):
        """Checks with no template must get a placeholder, not raise an error."""
        scan = _scan(_check("UNKNOWN-FUTURE-999", "app", Status.FAIL))
        results = gen.generate_all(scan, output_dir=str(tmp_path))
        assert len(results) == 1
        assert results[0].file_type == "text"
 
    def test_output_dir_created_if_missing(self, gen, tmp_path):
        """generate_all must create output_dir if it does not exist."""
        new_dir = tmp_path / "deep" / "nested" / "patches"
        scan = _scan(_check("HOST-SSH-001", "host", Status.FAIL))
        gen.generate_all(scan, output_dir=str(new_dir))
        assert new_dir.exists()
 
    def test_is_llm_false_when_llm_disabled(self, gen, tmp_path):
        scan = _scan(_check("HOST-SSH-001", "host", Status.FAIL))
        results = gen.generate_all(scan, output_dir=str(tmp_path))
        assert all(not r.is_llm for r in results)
 
    def test_empty_scan_returns_empty_list(self, gen, tmp_path):
        """No non-passing checks should produce no patches."""
        scan = _scan(
            _check("APP-DEBUG-001", "app", Status.PASS),
            _check("WS-HSTS-001",   "webserver", Status.PASS),
        )
        results = gen.generate_all(scan, output_dir=str(tmp_path))
        assert results == []
 
 
# ── PatchGenerator — LLM fallback ────────────────────────────────────────────
 
class TestPatchGeneratorLLMFallback:
 
    def test_falls_back_to_template_when_llm_returns_none(self, tmp_path):
        """When LLM returns None, the static template must be used."""
        gen = PatchGenerator(use_llm=True, api_key="fake-key")
 
        with patch("remediation.generator.generate_patch_with_llm", return_value=None):
            scan = _scan(_check("HOST-SSH-001", "host", Status.FAIL))
            results = gen.generate_all(scan, output_dir=str(tmp_path))
 
        assert len(results) == 1
        assert not results[0].is_llm  # template was used
 
    def test_llm_result_sets_is_llm_true(self, tmp_path):
        """When LLM returns a valid patch, is_llm must be True."""
        gen = PatchGenerator(use_llm=True, api_key="fake-key")
 
        fake_patch = {
            "filename":     "HOST-SSH-001.sh",
            "file_type":    "shell",
            "content":      "#!/bin/bash\necho 'LLM patch'",
            "instructions": "Run this script",
            "verification": "ssh root@server 'echo test'",
        }
 
        with patch("remediation.generator.generate_patch_with_llm", return_value=fake_patch):
            scan = _scan(_check("HOST-SSH-001", "host", Status.FAIL))
            results = gen.generate_all(scan, output_dir=str(tmp_path))
 
        assert results[0].is_llm
 
    def test_no_api_key_skips_llm(self, tmp_path):
        """Without an API key, LLM must not be attempted."""
        gen = PatchGenerator(use_llm=True, api_key="")
 
        with patch("remediation.generator.generate_patch_with_llm") as mock_llm:
            scan = _scan(_check("HOST-SSH-001", "host", Status.FAIL))
            gen.generate_all(scan, output_dir=str(tmp_path))
 
        mock_llm.assert_not_called()
 
 
# ── README content ────────────────────────────────────────────────────────────
 
class TestReadmeGeneration:
 
    def test_readme_has_required_sections(self, tmp_path):
        gen = PatchGenerator(use_llm=False)
        scan = _scan(
            _check("HOST-SSH-001", "host",      Status.FAIL, Severity.HIGH),
            _check("WS-HSTS-001",  "webserver", Status.FAIL, Severity.HIGH),
            _check("APP-RATE-001", "app",       Status.WARN, Severity.MEDIUM),
        )
        gen.generate_all(scan, output_dir=str(tmp_path))
        readme = (tmp_path / "README.md").read_text()
 
        assert "How to apply"       in readme
        assert "Verification"       in readme
        assert "Re-scan"            in readme
        assert "HOST-SSH-001"       in readme
        assert "WS-HSTS-001"        in readme
 
    def test_readme_sorted_by_severity(self, tmp_path):
        """Critical and HIGH checks must appear before LOW in README."""
        gen = PatchGenerator(use_llm=False)
        scan = _scan(
            _check("APP-PASS-001",  "app",  Status.WARN, Severity.LOW),
            _check("HOST-SSH-001",  "host", Status.FAIL, Severity.HIGH),
        )
        gen.generate_all(scan, output_dir=str(tmp_path))
        readme = (tmp_path / "README.md").read_text()
 
        high_pos = readme.find("HOST-SSH-001")
        low_pos  = readme.find("APP-PASS-001")
        assert high_pos < low_pos, "HIGH severity should appear before LOW in README"
 
 
# ── Concurrent execution ────────────────────────────────────────────────────────────────────────────
 
class TestConcurrentExecution:
 
    def test_results_in_original_check_order(self, tmp_path):
        gen = PatchGenerator(use_llm=False)
        check_ids = ["HOST-SSH-001", "WS-HSTS-001", "APP-DEBUG-001", "HOST-FW-001", "WS-SEC-001"]
        checks = [
            _check(cid,
                   "app" if "APP" in cid else "webserver" if "WS" in cid else "host",
                   Status.FAIL)
            for cid in check_ids
        ]
        scan = _scan(*checks)
        results = gen.generate_all(scan, output_dir=str(tmp_path))
 
        assert len(results) == len(check_ids)
        for i, (result, expected_id) in enumerate(zip(results, check_ids)):
            assert result.check_id == expected_id, (
                f"Position {i}: expected {expected_id}, got {result.check_id}. "
                "Concurrent execution broke result ordering."
            )
 
    def test_all_files_written_after_concurrent_generation(self, tmp_path):
        gen = PatchGenerator(use_llm=False)
        checks = [
            _check("HOST-SSH-001",  "host",      Status.FAIL),
            _check("HOST-FW-001",   "host",      Status.FAIL),
            _check("WS-HSTS-001",   "webserver", Status.FAIL),
            _check("APP-DEBUG-001", "app",       Status.FAIL),
        ]
        scan = _scan(*checks)
        results = gen.generate_all(scan, output_dir=str(tmp_path))
 
        for r in results:
            assert r.output_path.exists(), f"{r.filename} was not written to disk"
            assert r.output_path.stat().st_size > 0, f"{r.filename} is empty"
 
    def test_max_workers_param_accepted(self, tmp_path):
        gen = PatchGenerator(use_llm=False, max_workers=2)
        assert gen.max_workers == 2
        scan = _scan(_check("HOST-SSH-001", "host", Status.FAIL))
        results = gen.generate_all(scan, output_dir=str(tmp_path))
        assert len(results) == 1
 
    def test_mixed_llm_and_template_results_ordered(self, tmp_path):
        gen = PatchGenerator(use_llm=True, api_key="fake-key")
        call_count = [0]
 
        def fake_llm(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return {
                    "filename": kwargs["check_id"] + ".sh",
                    "file_type": "shell",
                    "content": "#!/bin/bash\necho ok",
                    "instructions": "run it",
                    "verification": "check it",
                }
            return None
 
        checks = [
            _check("HOST-SSH-001", "host", Status.FAIL),
            _check("HOST-FW-001",  "host", Status.FAIL),
        ]
        scan = _scan(*checks)
 
        with patch("remediation.generator.generate_patch_with_llm",
                   side_effect=lambda **kw: fake_llm(**kw)):
            results = gen.generate_all(scan, output_dir=str(tmp_path))
 
        assert len(results) == 2
        assert results[0].check_id == "HOST-SSH-001"
        assert results[1].check_id == "HOST-FW-001"
 
 
# ── Retry logic ───────────────────────────────────────────────────────────────────────────────────
 
class TestRetryLogic:
 
    def _call_llm(self, side_effect, max_retries=2):
        from remediation.llm import generate_patch_with_llm
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = side_effect
        with patch("remediation.llm._get_client", return_value=mock_client),              patch("time.sleep"):
            return generate_patch_with_llm(
                check_id="HOST-SSH-001",
                check_name="SSH hardening",
                layer="host",
                details="PermitRootLogin yes",
                severity="HIGH",
                stack_fingerprint="Ubuntu",
                recommendation="Set PermitRootLogin no",
                api_key="fake-key",
                max_retries=max_retries,
                retry_delay=0.01,
            )
 
    def test_retries_on_rate_limit_error(self):
        call_count = [0]
        good_json = (
            '{"filename": "HOST-SSH-001.sh", "file_type": "shell",'
            ' "content": "#!/bin/bash", "instructions": "run it",'
            ' "verification": "check it"}'
        )
 
        def side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] < 2:
                raise Exception("Error 429: rate_limit exceeded")
            mock = MagicMock()
            mock.content[0].text = good_json
            return mock
 
        result = self._call_llm(side_effect)
        assert result is not None, "Should have succeeded on retry"
        assert result["filename"] == "HOST-SSH-001.sh"
        assert call_count[0] == 2
 
    def test_retries_on_overloaded_error(self):
        call_count = [0]
        good_json = (
            '{"filename": "HOST-SSH-001.sh", "file_type": "shell",'
            ' "content": "#!/bin/bash", "instructions": "run it",'
            ' "verification": "check it"}'
        )
 
        def side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] < 2:
                raise Exception("Error 529: overloaded")
            mock = MagicMock()
            mock.content[0].text = good_json
            return mock
 
        result = self._call_llm(side_effect)
        assert result is not None
        assert call_count[0] == 2
 
    def test_returns_none_after_all_retries_exhausted(self):
        call_count = [0]
 
        def always_rate_limit(**kwargs):
            call_count[0] += 1
            raise Exception("Error 429: rate_limit exceeded")
 
        result = self._call_llm(always_rate_limit, max_retries=2)
        assert result is None
        assert call_count[0] == 3  # initial + 2 retries
 
    def test_does_not_retry_on_json_parse_error(self):
        call_count = [0]
 
        def bad_json(**kwargs):
            call_count[0] += 1
            mock = MagicMock()
            mock.content[0].text = "this is not valid json {{{"
            return mock
 
        result = self._call_llm(bad_json, max_retries=2)
        assert result is None
        assert call_count[0] == 1  # no retry for bad JSON
 
 
# ── --patch-dir flag ──────────────────────────────────────────────────────────────────────────
 
class TestPatchDirFlag:
 
    def test_custom_dir_is_used(self, tmp_path):
        custom_dir = tmp_path / "my_custom_patches"
        gen = PatchGenerator(use_llm=False)
        scan = _scan(_check("HOST-SSH-001", "host", Status.FAIL))
        results = gen.generate_all(scan, output_dir=str(custom_dir))
 
        assert custom_dir.exists()
        for r in results:
            assert str(custom_dir) in str(r.output_path)
 
    def test_patch_dir_created_recursively(self, tmp_path):
        deep_dir = tmp_path / "a" / "b" / "c" / "patches"
        gen = PatchGenerator(use_llm=False)
        scan = _scan(_check("HOST-SSH-001", "host", Status.FAIL))
        gen.generate_all(scan, output_dir=str(deep_dir))
        assert deep_dir.exists()
 
    def test_readme_written_to_custom_dir(self, tmp_path):
        custom_dir = tmp_path / "custom"
        gen = PatchGenerator(use_llm=False)
        scan = _scan(_check("HOST-SSH-001", "host", Status.FAIL))
        gen.generate_all(scan, output_dir=str(custom_dir))
        assert (custom_dir / "README.md").exists()