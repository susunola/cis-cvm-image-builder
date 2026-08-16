"""Tests for scripts/real_e2e_test.py.

This script is *not* covered by the ohbs_image package's own test suite —
it drives real, billed Tencent Cloud CVM calls to stand up/tear down a
jump box for end-to-end verification (see CONTRIBUTING.md "Running the
real end-to-end test").

Scope: we do NOT mock-test parameter construction (that just re-asserts
the same request dict the implementation already builds — brittle and
low-value). We DO test the error-handling branches, because a script
that creates a real billed instance must fail loudly and clean up
correctly rather than leaving orphaned resources when the Tencent Cloud
API reports an error, and unrelated to network flakiness (which is
covered separately in wait_for_public_ip's timeout path).
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "real_e2e_test.py"

_spec = importlib.util.spec_from_file_location("real_e2e_test", SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
real_e2e_test = importlib.util.module_from_spec(_spec)
sys.modules["real_e2e_test"] = real_e2e_test
_spec.loader.exec_module(real_e2e_test)

from ohbs_image import ConfigError  # noqa: E402


class TestImportKeypair:
    def test_error_response_raises(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            lambda *a, **k: {"Response": {"Error": {"Code": "AuthFailure"}}})
        pub = tmp_path / "e2e_key.pub"
        pub.write_text("ssh-ed25519 AAAA fake\n")
        with pytest.raises(ConfigError, match="ImportKeyPair failed"):
            real_e2e_test.import_keypair("ap-guangzhou", "sid", "skey", None, pub)

    def test_missing_key_id_raises(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            lambda *a, **k: {"Response": {}})
        pub = tmp_path / "e2e_key.pub"
        pub.write_text("ssh-ed25519 AAAA fake\n")
        with pytest.raises(ConfigError, match="no KeyId"):
            real_e2e_test.import_keypair("ap-guangzhou", "sid", "skey", None, pub)

    def test_success_returns_key_id(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            lambda *a, **k: {"Response": {"KeyId": "skey-abc123"}})
        pub = tmp_path / "e2e_key.pub"
        pub.write_text("ssh-ed25519 AAAA fake\n")
        assert real_e2e_test.import_keypair(
            "ap-guangzhou", "sid", "skey", None, pub) == "skey-abc123"


class TestRunInstance:
    def _args(self):
        return mock.MagicMock(
            image_id="img-x", instance_type="S5.MEDIUM2", zone="ap-guangzhou-3",
            vpc_id="vpc-1", subnet_id="subnet-1", security_group_id="sg-1")

    def test_error_response_raises(self, monkeypatch):
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            lambda *a, **k: {"Response": {"Error": {"Code": "ResourceInsufficient"}}})
        with pytest.raises(ConfigError, match="RunInstances failed"):
            real_e2e_test.run_instance(self._args(), "sid", "skey", None, "key-1")

    def test_missing_instance_id_raises(self, monkeypatch):
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            lambda *a, **k: {"Response": {"InstanceIdSet": []}})
        with pytest.raises(ConfigError, match="no InstanceId"):
            real_e2e_test.run_instance(self._args(), "sid", "skey", None, "key-1")

    def test_success_returns_instance_id(self, monkeypatch):
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            lambda *a, **k: {"Response": {"InstanceIdSet": ["ins-abc123"]}})
        assert real_e2e_test.run_instance(
            self._args(), "sid", "skey", None, "key-1") == "ins-abc123"

    def test_jump_box_named_with_cis_e2e_prefix(self, monkeypatch):
        captured = {}
        def fake_api(service, action, version, region, params, *rest, **kw):
            captured["params"] = params
            return {"Response": {"InstanceIdSet": ["ins-1"]}}
        monkeypatch.setattr("real_e2e_test._tc3_api", fake_api)
        real_e2e_test.run_instance(self._args(), "sid", "skey", None, "key-1")
        name = captured["params"]["InstanceName"]
        assert name.startswith("CIS_E2E_")
        assert captured["params"]["TagSpecification"][0]["Tags"][0]["Value"] == "cis-e2e-jumpbox"


class TestWaitForPublicIp:
    def test_error_response_raises_immediately(self, monkeypatch):
        """An auth/permission error is not transient — must not poll for
        the full BOOT_TIMEOUT_SECONDS, must raise straight away."""
        calls = []

        def fake_api(*a, **k):
            calls.append(1)
            return {"Response": {"Error": {"Code": "UnauthorizedOperation"}}}

        monkeypatch.setattr("real_e2e_test._tc3_api", fake_api)
        monkeypatch.setattr("real_e2e_test.time.sleep", lambda s: None)
        with pytest.raises(ConfigError, match="DescribeInstances failed"):
            real_e2e_test.wait_for_public_ip("ap-guangzhou", "sid", "skey", None, "ins-1")
        assert len(calls) == 1

    def test_transient_api_exception_retries_then_times_out(self, monkeypatch):
        """A transient exception from _tc3_api (e.g. network blip) must be
        swallowed and retried, not propagated — but must still respect the
        overall boot timeout instead of retrying forever."""
        times = iter([0, 1000])  # first call: before deadline; second: past it

        monkeypatch.setattr("real_e2e_test.time.time", lambda: next(times))
        monkeypatch.setattr("real_e2e_test.time.sleep", lambda s: None)
        monkeypatch.setattr("real_e2e_test.BOOT_TIMEOUT_SECONDS", 900)
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            mock.MagicMock(side_effect=ConnectionError("network blip")))
        assert real_e2e_test.wait_for_public_ip(
            "ap-guangzhou", "sid", "skey", None, "ins-1") == ""

    def test_running_with_ip_returns_ip(self, monkeypatch):
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            lambda *a, **k: {"Response": {"InstanceSet": [{
                "InstanceState": "RUNNING",
                "PublicIpAddresses": ["1.2.3.4"],
            }]}})
        assert real_e2e_test.wait_for_public_ip(
            "ap-guangzhou", "sid", "skey", None, "ins-1") == "1.2.3.4"


class TestTerminateInstance:
    def test_api_failure_is_swallowed_not_raised(self, monkeypatch, caplog):
        """Cleanup must never raise — an orphaned real, billed instance is
        worse than a script that reports 'please terminate manually'."""
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            mock.MagicMock(side_effect=RuntimeError("boom")))
        real_e2e_test.terminate_instance("ap-guangzhou", "sid", "skey", None, "ins-1")
        assert "please terminate it manually" in caplog.text

    def test_success_no_raise(self, monkeypatch):
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            lambda *a, **k: {"Response": {}})
        real_e2e_test.terminate_instance("ap-guangzhou", "sid", "skey", None, "ins-1")


class TestDeleteKeypair:
    def test_api_failure_is_swallowed_not_raised(self, monkeypatch, caplog):
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            mock.MagicMock(side_effect=RuntimeError("boom")))
        real_e2e_test.delete_keypair("ap-guangzhou", "sid", "skey", None, "key-1")
        assert "please delete it manually" in caplog.text


class TestParseJunitXml:
    def test_empty_string_returns_note(self):
        summary = real_e2e_test.parse_junit_xml("")
        assert summary.total == 0
        assert "never ran" in summary.note

    def test_malformed_xml_returns_note_not_raise(self):
        summary = real_e2e_test.parse_junit_xml("<not valid xml")
        assert summary.total == 0
        assert "Could not parse JUnit XML" in summary.note

    def test_all_passing(self):
        xml_text = """<?xml version="1.0"?>
<testsuites><testsuite name="pytest" tests="2" time="1.2">
<testcase classname="tests.test_foo" name="test_a" time="0.5"/>
<testcase classname="tests.test_foo" name="test_b" time="0.7"/>
</testsuite></testsuites>"""
        summary = real_e2e_test.parse_junit_xml(xml_text)
        assert summary.total == 2
        assert summary.passed == 2
        assert summary.failed == 0
        assert summary.errors == 0
        assert summary.skipped == 0
        assert summary.note == ""
        assert all(c.status == "passed" for c in summary.cases)

    def test_mixed_pass_fail_error_skip(self):
        xml_text = """<?xml version="1.0"?>
<testsuites><testsuite name="pytest" tests="4" time="2.0">
<testcase classname="tests.test_foo" name="test_pass" time="0.1"/>
<testcase classname="tests.test_foo" name="test_fail" time="0.2">
  <failure message="assert 1 == 2">AssertionError</failure>
</testcase>
<testcase classname="tests.test_foo" name="test_err" time="0.3">
  <error message="boom">RuntimeError: boom</error>
</testcase>
<testcase classname="tests.test_foo" name="test_skip" time="0.0">
  <skipped message="not applicable"/>
</testcase>
</testsuite></testsuites>"""
        summary = real_e2e_test.parse_junit_xml(xml_text)
        assert summary.total == 4
        assert summary.passed == 1
        assert summary.failed == 1
        assert summary.errors == 1
        assert summary.skipped == 1
        statuses = {c.name: c.status for c in summary.cases}
        assert statuses == {
            "test_pass": "passed",
            "test_fail": "failed",
            "test_err": "error",
            "test_skip": "skipped",
        }
        messages = {c.name: c.message for c in summary.cases}
        assert messages["test_fail"] == "assert 1 == 2"
        assert messages["test_err"] == "boom"
        assert messages["test_skip"] == "not applicable"

    def test_no_testsuite_element_returns_note(self):
        summary = real_e2e_test.parse_junit_xml("<somethingelse></somethingelse>")
        assert summary.total == 0
        assert "no <testsuite>" in summary.note


class TestRenderHtmlReport:
    def _steps(self, all_passed: bool) -> list:
        step_result = real_e2e_test.StepResult
        if all_passed:
            return [
                step_result("python_check", "Python 3.12 / git check", 0, "ok"),
                step_result("clone", "Clone repository", 0, "ok"),
            ]
        return [
            step_result("python_check", "Python 3.12 / git check", 0, "ok"),
            step_result("ruff", "ruff check", 1, "boom <script>alert(1)</script>"),
        ]

    def test_all_passed_shows_passed_banner(self):
        junit = real_e2e_test.JunitSummary(total=1, passed=1)
        html_out = real_e2e_test.render_html_report(
            overall_passed=True, started_at=0.0, duration_s=12.3,
            instance_id="ins-1", region="ap-hongkong", zone="ap-hongkong-3",
            image_id="img-1", branch="main", commit="abc123",
            steps=self._steps(True), junit=junit,
        )
        assert "PASSED" in html_out
        assert "FAILED" not in html_out
        assert "Python 3.12 / git check" in html_out
        assert "ins-1" in html_out

    def test_failure_shows_failed_banner_and_escapes_log(self):
        junit = real_e2e_test.JunitSummary(
            total=2, passed=1, failed=1,
            cases=[real_e2e_test.JunitCase(
                "tests.test_foo", "test_fail", 0.1, "failed",
                "boom <script>bad</script>")])
        html_out = real_e2e_test.render_html_report(
            overall_passed=False, started_at=0.0, duration_s=5.0,
            instance_id="ins-2", region="ap-hongkong", zone="ap-hongkong-3",
            image_id="img-1", branch="main", commit="abc123",
            steps=self._steps(False), junit=junit,
        )
        assert "FAILED" in html_out
        # Raw '<script>' must never appear unescaped in the output.
        assert "<script>" not in html_out
        assert "&lt;script&gt;" in html_out
        assert "test_fail" in html_out

    def test_note_rendered_when_junit_has_note(self):
        junit = real_e2e_test.JunitSummary(note="No JUnit XML available (pytest step likely never ran).")
        html_out = real_e2e_test.render_html_report(
            overall_passed=False, started_at=0.0, duration_s=1.0,
            instance_id="ins-3", region="ap-hongkong", zone="ap-hongkong-3",
            image_id="img-1", branch="main", commit="",
            steps=self._steps(False), junit=junit,
        )
        assert "No JUnit XML available" in html_out


class TestFetchRemoteReports:
    def _blob(self, contents: dict) -> str:
        parts = []
        for key, text in contents.items():
            parts.append(f"===CIS_E2E_FILE:{key}===\n{text}===CIS_E2E_END===")
        return "\n".join(parts)

    def test_parses_all_expected_keys(self, monkeypatch, tmp_path):
        steps = real_e2e_test.TOOLCHAIN_STEPS
        keys = [name for name, _ in steps] + ["commit", "pytest_junit", "matrix_results"]
        contents = {k: f"content-for-{k}\n" for k in keys}
        blob = self._blob(contents)
        monkeypatch.setattr(
            "real_e2e_test.subprocess.run",
            lambda *a, **k: mock.MagicMock(stdout=blob))
        result = real_e2e_test.fetch_remote_reports("1.2.3.4", "root", tmp_path / "key", steps)
        for k in keys:
            assert result[k] == f"content-for-{k}\n"

    def test_missing_file_yields_empty_string(self, monkeypatch, tmp_path):
        steps = real_e2e_test.TOOLCHAIN_STEPS
        keys = [name for name, _ in steps] + ["commit", "pytest_junit", "matrix_results"]
        contents = dict.fromkeys(keys, "")
        blob = self._blob(contents)
        monkeypatch.setattr(
            "real_e2e_test.subprocess.run",
            lambda *a, **k: mock.MagicMock(stdout=blob))
        result = real_e2e_test.fetch_remote_reports("1.2.3.4", "root", tmp_path / "key", steps)
        assert all(v == "" for v in result.values())

    def test_ssh_timeout_returns_empty_dict(self, monkeypatch, tmp_path):
        import subprocess as sp
        monkeypatch.setattr(
            "real_e2e_test.subprocess.run",
            mock.MagicMock(side_effect=sp.TimeoutExpired(cmd="ssh", timeout=60)))
        result = real_e2e_test.fetch_remote_reports(
            "1.2.3.4", "root", tmp_path / "key", real_e2e_test.TOOLCHAIN_STEPS)
        assert result == {}

    def test_ssh_os_error_returns_empty_dict(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "real_e2e_test.subprocess.run",
            mock.MagicMock(side_effect=OSError("no route to host")))
        result = real_e2e_test.fetch_remote_reports(
            "1.2.3.4", "root", tmp_path / "key", real_e2e_test.TOOLCHAIN_STEPS)
        assert result == {}


class TestBuildStepResults:
    def test_missing_report_marks_not_run(self):
        results = real_e2e_test.build_step_results({}, real_e2e_test.TOOLCHAIN_STEPS)
        assert all(s.exit_code is None and s.status == "not run" for s in results)

    def test_peels_trailing_exit_code_line(self):
        reports = {"python_check": "some output\nmore output\nEXIT:0\n"}
        results = real_e2e_test.build_step_results(reports, real_e2e_test.TOOLCHAIN_STEPS)
        step = next(s for s in results if s.name == "python_check")
        assert step.exit_code == 0
        assert step.status == "passed"
        assert "EXIT:0" not in step.log

    def test_nonzero_exit_code_marks_failed(self):
        reports = {"ruff": "some error\nEXIT:1\n"}
        results = real_e2e_test.build_step_results(reports, real_e2e_test.TOOLCHAIN_STEPS)
        step = next(s for s in results if s.name == "ruff")
        assert step.exit_code == 1
        assert step.status == "failed"

    def test_malformed_exit_line_treated_as_not_run(self):
        reports = {"mypy": "some output\nEXIT:notanumber\n"}
        results = real_e2e_test.build_step_results(reports, real_e2e_test.TOOLCHAIN_STEPS)
        step = next(s for s in results if s.name == "mypy")
        assert step.exit_code is None
        assert step.status == "not run"


class TestComputeOverallPassed:
    def test_all_zero_exit_codes_is_passed(self):
        step_result = real_e2e_test.StepResult
        steps = [step_result("a", "A", 0, ""), step_result("b", "B", 0, "")]
        assert real_e2e_test.compute_overall_passed(steps) is True

    def test_any_nonzero_exit_code_fails(self):
        step_result = real_e2e_test.StepResult
        steps = [step_result("a", "A", 0, ""), step_result("b", "B", 1, "")]
        assert real_e2e_test.compute_overall_passed(steps) is False

    def test_any_not_run_step_fails(self):
        step_result = real_e2e_test.StepResult
        steps = [step_result("a", "A", 0, ""), step_result("b", "B", None, "")]
        assert real_e2e_test.compute_overall_passed(steps) is False

    def test_profile_results_none_falls_back_to_steps_only(self):
        step_result = real_e2e_test.StepResult
        steps = [step_result("a", "A", 0, "")]
        assert real_e2e_test.compute_overall_passed(steps, None) is True

    def test_all_profile_results_passed_or_skipped_is_passed(self):
        step_result = real_e2e_test.StepResult
        pbr = real_e2e_test.ProfileBuildResult
        steps = [step_result("a", "A", 0, "")]
        profile_results = [
            pbr("rhel8", 1, "passed", 0, 97.0, ["img-1"], "ok"),
            pbr("win2016", 1, "skipped", None, None, [], "", skip_reason="no image configured"),
        ]
        assert real_e2e_test.compute_overall_passed(steps, profile_results) is True

    def test_any_failed_profile_result_fails_even_if_steps_passed(self):
        step_result = real_e2e_test.StepResult
        pbr = real_e2e_test.ProfileBuildResult
        steps = [step_result("a", "A", 0, "")]
        profile_results = [pbr("rhel8", 1, "failed", 1, None, [], "boom")]
        assert real_e2e_test.compute_overall_passed(steps, profile_results) is False


class TestBuildSteps:
    def test_toolchain_mode_returns_original_six_steps(self):
        steps = real_e2e_test.build_steps("toolchain", needs_windows=False)
        assert steps == real_e2e_test.TOOLCHAIN_STEPS

    def test_matrix_mode_without_windows_excludes_windows_step(self):
        steps = real_e2e_test.build_steps("single", needs_windows=False)
        names = [n for n, _ in steps]
        assert "ansible_windows_collection" not in names
        assert "profile_matrix" in names
        assert "ruff" not in names and "pytest" not in names

    def test_matrix_mode_with_windows_includes_windows_step(self):
        steps = real_e2e_test.build_steps("all", needs_windows=True)
        names = [n for n, _ in steps]
        assert "ansible_windows_collection" in names
        assert names.index("ansible_windows_collection") < names.index("profile_matrix")


class TestResolveCombos:
    def _args(self, target_mode, profile=None, level=None, max_parallel_builds=4,
              levels=None):
        return mock.MagicMock(
            target_mode=target_mode, profile=profile, level=level,
            max_parallel_builds=max_parallel_builds,
            levels=levels if levels is not None else (1, 2),
            region="ap-guangzhou", zone="ap-guangzhou-3",
            vpc_id="vpc-gz", subnet_id="subnet-gz", security_group_id="sg-gz")

    def test_single_mode_missing_image_exits(self, monkeypatch):
        monkeypatch.delenv("E2E_TARGET_IMAGE_RHEL8", raising=False)
        with pytest.raises(SystemExit):
            real_e2e_test.resolve_combos(self._args("single", "rhel8", 1))

    def test_single_mode_with_image_returns_one_combo(self, monkeypatch):
        monkeypatch.setenv("E2E_TARGET_IMAGE_RHEL8", "img-rhel8")
        combos, skipped = real_e2e_test.resolve_combos(self._args("single", "rhel8", 1))
        assert len(combos) == 1
        assert combos[0].profile == "rhel8"
        assert combos[0].level == 1
        assert combos[0].image_id == "img-rhel8"
        assert combos[0].family == "linux"
        assert skipped == []

    def test_placement_falls_back_to_jump_box(self, monkeypatch):
        monkeypatch.setenv("E2E_TARGET_IMAGE_RHEL8", "img-rhel8")
        # No unified E2E_TARGET_* placement vars set -> jump box placement.
        combos, _ = real_e2e_test.resolve_combos(self._args("single", "rhel8", 1))
        assert len(combos) == 1
        assert combos[0].image_id == "img-rhel8"

    def test_target_placement_falls_back_to_jump_box(self, monkeypatch):
        for k in ("E2E_TARGET_REGION", "E2E_TARGET_ZONE", "E2E_TARGET_VPC_ID",
                  "E2E_TARGET_SUBNET_ID", "E2E_TARGET_SG_ID"):
            monkeypatch.delenv(k, raising=False)
        args = mock.MagicMock(region="ap-guangzhou", zone="ap-guangzhou-3",
                              vpc_id="vpc-gz", subnet_id="subnet-gz",
                              security_group_id="sg-gz")
        tp = real_e2e_test.target_placement(args)
        assert tp == {"region": "ap-guangzhou", "zone": "ap-guangzhou-3",
                      "vpc_id": "vpc-gz", "subnet_id": "subnet-gz",
                      "security_group_id": "sg-gz"}

    def test_target_placement_unified_with_partial_fallback(self, monkeypatch):
        monkeypatch.setenv("E2E_TARGET_REGION", "ap-hongkong")
        monkeypatch.setenv("E2E_TARGET_VPC_ID", "vpc-hk")
        monkeypatch.delenv("E2E_TARGET_ZONE", raising=False)
        monkeypatch.delenv("E2E_TARGET_SUBNET_ID", raising=False)
        monkeypatch.delenv("E2E_TARGET_SG_ID", raising=False)
        args = mock.MagicMock(region="ap-guangzhou", zone="ap-guangzhou-3",
                              vpc_id="vpc-gz", subnet_id="subnet-gz",
                              security_group_id="sg-gz")
        tp = real_e2e_test.target_placement(args)
        # Unified global placement overrides, unset fields fall back.
        assert tp["region"] == "ap-hongkong"
        assert tp["vpc_id"] == "vpc-hk"
        assert tp["zone"] == "ap-guangzhou-3"
        assert tp["subnet_id"] == "subnet-gz"
        assert tp["security_group_id"] == "sg-gz"

    def test_target_placement_is_global_not_per_profile(self, monkeypatch):
        monkeypatch.setenv("E2E_TARGET_REGION", "ap-hongkong")
        args = mock.MagicMock(region="ap-guangzhou", zone="ap-guangzhou-3",
                              vpc_id="vpc-gz", subnet_id="subnet-gz",
                              security_group_id="sg-gz")
        tp = real_e2e_test.target_placement(args)
        # Same placement for every profile — no per-profile suffix.
        assert tp["region"] == "ap-hongkong"

    def test_all_linux_mode_skips_unconfigured_profiles(self, monkeypatch):
        for p in real_e2e_test.LINUX_PROFILES:
            monkeypatch.delenv(f"E2E_TARGET_IMAGE_{p.upper()}", raising=False)
        monkeypatch.setenv("E2E_TARGET_IMAGE_RHEL8", "img-rhel8")
        combos, skipped = real_e2e_test.resolve_combos(self._args("all-linux"))
        assert {c.profile for c in combos} == {"rhel8"}
        assert len(combos) == 2  # L1 + L2
        assert len(skipped) == (len(real_e2e_test.LINUX_PROFILES) - 1) * 2

    def test_all_linux_level_1_only(self, monkeypatch):
        for p in real_e2e_test.LINUX_PROFILES:
            monkeypatch.delenv(f"E2E_TARGET_IMAGE_{p.upper()}", raising=False)
        monkeypatch.setenv("E2E_TARGET_IMAGE_RHEL8", "img-rhel8")
        combos, skipped = real_e2e_test.resolve_combos(
            self._args("all-linux", levels=(1,)))
        # Only the L1 combo for rhel8 is built.
        assert len(combos) == 1
        assert combos[0].level == 1
        # rhel8's L2 is skipped (image configured, level not requested).
        assert any(c.profile == "rhel8" and c.level == 2 for c in skipped)
        # Every unconfigured profile is skipped for both levels.
        assert all(c.level in (1, 2) for c in skipped)

    def test_all_linux_level_2_only(self, monkeypatch):
        for p in real_e2e_test.LINUX_PROFILES:
            monkeypatch.delenv(f"E2E_TARGET_IMAGE_{p.upper()}", raising=False)
        monkeypatch.setenv("E2E_TARGET_IMAGE_RHEL8", "img-rhel8")
        combos, _ = real_e2e_test.resolve_combos(self._args("all-linux", levels=(2,)))
        assert len(combos) == 1
        assert combos[0].level == 2

    def test_all_mode_windows_combo_without_winrm_password_exits(self, monkeypatch):
        monkeypatch.setenv("E2E_TARGET_IMAGE_WIN2022", "img-win2022")
        monkeypatch.delenv("WINRM_PASSWORD", raising=False)
        with pytest.raises(SystemExit):
            real_e2e_test.resolve_combos(self._args("all"))

    def test_all_mode_windows_combo_with_winrm_password_succeeds(self, monkeypatch):
        monkeypatch.setenv("E2E_TARGET_IMAGE_WIN2022", "img-win2022")
        monkeypatch.setenv("WINRM_PASSWORD", "secret")
        combos, skipped = real_e2e_test.resolve_combos(self._args("all"))
        assert any(c.profile == "win2022" for c in combos)


class TestEnsureNonemptyCombos:
    def _args(self, target_mode):
        return mock.MagicMock(target_mode=target_mode)

    def test_nonempty_combos_does_not_abort(self):
        combos = [real_e2e_test.ProfileCombo("rhel8", 1, "img-rhel8", "linux")]
        real_e2e_test.ensure_nonempty_combos(self._args("all-linux"), combos, [])

    def test_all_skipped_batch_mode_aborts(self):
        skipped = [real_e2e_test.ProfileCombo("rhel8", 1, "", "linux",
                                              skip_reason="no image configured")]
        with pytest.raises(SystemExit):
            real_e2e_test.ensure_nonempty_combos(self._args("all"), [], skipped)

    def test_single_mode_never_aborts_here(self):
        # single mode already handles a missing image inside resolve_combos().
        real_e2e_test.ensure_nonempty_combos(self._args("single"), [], [])

    def test_nothing_configured_nothing_skipped_does_not_abort(self):
        real_e2e_test.ensure_nonempty_combos(self._args("all-linux"), [], [])


class TestParseLevels:
    def test_single_levels(self):
        assert real_e2e_test._parse_levels("1") == (1,)
        assert real_e2e_test._parse_levels("2") == (2,)
        assert real_e2e_test._parse_levels("l1") == (1,)
        assert real_e2e_test._parse_levels("L2") == (2,)

    def test_both_aliases(self):
        assert real_e2e_test._parse_levels("both") == (1, 2)
        assert real_e2e_test._parse_levels("1,2") == (1, 2)
        assert real_e2e_test._parse_levels("2,1") == (1, 2)

    def test_invalid_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            real_e2e_test._parse_levels("3")
        with pytest.raises(argparse.ArgumentTypeError):
            real_e2e_test._parse_levels("")


class TestParallelDefault:
    def test_env_var_default(self, monkeypatch):
        monkeypatch.setenv("E2E_MAX_PARALLEL_BUILDS", "7")
        monkeypatch.setenv("E2E_LEVELS", "1")
        # monkeypatch doesn't restore argparse defaults; call the real parser
        # by injecting sys.argv. Easier: directly exercise the resolution by
        # building args via parse_args with a minimal argv.
        monkeypatch.setattr(
            sys, "argv",
            ["real_e2e_test", "--region", "ap-guangzhou", "--zone", "ap-guangzhou-3",
             "--vpc-id", "v", "--subnet-id", "s", "--security-group-id", "g",
             "--target-mode", "all-linux"])
        args = real_e2e_test.parse_args()
        assert args.max_parallel_builds == 7
        assert args.levels == (1,)

    def test_default_four_when_env_unset(self, monkeypatch):
        monkeypatch.delenv("E2E_MAX_PARALLEL_BUILDS", raising=False)
        monkeypatch.delenv("E2E_LEVELS", raising=False)
        monkeypatch.setattr(
            sys, "argv",
            ["real_e2e_test", "--region", "ap-guangzhou", "--zone", "ap-guangzhou-3",
             "--vpc-id", "v", "--subnet-id", "s", "--security-group-id", "g",
             "--target-mode", "all-linux"])
        args = real_e2e_test.parse_args()
        assert args.max_parallel_builds == 4
        assert args.levels == (1, 2)

    def test_cli_flag_overrides_env(self, monkeypatch):
        monkeypatch.setenv("E2E_MAX_PARALLEL_BUILDS", "9")
        monkeypatch.setattr(
            sys, "argv",
            ["real_e2e_test", "--region", "ap-guangzhou", "--zone", "ap-guangzhou-3",
             "--vpc-id", "v", "--subnet-id", "s", "--security-group-id", "g",
             "--target-mode", "all-linux", "--max-parallel-builds", "2"])
        args = real_e2e_test.parse_args()
        assert args.max_parallel_builds == 2


class TestBuildProfileResults:
    def test_skipped_combos_become_skipped_results(self):
        skipped = [real_e2e_test.ProfileCombo("win2016", 1, "", "windows")]
        results = real_e2e_test.build_profile_results(skipped, "")
        assert len(results) == 1
        assert results[0].status == "skipped"
        assert results[0].skip_reason == "no image configured"

    def test_empty_matrix_json_yields_only_skips(self):
        skipped = [real_e2e_test.ProfileCombo("win2016", 1, "", "windows")]
        results = real_e2e_test.build_profile_results(skipped, "   ")
        assert len(results) == 1

    def test_matrix_json_merged_with_skips(self):
        skipped = [real_e2e_test.ProfileCombo("win2016", 1, "", "windows")]
        matrix_json = (
            '[{"profile": "rhel8", "level": 1, "exit_code": 0, "score": 95.0, '
            '"image_ids": ["img-1"], "log_tail": "ok"}]'
        )
        results = real_e2e_test.build_profile_results(skipped, matrix_json)
        assert len(results) == 2
        rhel8 = next(r for r in results if r.profile == "rhel8")
        assert rhel8.status == "passed"
        assert rhel8.score == 95.0
        assert rhel8.image_ids == ["img-1"]

    def test_matrix_json_nonzero_exit_marks_failed(self):
        matrix_json = (
            '[{"profile": "rhel8", "level": 2, "exit_code": 1, "score": null, '
            '"image_ids": [], "log_tail": "boom"}]'
        )
        results = real_e2e_test.build_profile_results([], matrix_json)
        assert results[0].status == "failed"

    def test_matrix_json_carries_instance_type(self):
        matrix_json = (
            '[{"profile": "rhel8", "level": 1, "exit_code": 0, "score": 90.0, '
            '"image_ids": ["img-1"], "log_tail": "ok", '
            '"instance_type": "SA2.MEDIUM2"}]'
        )
        results = real_e2e_test.build_profile_results([], matrix_json)
        assert results[0].instance_type == "SA2.MEDIUM2"

    def test_matrix_json_missing_instance_type_defaults_empty(self):
        matrix_json = (
            '[{"profile": "rhel8", "level": 1, "exit_code": 0, "score": 90.0, '
            '"image_ids": ["img-1"], "log_tail": "ok"}]'
        )
        results = real_e2e_test.build_profile_results([], matrix_json)
        assert results[0].instance_type == ""

    def test_malformed_matrix_json_does_not_raise(self):
        results = real_e2e_test.build_profile_results([], "not valid json")
        assert results == []


class TestRenderHtmlReportProfileMatrix:
    def test_profile_results_render_matrix_section(self):
        junit = real_e2e_test.JunitSummary()
        steps = [real_e2e_test.StepResult("python_check", "Python check", 0, "ok")]
        profile_results = [
            real_e2e_test.ProfileBuildResult(
                "rhel8", 1, "passed", 0, 97.2, ["img-abc"], "build ok",
                instance_type="SA2.MEDIUM2"),
            real_e2e_test.ProfileBuildResult(
                "win2016", 1, "skipped", None, None, [], "",
                skip_reason="no image configured"),
        ]
        html_out = real_e2e_test.render_html_report(
            overall_passed=True, started_at=0.0, duration_s=1.0,
            instance_id="ins-1", region="ap-guangzhou", zone="ap-guangzhou-3",
            image_id="img-jump", branch="main", commit="abc",
            steps=steps, junit=junit, profile_results=profile_results,
        )
        assert "Profile Build Matrix" in html_out
        assert "rhel8" in html_out
        assert "img-abc" in html_out
        assert "no image configured" in html_out
        assert "SA2.MEDIUM2" in html_out
        assert "Instance Type" in html_out

    def test_no_profile_results_omits_matrix_section(self):
        junit = real_e2e_test.JunitSummary()
        steps = [real_e2e_test.StepResult("python_check", "Python check", 0, "ok")]
        html_out = real_e2e_test.render_html_report(
            overall_passed=True, started_at=0.0, duration_s=1.0,
            instance_id="ins-1", region="ap-guangzhou", zone="ap-guangzhou-3",
            image_id="img-jump", branch="main", commit="abc",
            steps=steps, junit=junit,
        )
        assert "Profile Build Matrix" not in html_out

    def test_log_path_shown_when_provided(self):
        junit = real_e2e_test.JunitSummary()
        steps = [real_e2e_test.StepResult("python_check", "Python check", 0, "ok")]
        html_out = real_e2e_test.render_html_report(
            overall_passed=False, started_at=0.0, duration_s=1.0,
            instance_id="ins-1", region="ap-guangzhou", zone="ap-guangzhou-3",
            image_id="img-jump", branch="main", commit="abc",
            steps=steps, junit=junit, log_path="logs/e2e-123.log",
        )
        assert "logs/e2e-123.log" in html_out
        assert "Full remote log" in html_out

    def test_log_path_omitted_when_none(self):
        junit = real_e2e_test.JunitSummary()
        steps = [real_e2e_test.StepResult("python_check", "Python check", 0, "ok")]
        html_out = real_e2e_test.render_html_report(
            overall_passed=True, started_at=0.0, duration_s=1.0,
            instance_id="ins-1", region="ap-guangzhou", zone="ap-guangzhou-3",
            image_id="img-jump", branch="main", commit="abc",
            steps=steps, junit=junit,
        )
        assert "Full remote log" not in html_out

    def test_log_path_is_escaped(self):
        junit = real_e2e_test.JunitSummary()
        steps = [real_e2e_test.StepResult("python_check", "Python check", 0, "ok")]
        html_out = real_e2e_test.render_html_report(
            overall_passed=False, started_at=0.0, duration_s=1.0,
            instance_id="ins-1", region="ap-guangzhou", zone="ap-guangzhou-3",
            image_id="img-jump", branch="main", commit="abc",
            steps=steps, junit=junit, log_path="logs/e2e-<x>.log",
        )
        assert "<x>" not in html_out
        assert "&lt;x&gt;" in html_out

    def test_profile_log_tail_is_escaped(self):
        junit = real_e2e_test.JunitSummary()
        steps = [real_e2e_test.StepResult("python_check", "Python check", 0, "ok")]
        profile_results = [
            real_e2e_test.ProfileBuildResult(
                "rhel8", 2, "failed", 1, None, [], "boom <script>bad</script>"),
        ]
        html_out = real_e2e_test.render_html_report(
            overall_passed=False, started_at=0.0, duration_s=1.0,
            instance_id="ins-1", region="ap-guangzhou", zone="ap-guangzhou-3",
            image_id="img-jump", branch="main", commit="abc",
            steps=steps, junit=junit, profile_results=profile_results,
        )
        assert "<script>bad</script>" not in html_out
        assert "&lt;script&gt;" in html_out


class TestRunMatrixToml:
    def test_toml_template_includes_cis_e2e_instance_name(self):
        tpl = real_e2e_test.RUN_MATRIX_PY
        # The embedded toml template names every target build CVM with a
        # CIS_E2E_<profile>_L<level> prefix.
        assert 'instance_name = "CIS_E2E_{profile}_L{level}"' in tpl

    def test_run_matrix_renders_instance_name_line(self):
        # Render the embedded run_matrix.py with placeholders replaced and
        # confirm it references instance_name in the toml build section.
        rendered = (real_e2e_test.RUN_MATRIX_PY
            .replace("REPO_DIR_PLACEHOLDER", "/root/repo")
            .replace("MATRIX_WORKDIR_PLACEHOLDER", "/root/wd")
            .replace("CIS_IMAGE_BIN_PLACEHOLDER", "/root/repo/.venv/bin/ohbs-image")
            .replace("BUILD_INSTANCE_TYPE_PLACEHOLDER", "S5.MEDIUM2")
            .replace("REGION_PLACEHOLDER", "ap-guangzhou")
            .replace("ZONE_PLACEHOLDER", "ap-guangzhou-7")
            .replace("VPC_ID_PLACEHOLDER", "vpc-1")
            .replace("SUBNET_ID_PLACEHOLDER", "subnet-1")
            .replace("SECURITY_GROUP_ID_PLACEHOLDER", "sg-1"))
        assert 'instance_name = "CIS_E2E_{profile}_L{level}"' in rendered

    def test_run_matrix_writes_progress_incrementally(self):
        # The embedded runner must print a progress line per finished build
        # and rewrite matrix_results.json as each one lands, so the caller
        # can watch progress instead of waiting for the whole batch.
        tpl = real_e2e_test.RUN_MATRIX_PY
        assert "def record(combo, result):" in tpl
        assert "threading.Lock()" in tpl
        assert "[matrix]" in tpl
        assert "results_path.write_text(json.dumps(results))" in tpl

    def test_matrix_remote_script_tees_output_live(self):
        # run_step must tee (not redirect-then-cat) so build output streams
        # live to the SSH stdout during the run, not only at the end.
        assert "tee \"$LOGDIR/$name.log\"" in real_e2e_test.MATRIX_REMOTE_SCRIPT
        assert "PIPESTATUS" in real_e2e_test.MATRIX_REMOTE_SCRIPT

    def test_targets_get_public_ip(self):
        # Targets are reached from the jump box over the public internet
        # (they may be in a different region/VPC), so they need a public IP.
        assert "associate_public_ip = true" in real_e2e_test.RUN_MATRIX_PY

    def test_build_one_does_not_use_quiet(self):
        # --quiet swallows the packer/ansible detail we need to diagnose a
        # failed build, so build_one must NOT pass it.
        assert "--quiet" not in real_e2e_test.RUN_MATRIX_PY

    def test_log_tail_truncated_to_12000(self):
        assert "[-12000:]" in real_e2e_test.RUN_MATRIX_PY

    def test_build_one_parses_combined_stream(self):
        # `ohbs-image build` writes its readable output (packer + ok()/info()
        # summary, including image ID and score) to STDERR, so build_one must
        # parse stdout+stderr together, not stdout alone.
        rendered = (real_e2e_test.RUN_MATRIX_PY
            .replace("REPO_DIR_PLACEHOLDER", "/root/repo")
            .replace("MATRIX_WORKDIR_PLACEHOLDER", "/root/wd")
            .replace("CIS_IMAGE_BIN_PLACEHOLDER", "/root/repo/.venv/bin/ohbs-image")
            .replace("BUILD_INSTANCE_TYPE_PLACEHOLDER", "S5.MEDIUM2")
            .replace("REGION_PLACEHOLDER", "ap-guangzhou")
            .replace("ZONE_PLACEHOLDER", "ap-guangzhou-7")
            .replace("VPC_ID_PLACEHOLDER", "vpc-1")
            .replace("SUBNET_ID_PLACEHOLDER", "subnet-1")
            .replace("SECURITY_GROUP_ID_PLACEHOLDER", "sg-1"))
        assert "combined = cp.stdout + \"\\n\" + cp.stderr" in rendered
        assert "_extract_image_ids(all_lines)" in rendered
        # Score is parsed from "Re-audit score: NN%" (not _extract_score).
        assert "re-audit score:" in rendered.lower()
        # _extract_score is no longer imported for score parsing.
        assert "from ohbs_image import _extract_image_ids" in rendered
        assert "import _extract_image_ids, _extract_score" not in rendered

    def test_retry_on_stockout(self):
        # build_one must retry with a fallback instance type when the primary
        # fails with ResourceInsufficient.SpecifiedInstanceType (stockout).
        rendered = real_e2e_test.RUN_MATRIX_PY
        assert "ResourceInsufficient.SpecifiedInstanceType" in rendered
        assert "DEFAULT_FALLBACK_INSTANCE_TYPES" in rendered
        assert "S6.MEDIUM2" in rendered
        assert "SA2.MEDIUM2" in rendered

    def test_instance_types_env_override(self):
        # E2E_BUILD_INSTANCE_TYPES overrides the whole candidate list.
        assert "E2E_BUILD_INSTANCE_TYPES" in real_e2e_test.RUN_MATRIX_PY

    def test_result_records_actual_instance_type(self):
        # The result dict must carry which instance type actually built, so
        # the HTML report can show the fallback that succeeded.
        assert '"instance_type": instance_type' in real_e2e_test.RUN_MATRIX_PY or \
               "'instance_type': instance_type" in real_e2e_test.RUN_MATRIX_PY

    def test_disk_block_sa_uses_cloud_ssd(self):
        # SA-series instance types don't support the default CLOUD_PREMIUM
        # root disk; the toml must pass disk_type=CLOUD_SSD via [build.packer].
        assert "CLOUD_SSD" in real_e2e_test.RUN_MATRIX_PY
        assert "startswith(\"SA\")" in real_e2e_test.RUN_MATRIX_PY
        assert "disk_block" in real_e2e_test.RUN_MATRIX_PY

    def test_run_matrix_renders_disk_block(self):
        rendered = (real_e2e_test.RUN_MATRIX_PY
            .replace("REPO_DIR_PLACEHOLDER", "/root/repo")
            .replace("MATRIX_WORKDIR_PLACEHOLDER", "/root/wd")
            .replace("CIS_IMAGE_BIN_PLACEHOLDER", "/root/repo/.venv/bin/ohbs-image")
            .replace("BUILD_INSTANCE_TYPE_PLACEHOLDER", "SA5.MEDIUM2")
            .replace("REGION_PLACEHOLDER", "ap-guangzhou")
            .replace("ZONE_PLACEHOLDER", "ap-guangzhou-7")
            .replace("VPC_ID_PLACEHOLDER", "vpc-1")
            .replace("SUBNET_ID_PLACEHOLDER", "subnet-1")
            .replace("SECURITY_GROUP_ID_PLACEHOLDER", "sg-1"))
        import ast
        ast.parse(rendered)
        assert "disk_block=_disk_block(instance_type)" in rendered


class TestRedactLine:
    def test_redacts_secret_key_and_id(self, monkeypatch):
        monkeypatch.setenv("TENCENTCLOUD_SECRET_KEY", "super-secret-key-123")
        monkeypatch.setenv("TENCENTCLOUD_SECRET_ID", "AKIDabc")
        out = real_e2e_test._redact_line(
            "connecting with key=super-secret-key-123 id=AKIDabc")
        assert "super-secret-key-123" not in out
        assert "AKIDabc" not in out
        assert "***" in out

    def test_redacts_winrm_password(self, monkeypatch):
        monkeypatch.setenv("WINRM_PASSWORD", "WinP@ss#456")
        out = real_e2e_test._redact_line("net user Administrator 'WinP@ss#456'")
        assert "WinP@ss#456" not in out
        assert "***" in out

    def test_unrelated_line_unchanged(self, monkeypatch):
        monkeypatch.setenv("WINRM_PASSWORD", "secret-pw")
        line = "no secrets here"
        assert real_e2e_test._redact_line(line) == line

    def test_unset_secret_leaves_text_alone(self, monkeypatch):
        monkeypatch.delenv("WINRM_PASSWORD", raising=False)
        monkeypatch.delenv("TENCENTCLOUD_SECRET_KEY", raising=False)
        monkeypatch.delenv("TENCENTCLOUD_SECRET_ID", raising=False)
        line = "WINRM_PASSWORD=any-value-here"
        assert real_e2e_test._redact_line(line) == line


class TestDeleteBatchImages:
    def test_empty_list_is_noop(self, monkeypatch):
        called = []
        monkeypatch.setattr("real_e2e_test._tc3_api", lambda *a, **k: called.append(1))
        real_e2e_test.delete_batch_images("ap-guangzhou", "sid", "skey", None, [])
        assert called == []

    def test_success_no_raise(self, monkeypatch):
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            lambda *a, **k: {"Response": {}})
        real_e2e_test.delete_batch_images(
            "ap-guangzhou", "sid", "skey", None, ["img-1", "img-2"])

    def test_api_failure_is_swallowed_not_raised(self, monkeypatch, caplog):
        monkeypatch.setattr(
            "real_e2e_test._tc3_api",
            mock.MagicMock(side_effect=RuntimeError("boom")))
        real_e2e_test.delete_batch_images("ap-guangzhou", "sid", "skey", None, ["img-1"])
        assert "please delete them manually" in caplog.text
