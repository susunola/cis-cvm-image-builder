"""Tests for ciscvm — CIS-hardened Golden Image Builder."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from unittest import mock

import pytest

import ciscvm
from ciscvm import (
    PROFILES,
    SAMPLE_CONFIG,
    ConfigError,
    PackerResult,
    ResolvedConfig,
    _bundle_role,
    _check_bundled_role,
    _clean_is_safe,
    _color,
    _format_hcl_value,
    _validate_value_present,
    build_parser,
    cmd_clean,
    cmd_init,
    load_config,
    main,
    render_all,
    render_install,
    render_pkrvars,
    render_site,
    resolve,
    run_packer,
    run_preflight,
)

LINUX_PROFILES = [k for k, v in PROFILES.items() if v.get("family") != "windows"]
WIN_PROFILES = [k for k, v in PROFILES.items() if v.get("family") == "windows"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _suppress_logging(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="ciscvm")


@pytest.fixture
def valid_toml() -> dict:
    raw = tomllib.loads(SAMPLE_CONFIG)
    return raw


def _write_config(tmp_path: Path, data: dict) -> Path:
    import tomli_w
    path = tmp_path / "ciscvm.toml"
    path.write_text(tomli_w.dumps(data), encoding="utf-8")
    return path


def _make_win_toml(profile_name: str) -> dict:
    """Create a valid TOML dict for a Windows profile."""
    return {
        "build": {
            "profile": profile_name,
            "region": "ap-guangzhou",
            "zone": "ap-guangzhou-4",
            "instance_type": "S5.MEDIUM2",
            "source_image_id": "img-abc123",
            "vpc_id": "vpc-abc123",
            "subnet_id": "subnet-abc123",
            "security_group_id": "sg-abc123",
            "associate_public_ip": True,
        },
        "image": {"name_prefix": "win-cis", "copy_regions": []},
        "cis": {"level": 1},
        "cloud": {"secret_id_env": "TENCENTCLOUD_SECRET_ID", "secret_key_env": "TENCENTCLOUD_SECRET_KEY",
                  "winrm_password_env": "WINRM_PASSWORD"},
        "meta": {"os_tag": "windows-2022", "benchmark": "CIS-v1.0.0"},
    }


# ---------------------------------------------------------------------------
# Config loading & validation
# ---------------------------------------------------------------------------
class TestLoadConfig:
    def test_valid_config(self, valid_toml, tmp_path):
        cfg = _write_config(tmp_path, valid_toml)
        result = load_config(cfg)
        assert result["build"]["profile"] == "tencentos3"
        assert result["cis"]["level"] == 1

    def test_missing_file(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(tmp_path / "nonexistent.toml")

    def test_bad_toml_syntax(self, tmp_path):
        p = tmp_path / "bad.toml"
        p.write_text("this is [not valid {{{ toml", encoding="utf-8")
        with pytest.raises(ConfigError, match="parse"):
            load_config(p)

    def test_missing_section(self, valid_toml, tmp_path):
        del valid_toml["build"]
        cfg = _write_config(tmp_path, valid_toml)
        with pytest.raises(ConfigError, match="Missing \\[build\\]"):
            load_config(cfg)

    def test_missing_key(self, valid_toml, tmp_path):
        del valid_toml["build"]["region"]
        cfg = _write_config(tmp_path, valid_toml)
        with pytest.raises(ConfigError, match="build.*region"):
            load_config(cfg)

    def test_unknown_profile(self, valid_toml, tmp_path):
        valid_toml["build"]["profile"] = "freebsd13"
        cfg = _write_config(tmp_path, valid_toml)
        with pytest.raises(ConfigError, match="Unknown profile"):
            load_config(cfg)

    def test_bad_level(self, valid_toml, tmp_path):
        valid_toml["cis"]["level"] = 3
        cfg = _write_config(tmp_path, valid_toml)
        with pytest.raises(ConfigError, match="level must be 1 or 2"):
            load_config(cfg)

    def test_instance_type_no_prefix(self, valid_toml, tmp_path):
        valid_toml["build"]["instance_type"] = "S5-MEDIUM2"
        cfg = _write_config(tmp_path, valid_toml)
        with pytest.raises(ConfigError, match="instance_type"):
            load_config(cfg)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
class TestValidateValuePresent:
    def test_empty(self):
        assert _validate_value_present("x", "") is not None

    def test_placeholder(self):
        assert _validate_value_present("x", "img-xxxxxxxx") is not None

    def test_real_id_with_x(self):
        # Real IDs like "img-xxxxxxxx01" should not be flagged
        assert _validate_value_present("x", "img-xxxxxxxx01") is None

    def test_valid(self):
        assert _validate_value_present("x", "img-abc123") is None

    def test_none(self):
        assert _validate_value_present("x", None) is not None

    def test_zero_is_valid(self):
        """Zero should not be treated as empty."""
        assert _validate_value_present("x", 0) is None

    def test_false_is_valid(self):
        """False should not be treated as empty."""
        assert _validate_value_present("x", False) is None

    def test_empty_string(self):
        assert _validate_value_present("x", "") is not None


class TestFormatHCLValue:
    def test_bool_true(self):
        assert _format_hcl_value(True) == "true"

    def test_bool_false(self):
        assert _format_hcl_value(False) == "false"

    def test_int(self):
        assert _format_hcl_value(42) == "42"

    def test_float(self):
        assert _format_hcl_value(3.14) == "3.14"

    def test_list(self):
        assert _format_hcl_value(["ap-shanghai", "ap-beijing"]) == '["ap-shanghai", "ap-beijing"]'

    def test_string(self):
        assert _format_hcl_value("hello") == '"hello"'

    def test_string_escapes_double_quote(self):
        # Embedded quotes must be escaped so they can't break out of / inject HCL.
        assert _format_hcl_value('my"evil') == '"my\\"evil"'

    def test_string_escapes_backslash(self):
        assert _format_hcl_value("a\\b") == '"a\\\\b"'

    def test_string_escapes_backslash_before_quote(self):
        # Backslash escaped first, then quote — no double-escaping of the quote.
        assert _format_hcl_value('a\\"b') == '"a\\\\\\"b"'


# ---------------------------------------------------------------------------
# resolve()
# ---------------------------------------------------------------------------
class TestResolve:
    def test_linux_profile(self, valid_toml):
        r = resolve(valid_toml)
        assert isinstance(r, ResolvedConfig)
        assert r.profile_name == "tencentos3"
        assert r.level == 1
        assert r.cis_level_tag == "level1-server"
        assert r.ssh_username == "root"
        assert r.role_dir == "cis_tencentos3"
        assert r.associate_public_ip is False
        assert r.family == ""

    def test_level2(self, valid_toml):
        valid_toml["cis"]["level"] = 2
        r = resolve(valid_toml)
        assert r.cis_level_tag == "level2-server"
        assert r.level == 2

    def test_meta_overrides(self, valid_toml):
        valid_toml["meta"] = {"os_tag": "custom-os", "benchmark": "custom-v3"}
        r = resolve(valid_toml)
        assert r.image_os_tag == "custom-os"
        assert r.image_benchmark == "custom-v3"

    def test_image_name_override(self, valid_toml):
        valid_toml["image"]["name"] = "my-cis-image"
        r = resolve(valid_toml)
        assert r.image_name_override == "my-cis-image"
        assert ciscvm._image_name(r) == "my-cis-image"

    def test_image_name_auto_when_empty(self, valid_toml):
        assert resolve(valid_toml).image_name_override == ""
        name = ciscvm._image_name(resolve(valid_toml))
        assert name.startswith("tencentos3-cis-level1-")
        assert re.fullmatch(r"[A-Za-z0-9._-]+", name)

    def test_image_name_invalid_chars(self, valid_toml):
        valid_toml["image"]["name"] = "bad/name;rm"
        with pytest.raises(ConfigError, match=r"\[image\].name"):
            resolve(valid_toml)

    def test_image_name_too_long(self, valid_toml):
        valid_toml["image"]["name"] = "x" * 61
        with pytest.raises(ConfigError, match=r"\[image\].name"):
            resolve(valid_toml)

    def test_assume_role_default_off(self, valid_toml):
        r = resolve(valid_toml)
        assert r.assume_role_arn == ""
        assert r.assume_role_session == "ciscvm"
        assert r.assume_role_duration == 7200

    def test_assume_role_configured(self, valid_toml):
        valid_toml["cloud"]["assume_role_arn"] = \
            "qcs::cam::uin/1234567890:roleName/CrossAccountBuilder"
        valid_toml["cloud"]["assume_role_session"] = "my-build"
        valid_toml["cloud"]["assume_role_duration"] = 3600
        r = resolve(valid_toml)
        assert r.assume_role_arn.endswith("CrossAccountBuilder")
        assert r.assume_role_session == "my-build"
        assert r.assume_role_duration == 3600

    def test_assume_role_invalid_arn(self, valid_toml):
        valid_toml["cloud"]["assume_role_arn"] = "bad arn;rm -rf"
        with pytest.raises(ConfigError, match=r"assume_role_arn"):
            resolve(valid_toml)

    def test_assume_role_duration_range(self, valid_toml):
        valid_toml["cloud"]["assume_role_duration"] = 99999
        with pytest.raises(ConfigError, match=r"assume_role_duration"):
            resolve(valid_toml)

    def test_security_token_env_default(self, valid_toml):
        r = resolve(valid_toml)
        assert r.security_token_env == "TENCENTCLOUD_SECURITY_TOKEN"

    def test_security_token_env_custom(self, valid_toml):
        valid_toml["cloud"]["security_token_env"] = "MY_STS_TOKEN"
        r = resolve(valid_toml)
        assert r.security_token_env == "MY_STS_TOKEN"

    def test_security_token_env_rendered(self, valid_toml):
        import tempfile
        from pathlib import Path
        valid_toml["cloud"]["security_token_env"] = "MY_STS_TOKEN"
        r = resolve(valid_toml)
        with tempfile.TemporaryDirectory() as td:
            wd = Path(td) / "build"
            render_all(wd, r)
            hcl = (wd / "packer" / "main.pkr.hcl").read_text()
            assert 'default   = env("MY_STS_TOKEN")' in hcl
            assert "security_token              = var.security_token" in hcl
            assert "__SECURITY_TOKEN_ENV__" not in hcl

    def test_security_token_env_invalid(self, valid_toml):
        import tempfile
        from pathlib import Path
        valid_toml["cloud"]["security_token_env"] = "MY-TOKEN;rm"
        r = resolve(valid_toml)
        with tempfile.TemporaryDirectory() as td:
            wd = Path(td) / "build"
            with pytest.raises(ConfigError, match=r"security_token_env"):
                render_all(wd, r)


class TestExtractImageIds:
    def test_multi_region_artifact(self):
        lines = [
            "==> tencentcloud-cvm.default: Creating image...",
            "==> Builds finished. The artifacts of successful builds are:",
            "--> tencentcloud-cvm.default: Tencentcloud images(ap-guangzhou: img-1p9mwidq",
            "ap-hongkong: img-50m2n24g) were created.",
            "",
        ]
        assert ciscvm._extract_image_ids(lines) == ["img-1p9mwidq", "img-50m2n24g"]

    def test_single_region_artifact(self):
        lines = [
            "--> tencentcloud-cvm.default: Tencentcloud images(ap-guangzhou: img-abc123) were created.",
        ]
        assert ciscvm._extract_image_ids(lines) == ["img-abc123"]

    def test_legacy_created_image_id(self):
        lines = ["Created image ID: img-legacy999"]
        assert ciscvm._extract_image_ids(lines) == ["img-legacy999"]

    def test_no_match(self):
        assert ciscvm._extract_image_ids(["==> building...", "==> done"]) == []

    def test_windows_profile(self):
        data = _make_win_toml("win2022")
        r = resolve(data)
        assert r.family == "windows"
        assert r.winrm_username == "Administrator"
        assert r.winrm_password_env == "WINRM_PASSWORD"
        assert r.role_dir == "cis_win2022"
        assert r.ssh_username == ""

    def test_ubuntu_uses_ssh_ubuntu(self, valid_toml):
        valid_toml["build"]["profile"] = "ubuntu2204"
        r = resolve(valid_toml)
        assert r.ssh_username == "ubuntu"
        assert r.family == ""

    def test_copy_regions_string_raises(self, valid_toml):
        """Passing a string for copy_regions must raise ConfigError."""
        valid_toml["image"]["copy_regions"] = "ap-shanghai"
        with pytest.raises(ConfigError, match="copy_regions"):
            resolve(valid_toml)

    def test_copy_regions_list_ok(self, valid_toml):
        valid_toml["image"]["copy_regions"] = ["ap-shanghai", "ap-beijing"]
        r = resolve(valid_toml)
        assert r.image_copy_regions == ["ap-shanghai", "ap-beijing"]

    def test_empty_copy_regions(self, valid_toml):
        valid_toml["image"]["copy_regions"] = []
        r = resolve(valid_toml)
        assert r.image_copy_regions == []


# ---------------------------------------------------------------------------
# Render functions
# ---------------------------------------------------------------------------
class TestRenderPkrvars:
    def test_linux_output(self, valid_toml):
        r = resolve(valid_toml)
        out = render_pkrvars(r)
        assert "ssh_username" in out
        assert "root" in out

    def test_windows_output(self):
        r = resolve(_make_win_toml("win2022"))
        out = render_pkrvars(r)
        assert "winrm_username" in out
        assert "ssh_username" not in out


class TestRenderInstall:
    def test_dnf(self):
        p = PROFILES["tencentos3"]
        out = render_install(p)
        assert "cis-os engine" in out
        assert "dnf makecache" in out
        assert "ansible-core" in out

    def test_apt(self):
        p = PROFILES["ubuntu2204"]
        out = render_install(p)
        assert "apt-get update" in out
        assert "apt-get install" in out

    def test_zypper(self):
        p = PROFILES["sles15"]
        out = render_install(p)
        assert "zypper refresh" in out
        assert "zypper install" in out


class TestRenderSite:
    def test_linux_level1(self):
        p = PROFILES["tencentos3"]
        out = render_site(p, level=1)
        assert "cis_fail_on_findings" in out
        assert "cis_profile: L1" in out
        assert "cis_tencentos3" in out
        assert "localhost" in out

    def test_linux_level2(self):
        p = PROFILES["tencentos4"]
        out = render_site(p, level=2)
        assert "cis_profile: L2" in out
        assert "cis_tencentos4" in out

    def test_windows_site_yml(self):
        p = PROFILES["win2022"]
        out = render_site(p, level=1)
        assert "cis_profile: L1" in out
        assert "cis_win2022" in out
        assert "ansible_connection: winrm" in out
        assert "hosts: all" in out


class TestRenderAll:
    def test_linux_renders_correctly(self, valid_toml, tmp_path):
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        assert (wd / "packer" / "main.pkr.hcl").exists()
        assert (wd / "packer" / "auto.pkrvars.hcl").exists()
        assert (wd / "ansible" / "site.yml").exists()
        assert (wd / "packer" / "scripts" / "install-ansible.sh").exists()
        assert os.access(wd / "packer" / "scripts" / "install-ansible.sh", os.X_OK)
        assert (wd / "packer" / "scripts" / "ciscvm-finalize.sh").exists()
        assert os.access(wd / "packer" / "scripts" / "ciscvm-finalize.sh", os.X_OK)
        assert (wd / "ansible" / "roles" / "cis_tencentos3" / "tasks" / "main.yml").exists()
        assert not (wd / "packer" / "scripts" / "verify-cis.sh").exists()

    def test_no_unreplaced_markers(self, valid_toml, tmp_path):
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "__CLEAN_CMD__" not in hcl
        assert "__WINRM_PASSWORD_ENV__" not in hcl
        # HCL itself must not contain bare semicolons.  Shell snippets inside
        # quoted inline strings (e.g. the awk in the ssh-guard provisioner)
        # legitimately use ';' — they are quoted shell strings, not HCL syntax.
        # Comment lines (starting with # or //) are also exempt.
        for ln in hcl.splitlines():
            stripped = ln.strip()
            if stripped.startswith('"') and stripped.rstrip(',').endswith('"'):
                continue  # quoted shell string (inline list element)
            if stripped.startswith(("#", "//")):
                continue  # comment
            assert ";" not in ln, "semicolons are not valid in HCL: %r" % ln

    def test_banner_and_report_provisioner_present(self, valid_toml, tmp_path):
        """v0.10.0+: the HCL must collect the audit JSON and run the finalize
        step that writes /etc/ciscvm/banner, /etc/motd, and /opt/ciscvm-REPORT.md."""
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        finalize = (wd / "packer" / "scripts" / "ciscvm-finalize.sh").read_text()
        # HCL: re-audit must keep the result so we can persist it; new
        # provisioner #7.5 collects it; new #8 runs the finalize.
        assert "cis_keep_remote_artifacts=true" in hcl
        assert "ciscvm-AUDIT-RESULT.json" in hcl
        assert "collect-audit.sh" in hcl
        assert "ciscvm-finalize.sh" in hcl
        assert 'source      = "packer/scripts/ciscvm-finalize.sh"' in hcl
        assert 'destination = "/opt/ciscvm-ansible/ciscvm-finalize.sh"' in hcl
        assert 'remote_path  = "/root/ciscvm-run-finalize.sh"' in hcl
        assert "run-finalize.sh" in hcl
        # Finalize script: all the in-image channels are written.
        assert "/etc/ciscvm/banner" in finalize
        assert "/etc/motd" in finalize
        assert "/etc/issue" in finalize
        assert "/etc/issue.net" in finalize
        assert "/etc/ssh/sshd_config.d/99-ciscvm-banner.conf" in finalize
        assert "/opt/ciscvm-REPORT.md" in finalize
        assert "/usr/local/bin/ciscvm-info" in finalize
        assert "Banner /etc/ciscvm/banner" in finalize
        # The source image, OS and ciscv version are wired through.
        assert valid_toml["build"]["source_image_id"] in finalize
        assert valid_toml["meta"]["os_tag"] in finalize
        # The ciscv banner ASCII is embedded.
        assert "SECX  SERIES" in finalize
        assert "CIS-HARDENED IMAGE BUILDER" in finalize
        # Bash syntax must be clean (catches missing fi/quote before delivery).
        import subprocess
        p = subprocess.run(
            ["bash", "-n", str(wd / "packer" / "scripts" / "ciscvm-finalize.sh")],
            capture_output=True, text=True,
        )
        assert p.returncode == 0, f"bash -n failed: {p.stderr}"

    def test_banner_uses_no_placeholder_markers(self, valid_toml, tmp_path):
        """The ASCII art must not contain runs of underscores that would
        trigger the _assert_no_markers check (regex: __[A-Z_]+__)."""
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        finalize = (wd / "packer" / "scripts" / "ciscvm-finalize.sh").read_text()
        import re
        leftovers = re.findall(r"__[A-Z_]+__", finalize)
        assert not leftovers, f"unreplaced markers: {leftovers}"

    def test_finalize_args_substituted_into_hcl(self, valid_toml, tmp_path):
        """Build metadata must reach the HCL's inline command verbatim —
        no `__SOURCE_IMAGE__` etc. should remain after render_all."""
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        for m in ("__SOURCE_IMAGE__", "__IMAGE_NAME__", "__IMAGE_OS__",
                  "__CIS_LEVEL__", "__IMAGE_BENCHMARK__", "__CISCVM_VERSION__"):
            assert m not in hcl, f"unsubstituted marker {m} in HCL"
        # And the actual values should appear in the HCL inline (as Packer
        # bakes them in at runtime via shell quoting).
        assert valid_toml["build"]["source_image_id"] in hcl
        assert valid_toml["meta"]["os_tag"] in hcl
        assert valid_toml["meta"]["benchmark"] in hcl

    def test_windows_has_no_banner_provisioner(self, tmp_path):
        """v0.10.0: the banner/report is Linux-only (per user request)."""
        r = resolve(_make_win_toml("win2022"))
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "ciscvm-finalize.sh" not in hcl
        assert "ciscvm-AUDIT-RESULT.json" not in hcl
        assert not (wd / "packer" / "scripts" / "ciscvm-finalize.sh").exists()

    def test_report_generator_handles_audit_json(self, valid_toml, tmp_path):
        """The python heredoc embedded in ciscvm-finalize.sh must produce a
        well-formed markdown report when fed a representative audit JSON."""
        import subprocess as _sp
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        finalize = (wd / "packer" / "scripts" / "ciscvm-finalize.sh").read_text()

        # Extract the embedded python heredoc (between "<<'PY_EOF'" and PY_EOF).
        in_py = False
        py_lines = []
        for ln in finalize.splitlines():
            if ln.startswith("sudo /opt/ciscvm-ansible/bin/python"):
                in_py = True
                continue
            if in_py and ln.strip() == "PY_EOF":
                break
            if in_py:
                py_lines.append(ln)
        py = "\n".join(py_lines)
        assert py, "expected an embedded python heredoc in finalize.sh"

        # Make the heredoc runnable on macOS (no sudo, no /opt).
        # 1) swap `os.system("sudo install -m 0644 ...") ` for a plain copy.
        # The heredoc only contains one os.system call so this is safe.
        py = re.sub(
            r"os\.system\([^)]*\)[^\n]*",
            'open(report_p, "w").write(open(tmp).read())',
            py,
        )
        # 2) tolerate the optional unlink (file already moved).
        py = re.sub(
            r"(\s*)os\.unlink\(tmp\)\s*$",
            r"\1try:\n\1    os.unlink(tmp)\n\1except FileNotFoundError:\n\1    pass",
            py,
            flags=re.MULTILINE,
        )
        # 3) ensure shutil is in scope.
        if "import shutil" not in py:
            py = py.replace("import json, os, sys, tempfile",
                            "import json, os, shutil, sys, tempfile")
        py_path = tmp_path / "report_gen.py"
        py_path.write_text(py)

        # Build a representative audit JSON.
        audit = {
            "mode": "scan",
            "score": 85.1,
            "summary": {"all": {
                "total": 224, "applied": 94, "applied_pending": 24,
                "apply_failed": 0, "skipped_disruptive": 18,
                "pass": 187, "fail": 33, "manual": 0, "notapplicable": 0,
            }},
            "results": [
                {"id": "5.2.7",  "title": "Ensure access to the su command is restricted", "status": "fail"},
                {"id": "3.4.2.1", "title": "Ensure firewalld service is enabled",            "status": "applied_pending"},
            ],
        }
        audit_p = tmp_path / "audit.json"
        audit_p.write_text(json.dumps(audit))
        report_p = tmp_path / "ciscv-REPORT.md"

        # Run the embedded python with the same argv the in-image bash uses.
        rc = _sp.run(
            [sys.executable, str(py_path),
             valid_toml["build"]["source_image_id"],
             "t3-cis-level1-20260806-173729",
             valid_toml["meta"]["os_tag"],
             "level1-server",
             valid_toml["meta"]["benchmark"],
             ciscvm.VERSION,
             "2026-08-06T17:37:29Z",
             str(audit_p),
             str(report_p)],
            capture_output=True, text=True,
        )
        assert rc.returncode == 0, f"report gen failed: {rc.stderr}"

        assert report_p.exists(), "report file not created"
        body = report_p.read_text()
        # Headings + key facts.
        assert "# ciscv — CIS Hardening Report" in body
        assert "Build metadata" in body
        assert valid_toml["build"]["source_image_id"] in body
        assert valid_toml["meta"]["os_tag"] in body
        assert "85.1%" in body
        # The actual rule IDs from the audit JSON surface in the report.
        assert "5.2.7" in body
        assert "3.4.2.1" in body

    def test_pre_audit_logfix_provisioner_present(self, valid_toml, tmp_path):
        """v0.10.1: a fix-logperms provisioner runs between reconnect and re-audit
        to repair boot-loosened log-file perms and journald config before the gate check."""
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "fix-logperms.sh" in hcl
        assert "chmod g-wx,o-rwx" in hcl
        assert "ForwardToSyslog=no" in hcl
        # Must appear after reconnect but before re-audit
        reconnect_idx = hcl.find("reconnected.sh")
        logfix_idx = hcl.find("fix-logperms.sh")
        reaudit_idx = hcl.find("site-audit.yml")
        assert reconnect_idx < logfix_idx < reaudit_idx, \
            f"expected reconnect({reconnect_idx}) < fix-logperms({logfix_idx}) < re-audit({reaudit_idx})"

    def test_windows_renders_correctly(self, tmp_path):
        r = resolve(_make_win_toml("win2022"))
        wd = tmp_path / "build"
        render_all(wd, r)
        assert (wd / "packer" / "main.pkr.hcl").exists()
        assert (wd / "packer" / "auto.pkrvars.hcl").exists()
        assert (wd / "ansible" / "site.yml").exists()
        # Windows: no install script
        assert not (wd / "packer" / "scripts" / "install-ansible.sh").exists()
        # Role copied
        assert (wd / "ansible" / "roles" / "cis_win2022" / "tasks" / "main.yml").exists()
        # HCL has winrm, not ssh
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "winrm" in hcl
        assert "WINRM_PASSWORD" in hcl
        assert "ssh_username" not in hcl


# ---------------------------------------------------------------------------
# Bundled role helpers
# ---------------------------------------------------------------------------
class TestBundleRole:
    def test_copies_linux_role(self, tmp_path):
        wd = tmp_path / "build"
        _bundle_role(wd, "cis_tencentos3")
        assert (wd / "ansible" / "roles" / "cis_tencentos3" / "tasks" / "main.yml").exists()

    def test_copies_windows_role(self, tmp_path):
        wd = tmp_path / "build"
        _bundle_role(wd, "cis_win2022")
        assert (wd / "ansible" / "roles" / "cis_win2022" / "tasks" / "main.yml").exists()

    def test_missing_role_raises(self, tmp_path):
        wd = tmp_path / "build"
        with pytest.raises(ConfigError, match="not found"):
            _bundle_role(wd, "nonexistent_role")


class TestCheckBundledRole:
    def test_exists(self):
        assert _check_bundled_role("cis_tencentos3") is True

    def test_windows_exists(self):
        assert _check_bundled_role("cis_win2022") is True

    def test_not_exists(self):
        assert _check_bundled_role("no_such_role") is False

    def test_path_traversal_rejected(self):
        """Directory traversal attempts should return False."""
        assert _check_bundled_role("../../etc") is False
        assert _check_bundled_role("/etc/passwd") is False


class TestPackaging:
    """Guard the package layout so `pip install` ships the bundled roles.

    Regression: roles/ must live *inside* the ciscvm package (next to
    __init__.py), otherwise wheels omit them and `ciscvm build` fails after
    a clean install.
    """

    def test_roles_dir_inside_package(self):
        pkg_dir = Path(ciscvm.__file__).parent
        assert (pkg_dir / "roles").is_dir()
        assert (pkg_dir / "py.typed").is_file()

    def test_all_profile_roles_resolve(self):
        """Every profile's bundled role directory must exist on disk."""
        missing = [
            p["role_dir"] for p in PROFILES.values() if not _check_bundled_role(p["role_dir"])
        ]
        assert missing == [], f"Bundled roles missing: {missing}"


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
class TestRunPreflight:
    def test_passes_with_valid_env(self, valid_toml, monkeypatch):
        monkeypatch.setenv("TENCENTCLOUD_SECRET_ID", "test-id")
        monkeypatch.setenv("TENCENTCLOUD_SECRET_KEY", "test-key")
        valid_toml["build"]["source_image_id"] = "img-abc123"
        valid_toml["build"]["vpc_id"] = "vpc-abc123"
        valid_toml["build"]["subnet_id"] = "subnet-abc123"
        valid_toml["build"]["security_group_id"] = "sg-abc123"
        r = resolve(valid_toml)
        with mock.patch("shutil.which", return_value="/usr/bin/packer"):
            assert run_preflight(r) is True

    def test_passes_windows_with_winrm_password(self, monkeypatch):
        monkeypatch.setenv("TENCENTCLOUD_SECRET_ID", "test-id")
        monkeypatch.setenv("TENCENTCLOUD_SECRET_KEY", "test-key")
        monkeypatch.setenv("WINRM_PASSWORD", "test-pass")
        data = _make_win_toml("win2022")
        r = resolve(data)
        with mock.patch("shutil.which", return_value="/usr/bin/packer"):
            assert run_preflight(r) is True

    def test_fails_windows_without_winrm_password(self, monkeypatch):
        monkeypatch.setenv("TENCENTCLOUD_SECRET_ID", "test-id")
        monkeypatch.setenv("TENCENTCLOUD_SECRET_KEY", "test-key")
        monkeypatch.delenv("WINRM_PASSWORD", raising=False)
        data = _make_win_toml("win2022")
        r = resolve(data)
        with mock.patch("shutil.which", return_value="/usr/bin/packer"):
            assert run_preflight(r) is False

    def test_fails_without_credentials(self, valid_toml, monkeypatch):
        monkeypatch.delenv("TENCENTCLOUD_SECRET_ID", raising=False)
        monkeypatch.delenv("TENCENTCLOUD_SECRET_KEY", raising=False)
        r = resolve(valid_toml)
        with mock.patch("shutil.which", return_value="/usr/bin/packer"):
            assert run_preflight(r) is False

    def test_fails_without_packer(self, valid_toml, monkeypatch):
        monkeypatch.setenv("TENCENTCLOUD_SECRET_ID", "test-id")
        monkeypatch.setenv("TENCENTCLOUD_SECRET_KEY", "test-key")
        r = resolve(valid_toml)
        with mock.patch("shutil.which", return_value=None):
            assert run_preflight(r) is False


# ---------------------------------------------------------------------------
# PackerResult & run_packer
# ---------------------------------------------------------------------------
class TestPackerResult:
    def test_defaults(self):
        pr = PackerResult(exit_code=0)
        assert pr.exit_code == 0
        assert pr.stdout_lines == []

    def test_with_output(self):
        pr = PackerResult(exit_code=0, stdout_lines=["line1", "line2"])
        assert pr.stdout_lines == ["line1", "line2"]


class TestRunPacker:
    def test_returns_result_on_success(self, valid_toml, tmp_path):
        wd = tmp_path / "build"
        wd.mkdir()
        (wd / "packer").mkdir()
        (wd / "packer" / "main.pkr.hcl").write_text("")
        (wd / "packer" / "auto.pkrvars.hcl").write_text("")

        with (
            mock.patch("subprocess.run") as mock_run,
            mock.patch("subprocess.Popen") as mock_popen,
        ):
            mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            mock_proc = mock.MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = ["OK\n"]
            mock_proc.__enter__.return_value = mock_proc
            mock_popen.return_value = mock_proc
            result = run_packer(wd, "validate", capture=True)
            assert result.exit_code == 0

    def test_init_failure_returns_error(self, valid_toml, tmp_path):
        wd = tmp_path / "build"
        wd.mkdir()
        (wd / "packer").mkdir()
        (wd / "packer" / "main.pkr.hcl").write_text("")

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess([], 1, stdout="", stderr="error")
            result = run_packer(wd, "build", capture=True)
            assert result.exit_code == 1

    def test_init_failure_surfaces_output(self, tmp_path, capsys):
        """packer init failure must print its captured output itself."""
        wd = tmp_path / "build"
        wd.mkdir()
        (wd / "packer").mkdir()
        (wd / "packer" / "main.pkr.hcl").write_text("")

        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                [], 1, stdout="plugin registry unreachable", stderr=""
            )
            result = run_packer(wd, "validate", capture=True)
        assert result.exit_code == 1
        err = capsys.readouterr().err
        assert "plugin registry unreachable" in err

    def test_subcmd_failure_returns_error(self, tmp_path):
        """init succeeds but the sub-command (validate/build) fails."""
        wd = tmp_path / "build"
        wd.mkdir()
        (wd / "packer").mkdir()
        (wd / "packer" / "main.pkr.hcl").write_text("")

        with (
            mock.patch("subprocess.run") as mock_run,
            mock.patch("subprocess.Popen") as mock_popen,
        ):
            mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            mock_proc = mock.MagicMock()
            mock_proc.returncode = 2
            mock_proc.stdout = ["Error: invalid config\n"]
            mock_proc.__enter__.return_value = mock_proc
            mock_popen.return_value = mock_proc
            result = run_packer(wd, "validate", capture=True)
        assert result.exit_code == 2
        assert "Error: invalid config" in result.stdout_lines[0]

    def test_quiet_captures_but_does_not_stream(self, tmp_path, capsys):
        """--quiet must capture lines for parsing but NOT stream them to stderr."""
        wd = tmp_path / "build"
        wd.mkdir()
        (wd / "packer").mkdir()
        (wd / "packer" / "main.pkr.hcl").write_text("")

        with (
            mock.patch("subprocess.run") as mock_run,
            mock.patch("subprocess.Popen") as mock_popen,
        ):
            mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            mock_proc = mock.MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = ["Created image ID: img-quiet\n"]
            mock_proc.__enter__.return_value = mock_proc
            mock_popen.return_value = mock_proc
            result = run_packer(wd, "build", quiet=True, capture=True)
        err = capsys.readouterr().err
        # Captured for image-ID parsing, but suppressed from live stderr.
        assert result.stdout_lines == ["Created image ID: img-quiet"]
        assert "Created image ID" not in err

    def test_packer_not_found(self, tmp_path):
        """Missing packer binary is reported as exit code 1, not a crash."""
        wd = tmp_path / "build"
        wd.mkdir()
        (wd / "packer").mkdir()
        (wd / "packer" / "main.pkr.hcl").write_text("")

        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            result = run_packer(wd, "validate", capture=True)
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------
class TestCmdInit:
    def test_creates_config(self, tmp_path):
        with mock.patch("sys.stdout", new_callable=lambda: open(os.devnull, "w")):
            rc = cmd_init(mock.MagicMock(target=str(tmp_path), force=False))
        assert rc == 0
        assert (tmp_path / "ciscvm.toml").exists()
        assert (tmp_path / ".gitignore").exists()

    def test_refuses_overwrite_without_force(self, tmp_path):
        (tmp_path / "ciscvm.toml").write_text("existing", encoding="utf-8")
        rc = cmd_init(mock.MagicMock(target=str(tmp_path), force=False))
        assert rc == 1

    def test_overwrite_with_force(self, tmp_path):
        (tmp_path / "ciscvm.toml").write_text("existing", encoding="utf-8")
        rc = cmd_init(mock.MagicMock(target=str(tmp_path), force=True))
        assert rc == 0


class TestCmdClean:
    def test_removes_directory(self, tmp_path):
        wd = tmp_path / "build"
        wd.mkdir()
        # Create ciscvm marker files
        (wd / "packer").mkdir()
        (wd / "packer" / "main.pkr.hcl").write_text("")
        rc = cmd_clean(mock.MagicMock(workdir=str(wd)))
        assert rc == 0
        assert not wd.exists()

    def test_missing_directory_is_ok(self, tmp_path):
        wd = tmp_path / "nonexistent"
        rc = cmd_clean(mock.MagicMock(workdir=str(wd)))
        assert rc == 0

    def test_not_a_ciscvm_dir(self, tmp_path):
        """Refuse to clean a directory without ciscvm markers."""
        wd = tmp_path / "not-ciscvm"
        wd.mkdir()
        rc = cmd_clean(mock.MagicMock(workdir=str(wd)))
        assert rc == 1
        assert wd.exists()  # not deleted

    def test_refuses_system_path(self):
        """Refuse to clean / , /etc , /home , etc."""
        rc = cmd_clean(mock.MagicMock(workdir="/"))
        assert rc == 1
        rc = cmd_clean(mock.MagicMock(workdir="/etc"))
        assert rc == 1
        rc = cmd_clean(mock.MagicMock(workdir="/usr"))
        assert rc == 1


class TestCmdBuildOutput:
    """cmd_build must not re-print packer output (run_packer already streams it)."""

    def _prep(self, tmp_path):
        r = mock.MagicMock()
        r.family = ""
        r.profile_name = "cis_ubuntu2204"
        r.level = 1
        r.region = "ap-guangzhou"
        r.source_image_id = "img-abc"
        r.instance_type = "S5.MEDIUM2"
        return r, tmp_path / "build"

    def test_build_does_not_reprint_output(self, tmp_path, capsys):
        from ciscvm import PackerResult, cmd_build

        r, wd = self._prep(tmp_path)
        packer_lines = ["==> building", "Created image ID: img-xyz789", "done"]
        with (
            mock.patch("ciscvm._load_resolve_preflight", return_value=(r, wd)),
            mock.patch("ciscvm.render_all"),
            mock.patch(
                "ciscvm.run_packer",
                return_value=PackerResult(exit_code=0, stdout_lines=packer_lines),
            ),
        ):
            rc = cmd_build(mock.MagicMock(config="x", workdir=str(wd), yes=True, quiet=False, log_file=None))
        assert rc == 0
        out = capsys.readouterr().out
        # The packer log lines must NOT be dumped to stdout by cmd_build.
        assert "==> building" not in out
        assert "done" not in out

    def test_build_still_parses_image_id(self, tmp_path, capsys):
        from ciscvm import PackerResult, cmd_build

        r, wd = self._prep(tmp_path)
        with (
            mock.patch("ciscvm._load_resolve_preflight", return_value=(r, wd)),
            mock.patch("ciscvm.render_all"),
            mock.patch(
                "ciscvm.run_packer",
                return_value=PackerResult(
                    exit_code=0, stdout_lines=["Created image ID: img-xyz789"]
                ),
            ),
        ):
            rc = cmd_build(mock.MagicMock(config="x", workdir=str(wd), yes=True, quiet=False, log_file=None))
        assert rc == 0
        # Image ID is surfaced via the logger (stderr), captured by caplog elsewhere;
        # here we just confirm the command succeeded and did not crash on parsing.

    def test_build_quiet_does_not_dump_log(self, tmp_path, capsys):
        """--quiet build shows only the summary, never the packer log."""
        from ciscvm import PackerResult, cmd_build

        r, wd = self._prep(tmp_path)
        packer_lines = ["==> building", "Created image ID: img-q", "done"]
        captured_quiet: dict[str, object] = {}

        def fake_run_packer(workdir, subcmd, quiet=False, capture=False, timeout=None, debug=False, log_file=None):
            captured_quiet["quiet"] = quiet
            captured_quiet["capture"] = capture
            return PackerResult(exit_code=0, stdout_lines=packer_lines)

        with (
            mock.patch("ciscvm._load_resolve_preflight", return_value=(r, wd)),
            mock.patch("ciscvm.render_all"),
            mock.patch("ciscvm.run_packer", side_effect=fake_run_packer),
        ):
            rc = cmd_build(mock.MagicMock(config="x", workdir=str(wd), yes=True, quiet=True, log_file=None))
        assert rc == 0
        # cmd_build must forward quiet=True and still capture (for image-ID parsing).
        assert captured_quiet == {"quiet": True, "capture": True}
        out = capsys.readouterr().out
        assert "==> building" not in out
        assert "done" not in out

    def test_build_returns_packer_exit_code(self, tmp_path):
        """A failed packer build must propagate a non-zero exit code."""
        from ciscvm import PackerResult, cmd_build

        r, wd = self._prep(tmp_path)
        with (
            mock.patch("ciscvm._load_resolve_preflight", return_value=(r, wd)),
            mock.patch("ciscvm.render_all"),
            mock.patch(
                "ciscvm.run_packer",
                return_value=PackerResult(exit_code=1, stdout_lines=["Error"]),
            ),
        ):
            rc = cmd_build(mock.MagicMock(config="x", workdir=str(wd), yes=True, quiet=False, log_file=None))
        assert rc == 1

    def test_build_aborts_when_preflight_fails(self, tmp_path):
        """If preflight fails, cmd_build must not render or invoke packer."""
        from ciscvm import cmd_build

        with (
            mock.patch("ciscvm._load_resolve_preflight", return_value=None),
            mock.patch("ciscvm.render_all") as mock_render,
            mock.patch("ciscvm.run_packer") as mock_run,
        ):
            rc = cmd_build(mock.MagicMock(config="x", workdir="wd", yes=True, quiet=False))
        assert rc == 1
        mock_render.assert_not_called()
        mock_run.assert_not_called()


class TestCmdValidateOutput:
    """cmd_validate end-to-end with real rendering + mocked packer."""

    def test_validate_renders_and_invokes_packer(self, valid_toml, tmp_path, monkeypatch):
        from ciscvm import PackerResult, cmd_validate

        monkeypatch.setenv("TENCENTCLOUD_SECRET_ID", "test-id")
        monkeypatch.setenv("TENCENTCLOUD_SECRET_KEY", "test-key")
        valid_toml["build"]["source_image_id"] = "img-abc123"
        valid_toml["build"]["vpc_id"] = "vpc-abc123"
        valid_toml["build"]["subnet_id"] = "subnet-abc123"
        valid_toml["build"]["security_group_id"] = "sg-abc123"

        cfg = _write_config(tmp_path, valid_toml)
        wd = tmp_path / "build"
        seen: dict[str, object] = {}

        def fake_run_packer(workdir, subcmd, quiet=False, capture=False, timeout=None, debug=False):
            seen["subcmd"] = subcmd
            seen["workdir"] = Path(workdir)
            return PackerResult(exit_code=0)

        with (
            mock.patch("shutil.which", return_value="/usr/bin/packer"),
            mock.patch("ciscvm.run_packer", side_effect=fake_run_packer),
        ):
            rc = cmd_validate(
                mock.MagicMock(config=str(cfg), workdir=str(wd), quiet=False)
            )
        assert rc == 0
        # Real rendering happened before packer was invoked.
        assert (wd / "packer" / "main.pkr.hcl").exists()
        assert (wd / "packer" / "auto.pkrvars.hcl").exists()
        assert (wd / "ansible" / "site.yml").exists()
        assert seen["subcmd"] == "validate"
        assert seen["workdir"] == wd

    def test_validate_propagates_failure(self, valid_toml, tmp_path, monkeypatch):
        from ciscvm import PackerResult, cmd_validate

        monkeypatch.setenv("TENCENTCLOUD_SECRET_ID", "test-id")
        monkeypatch.setenv("TENCENTCLOUD_SECRET_KEY", "test-key")
        valid_toml["build"]["source_image_id"] = "img-abc123"
        valid_toml["build"]["vpc_id"] = "vpc-abc123"
        valid_toml["build"]["subnet_id"] = "subnet-abc123"
        valid_toml["build"]["security_group_id"] = "sg-abc123"

        cfg = _write_config(tmp_path, valid_toml)
        wd = tmp_path / "build"

        with (
            mock.patch("shutil.which", return_value="/usr/bin/packer"),
            mock.patch("ciscvm.run_packer", return_value=PackerResult(exit_code=3)),
        ):
            rc = cmd_validate(
                mock.MagicMock(config=str(cfg), workdir=str(wd), quiet=False)
            )
        assert rc == 3

    def test_validate_aborts_when_preflight_fails(self, tmp_path):
        from ciscvm import cmd_validate

        with (
            mock.patch("ciscvm._load_resolve_preflight", return_value=None),
            mock.patch("ciscvm.render_all") as mock_render,
            mock.patch("ciscvm.run_packer") as mock_run,
        ):
            rc = cmd_validate(mock.MagicMock(config="x", workdir="wd", quiet=False))
        assert rc == 1
        mock_render.assert_not_called()
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
class TestBuildParser:
    def test_init_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["init"])
        assert args.command == "init"

    def test_version_flag(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--version"])
        assert exc.value.code == 0


# ---------------------------------------------------------------------------
# main() entry point
# ---------------------------------------------------------------------------
class TestMain:
    def test_init(self, tmp_path):
        rc = main(["init", "--target", str(tmp_path)])
        assert rc == 0
        assert (tmp_path / "ciscvm.toml").exists()

    def test_clean_missing(self, tmp_path):
        wd = str(tmp_path / "build")
        rc = main(["clean", "--workdir", wd])
        assert rc == 0

    def test_preflight_bad_config(self):
        rc = main(["preflight", "--config", "/nonexistent.toml"])
        assert rc == 1


# ---------------------------------------------------------------------------
# PROFILES integrity checks
# ---------------------------------------------------------------------------
class TestProfiles:
    def test_count_is_14(self):
        assert len(PROFILES) == 14, f"Expected 14 profiles, got {len(PROFILES)}"

    def test_all_have_os_tag(self):
        for name, p in PROFILES.items():
            assert p.get("os_tag"), f"{name}: missing os_tag"

    def test_all_have_benchmark(self):
        for name, p in PROFILES.items():
            assert p.get("benchmark"), f"{name}: missing benchmark"

    def test_all_have_role_dir(self):
        for name, p in PROFILES.items():
            assert p.get("role_dir"), f"{name}: missing role_dir"

    def test_linux_have_ssh_username(self):
        for name in LINUX_PROFILES:
            p = PROFILES[name]
            assert p.get("ssh_username"), f"{name}: missing ssh_username"

    def test_windows_have_winrm_username(self):
        for name in WIN_PROFILES:
            p = PROFILES[name]
            assert p.get("winrm_username"), f"{name}: missing winrm_username"

    def test_linux_have_pkg_commands(self):
        for name in LINUX_PROFILES:
            p = PROFILES[name]
            assert p.get("pkg_update"), f"{name}: missing pkg_update"
            assert p.get("pkg_install"), f"{name}: missing pkg_install"
            assert p.get("clean_cmd"), f"{name}: missing clean_cmd"

    def test_windows_have_no_pkg_commands(self):
        for name in WIN_PROFILES:
            p = PROFILES[name]
            assert "pkg_update" not in p, f"{name}: should not have pkg_update"
            assert "pkg_install" not in p, f"{name}: should not have pkg_install"


# ---------------------------------------------------------------------------
# Clean safety
# ---------------------------------------------------------------------------
class TestCleanIsSafe:
    def test_allows_valid_ciscvm_dir(self, tmp_path):
        wd = tmp_path / "build"
        (wd / "packer").mkdir(parents=True)
        (wd / "packer" / "main.pkr.hcl").write_text("")
        assert _clean_is_safe(wd) is None

    def test_allows_ansible_marker(self, tmp_path):
        wd = tmp_path / "build"
        (wd / "ansible").mkdir(parents=True)
        (wd / "ansible" / "site.yml").write_text("")
        assert _clean_is_safe(wd) is None

    def test_rejects_dir_without_markers(self, tmp_path):
        wd = tmp_path / "empty"
        wd.mkdir()
        assert _clean_is_safe(wd) is not None

    def test_rejects_system_paths(self):
        for p in ["/", "/etc", "/usr", "/home"]:
            assert _clean_is_safe(Path(p)) is not None, f"should reject {p}"

    def test_rejects_home(self):
        home = Path.home()
        assert _clean_is_safe(home) is not None
        assert _clean_is_safe(home / "Desktop") is not None

    def test_allows_home_build_dir_with_markers(self, tmp_path):
        """Builds inside home dir should be cleanable if they have markers."""
        wd = tmp_path / "my-build"
        (wd / "packer").mkdir(parents=True)
        (wd / "packer" / "main.pkr.hcl").write_text("")
        assert _clean_is_safe(wd) is None


# ---------------------------------------------------------------------------
# _color TTY check
# ---------------------------------------------------------------------------
class TestColor:
    def test_no_color_env(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        result = _color("hello", 31)
        assert "\033" not in result
        assert result == "hello"

    def test_non_tty_stderr(self, monkeypatch):
        """When stderr is not a TTY, ANSI codes are stripped."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        with mock.patch.object(ciscvm.sys.stderr, "isatty", return_value=False):
            result = _color("hello", 31)
            assert "\033" not in result

    def test_tty_produces_ansi(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        with mock.patch.object(ciscvm.sys.stderr, "isatty", return_value=True):
            result = _color("hello", 31)
            assert "\033" in result


# ---------------------------------------------------------------------------
# Integration: end-to-end render for all profiles
# ---------------------------------------------------------------------------
class TestAllProfilesRender:
    @pytest.mark.parametrize("profile_name", list(PROFILES))
    def test_profile_renders(self, profile_name, valid_toml, tmp_path):
        if PROFILES[profile_name].get("family") == "windows":
            data = _make_win_toml(profile_name)
        else:
            valid_toml["build"]["profile"] = profile_name
            data = valid_toml

        r = resolve(data)
        wd = tmp_path / "build"
        render_all(wd, r)
        assert (wd / "packer" / "main.pkr.hcl").exists(), f"{profile_name}: no main.pkr.hcl"
        assert (wd / "ansible" / "site.yml").exists(), f"{profile_name}: no site.yml"

        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        if r.family != "windows":
            assert "__CLEAN_CMD__" not in hcl, f"{profile_name}: unreplaced marker"

    @pytest.mark.parametrize("profile_name", list(PROFILES))
    def test_inline_items_comma_separated(self, profile_name, valid_toml, tmp_path):
        """Regression: a missing comma between inline items silently became one
        concatenated string in Python (implicit literal joining) and produced an
        HCL 'Missing item separator' parse error in packer build."""
        import re

        if PROFILES[profile_name].get("family") == "windows":
            data = _make_win_toml(profile_name)
        else:
            valid_toml["build"]["profile"] = profile_name
            data = valid_toml

        r = resolve(data)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()

        blocks = list(re.finditer(r"inline\s*=\s*\[(.*?)\]\s*\n", hcl, re.S))
        assert blocks, f"{profile_name}: no inline blocks found in HCL"
        for blk in blocks:
            lines = [l for l in blk.group(1).splitlines() if l.strip()]
            for i in range(len(lines) - 1):
                prev = lines[i].rstrip()
                assert not prev.endswith('"') or prev.endswith('",'), (
                    f"{profile_name}: inline item {i} missing trailing comma: "
                    f"{prev[:80]!r}"
                )

    @pytest.mark.parametrize("profile_name", list(PROFILES))
    def test_ssh_guard_nft_awk_and_reconnect_budget(self, profile_name, valid_toml, tmp_path):
        """Regression (v0.14.16/v0.14.17): the SSH guard's nftables table
        iteration must read 'family name' as one token pair (while-read over
        `nft list tables`, NOT a for-loop over $(awk ...)); the post-reboot
        reconnect provisioner must widen start_retry_timeout (the connect
        window — max_retries only retries command execution); and the guard
        must delete the stale /.autorelabel marker so a SELinux disabled ->
        permissive boot does not stall on a boot-time relabel."""
        if PROFILES[profile_name].get("family") == "windows":
            data = _make_win_toml(profile_name)
        else:
            valid_toml["build"]["profile"] = profile_name
            data = valid_toml

        r = resolve(data)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()

        # nft table iteration must carry family+name (Linux template only)
        if r.family != "windows":
            assert "while read -r _ fam name" in hcl, (
                f"{profile_name}: nft table iteration not using while-read"
            )
            # the old broken forms must be gone
            assert "awk '{print $2, $3}')" not in hcl, (
                f"{profile_name}: word-splitting nft iteration still present"
            )
            assert "nft list tables 2>/dev/null | awk '{print $2}')" not in hcl, (
                f"{profile_name}: old family-only nft iteration still present"
            )
            # post-reboot reconnect provisioner widens the CONNECT window
            assert 'start_retry_timeout = "25m"' in hcl, (
                f"{profile_name}: post-reboot connect window not widened"
            )
            # stale SELinux autorelabel marker must be removed pre-reboot
            assert "rm -f /.autorelabel" in hcl, (
                f"{profile_name}: stale /.autorelabel not removed by guard"
            )
            # post-reboot evidence echo must exist
            assert "post-reboot: autorelabel=" in hcl, (
                f"{profile_name}: post-reboot state evidence missing"
            )
            # /opt must be made rw (fstab ro stripped + remount) so post-reboot
            # provisioner uploads and ansible staging do not hit a ro fs
            assert "fstab /opt line rewritten to rw" in hcl, (
                f"{profile_name}: /opt ro fstab fix missing"
            )
            assert 'remount,rw /opt' in hcl, (
                f"{profile_name}: /opt remount rw missing"
            )
            # v0.14.19: the whole ROOT fs came up ro (scp to /root failed) —
            # the boot oneshot must force remount rw before sshd, and the guard
            # must strip ro from the / fstab line + report root mount options
            assert "mount -o remount,rw / >/dev/null 2>&1" in hcl, (
                f"{profile_name}: boot oneshot root remount rw missing"
            )
            assert "fstab / line rewritten to rw" in hcl, (
                f"{profile_name}: guard root fstab ro fix missing"
            )
            assert "VERIFY: root options=$(findmnt -no OPTIONS /" in hcl, (
                f"{profile_name}: root mount state VERIFY missing"
            )
            # post-reboot provisioner uploads must not depend on /opt writable
            assert 'remote_path       = "/root/ciscvm-reconnected.sh"' in hcl, (
                f"{profile_name}: reconnect upload still targets /opt"
            )


class TestBuildGovernance:
    """smoke test / lineage / notification / provenance (v0.14)."""

    def test_smoke_rendered_linux_by_default(self, valid_toml, tmp_path):
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "__SMOKE_TEST_BLOCK__" not in hcl
        assert "smoke test: sshd config parses" in hcl
        assert "smoke test: /dev/shm noexec" in hcl
        assert "SMOKE FAIL" in hcl

    def test_smoke_auditd_conditional(self, valid_toml, tmp_path):
        """Regression (v0.14.20/21): auditd is L2 (4.1.x excluded at L1) — the
        smoke test must only require auditd active when it is ENABLED, not when
        its unit file merely exists (TOS4 ships the unit but L1 leaves it off)."""
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "auditd active (if enabled" in hcl
        assert "is-enabled --quiet auditd" in hcl
        # the unconditional hard fail must be gone
        assert "SMOKE FAIL: auditd not active" not in hcl
        assert "auditd not enabled (L1) — skipped" in hcl

    def test_smoke_shm_and_journal_conditional(self, valid_toml, tmp_path):
        """Regression (v0.14.21): /dev/shm noexec (1.1.8.2) is L1-disruptive
        and journal-upload's unit exists on every systemd box — the smoke test
        must gate both on 'actually applied/enabled', not on file existence."""
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        # /dev/shm gated on fstab applying noexec
        assert "smoke test: /dev/shm noexec (if hardened in fstab)" in hcl
        assert "SMOKE FAIL: /dev/shm noexec applied but not live" in hcl
        assert "SMOKE FAIL: /dev/shm lacks noexec" not in hcl
        # journal-upload gated on is-enabled, not unit-file existence
        assert "journal-upload (if enabled)" in hcl
        assert "is-enabled --quiet systemd-journal-upload.service" in hcl
        assert "list-unit-files systemd-journal-upload.service" not in hcl

    def test_smoke_disabled(self, valid_toml, tmp_path):
        valid_toml["meta"]["smoke_test"] = False
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "smoke test" not in hcl

    def test_smoke_rendered_windows(self, tmp_path):
        data = _make_win_toml("win2022")
        r = resolve(data)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "smoke test PASSED - image is buildable" in hcl
        assert "mpssvc" in hcl  # Windows firewall check

    def test_lineage_record_and_images(self, valid_toml, tmp_path):
        r = resolve(valid_toml)
        lin = tmp_path / "lineage.jsonl"
        with mock.patch("ciscvm._lineage_path", return_value=lin):
            from ciscvm import _record_lineage, cmd_images
            p = _record_lineage(r, ["img-aaa", "img-bbb"], "img-name", 91.5, ok=True)
            assert p == lin and lin.exists()
            _record_lineage(r, [], "img-name", None, ok=False)
            args = mock.MagicMock(latest=False, limit=10)
            assert cmd_images(args) == 0
        recs = [json.loads(x) for x in lin.read_text().splitlines()]
        assert recs[0]["status"] == "ok"
        assert recs[0]["image_ids"] == ["img-aaa", "img-bbb"]
        assert recs[0]["score"] == 91.5
        assert recs[1]["status"] == "failed"

    def test_notify_routing_failure_only(self, valid_toml, tmp_path):
        valid_toml["notify"] = {"webhook": "https://example.invalid/hook", "on": "failure"}
        r = resolve(valid_toml)
        with mock.patch("ciscvm.urllib.request.urlopen") as urlopen:
            from ciscvm import _send_notification
            # success build + on=failure -> no POST
            _send_notification(r, True, ["img-x"], 90.0, "n")
            urlopen.assert_not_called()
            # failed build -> POST
            _send_notification(r, False, [], None, "n")
            assert urlopen.call_count == 1

    def test_notify_on_always(self, valid_toml, tmp_path):
        valid_toml["notify"] = {"webhook": "https://example.invalid/hook", "on": "always"}
        r = resolve(valid_toml)
        with mock.patch("ciscvm.urllib.request.urlopen"):
            from ciscvm import _send_notification
            _send_notification(r, True, ["img-x"], 90.0, "n")  # must not raise

    def test_provenance_written_and_signed(self, valid_toml, tmp_path):
        from ciscvm import _write_provenance
        valid_toml["sign"] = {"gpg_key": "TESTKEY"}
        r = resolve(valid_toml)
        with (
            mock.patch("ciscvm._lineage_path", return_value=tmp_path / "lineage.jsonl"),
            mock.patch("subprocess.run") as sub,
        ):
            sub.return_value = mock.Mock(returncode=0, stderr="", stdout="")
            p = _write_provenance(r, ["img-xyz"], "img-name", 98.2)
        assert p is not None and p.exists()
        # gpg invoked with the configured key + sig output path
        assert sub.call_count == 1
        cmd = sub.call_args.args[0]
        assert cmd[0] == "gpg" and "--local-user" in cmd
        assert cmd[cmd.index("--local-user") + 1] == "TESTKEY"
        sig = p.with_suffix(p.suffix + ".sig")
        assert str(sig) in cmd
        prov = json.loads(p.read_text())
        assert prov["subject"][0]["name"] == "img-xyz"
        assert prov["predicate"]["buildDefinition"]["externalParameters"]["profile"] == "tencentos3"
        assert prov["predicate"]["runDetails"]["metadata"]["reAuditScore"] == 98.2

    def test_provenance_unsigned_when_no_key(self, valid_toml, tmp_path):
        from ciscvm import _write_provenance
        r = resolve(valid_toml)
        with mock.patch("ciscvm._lineage_path", return_value=tmp_path / "lineage.jsonl"):
            p = _write_provenance(r, ["img-xyz"], "img-name", None)
        assert p is not None
        assert not p.with_suffix(p.suffix + ".sig").exists()


class TestVerify:
    """ciscvm verify — SLSA provenance signature verification."""

    def _make_prov(self, tmp_path, image_id="img-abc", signed=True, key="TESTKEY"):
        import ciscvm
        from ciscvm import SAMPLE_CONFIG, _write_provenance
        ciscvm._lineage_path = lambda: tmp_path / "lineage.jsonl"
        data = tomllib.loads(SAMPLE_CONFIG)
        data["sign"] = {"gpg_key": key}
        r = resolve(data)
        with mock.patch("subprocess.run") as sub:
            sub.return_value = mock.Mock(returncode=0, stderr="", stdout="")
            p = _write_provenance(r, [image_id], "img-name", 96.0)
        sig = p.with_suffix(p.suffix + ".sig")
        if signed:
            # simulate what real gpg would have produced
            sig.write_text("-----BEGIN PGP SIGNATURE-----\nmock\n-----END PGP SIGNATURE-----\n")
        else:
            sig.unlink(missing_ok=True)
        return p

    def test_verify_valid_signature(self, valid_toml, tmp_path):
        from ciscvm import cmd_verify
        p = self._make_prov(tmp_path)
        with mock.patch("subprocess.run") as sub:
            sub.return_value = mock.Mock(returncode=0, stderr="", stdout="")
            rc = cmd_verify(mock.MagicMock(provenance=str(p), image=None))
        assert rc == 0
        cmd = sub.call_args.args[0]
        assert cmd[0] == "gpg" and "--verify" in cmd

    def test_verify_invalid_signature(self, valid_toml, tmp_path):
        from ciscvm import cmd_verify
        p = self._make_prov(tmp_path)
        with mock.patch("subprocess.run") as sub:
            sub.return_value = mock.Mock(returncode=1, stderr="BAD signature", stdout="")
            rc = cmd_verify(mock.MagicMock(provenance=str(p), image=None))
        assert rc == 1

    def test_verify_unsigned_warns_fails(self, valid_toml, tmp_path):
        from ciscvm import cmd_verify
        p = self._make_prov(tmp_path, signed=False)
        rc = cmd_verify(mock.MagicMock(provenance=str(p), image=None))
        assert rc == 1  # unsigned provenance does not verify

    def test_verify_by_image_id(self, valid_toml, tmp_path):
        import ciscvm
        from ciscvm import cmd_verify
        self._make_prov(tmp_path, image_id="img-target-1")
        with (
            mock.patch("ciscvm._lineage_path", return_value=tmp_path / "lineage.jsonl"),
            mock.patch("subprocess.run") as sub,
        ):
            sub.return_value = mock.Mock(returncode=0, stderr="", stdout="")
            rc = cmd_verify(mock.MagicMock(provenance=None, image="img-target-1"))
        assert rc == 0

    def test_verify_image_not_found(self, valid_toml, tmp_path):
        import ciscvm
        from ciscvm import cmd_verify
        self._make_prov(tmp_path, image_id="img-other")
        with mock.patch("ciscvm._lineage_path", return_value=tmp_path / "lineage.jsonl"):
            rc = cmd_verify(mock.MagicMock(provenance=None, image="img-missing"))
        assert rc == 1


class TestScanListRules:
    """ciscvm scan / list / [cis].rules_include|exclude (roadmap v0.14.3)."""

    def test_rules_filter_rendered(self, valid_toml, tmp_path):
        valid_toml["cis"]["rules_include"] = ["1.5.6", "5.4.3.2"]
        valid_toml["cis"]["rules_exclude"] = ["1.1.2.2.4"]
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        site = (wd / "ansible" / "site.yml").read_text()
        assert "cis_include: [\"1.5.6\", \"5.4.3.2\"]" in site
        assert "cis_exclude: [\"1.1.2.2.4\"]" in site
        assert "cis_mode: apply" in site

    def test_rules_default_empty(self, valid_toml, tmp_path):
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        site = (wd / "ansible" / "site.yml").read_text()
        assert "cis_include: []" in site and "cis_exclude: []" in site

    def test_rules_overlap_rejected(self, valid_toml):
        valid_toml["cis"]["rules_include"] = ["1.5.6"]
        valid_toml["cis"]["rules_exclude"] = ["1.5.6"]
        with pytest.raises(ConfigError, match=r"overlap"):
            resolve(valid_toml)

    def test_scan_mode_rendered(self, valid_toml, tmp_path):
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r, scan=True)
        site = (wd / "ansible" / "site.yml").read_text()
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "cis_mode: scan" in site
        assert "smoke test" not in hcl  # smoke skipped in audit-only mode

    def test_cmd_list_output(self, capsys):
        from ciscvm import cmd_list
        rc = cmd_list(mock.MagicMock())
        out = capsys.readouterr().out
        assert rc == 0
        assert "tencentos3" in out and "win2022" in out and "profile" in out

    def test_cmd_scan_gate_fail(self, valid_toml, tmp_path):
        from ciscvm import PackerResult, cmd_scan
        r = resolve(valid_toml)
        with (
            mock.patch("ciscvm._load_resolve_preflight", return_value=(r, tmp_path / "b")),
            mock.patch("ciscvm.render_all"),
            mock.patch("ciscvm.run_packer",
                       return_value=PackerResult(exit_code=0, stdout_lines=[
                           "Tencentcloud images(ap-guangzhou: img-scan1) were created.",
                           "Score: 80.0%"])),
            mock.patch("ciscvm._record_lineage") as lin,
        ):
            rc = cmd_scan(mock.MagicMock(config="x", workdir="b", yes=True, quiet=True,
                                         debug=False, min_score=85.0))
        assert rc == 1  # gate failed: 80 < 85
        lin.assert_called_once()
        assert lin.call_args.kwargs["ok"] is False  # recorded as failed

    def test_cmd_scan_gate_pass(self, valid_toml, tmp_path):
        from ciscvm import PackerResult, cmd_scan
        r = resolve(valid_toml)
        with (
            mock.patch("ciscvm._load_resolve_preflight", return_value=(r, tmp_path / "b")),
            mock.patch("ciscvm.render_all"),
            mock.patch("ciscvm.run_packer",
                       return_value=PackerResult(exit_code=0, stdout_lines=[
                           "Tencentcloud images(ap-guangzhou: img-scan2) were created.",
                           "Score: 92.0%"])),
            mock.patch("ciscvm._record_lineage") as lin,
            mock.patch("ciscvm._write_provenance") as prov,
        ):
            rc = cmd_scan(mock.MagicMock(config="x", workdir="b", yes=True, quiet=True,
                                         debug=False, min_score=85.0))
        assert rc == 0
        assert lin.call_args.kwargs["ok"] is True
        prov.assert_called_once()


class TestCleanupImages:
    """ciscvm cleanup-images — retire old images by lineage age."""

    def _seed_lineage(self, tmp_path, days_ago):
        import ciscvm
        from datetime import datetime, timezone, timedelta
        ciscvm._lineage_path = lambda: tmp_path / "lineage.jsonl"
        path = tmp_path / "lineage.jsonl"
        def rec(ts, imgs, status="ok"):
            return json.dumps({"ts": ts, "status": status, "region": "ap-guangzhou",
                               "image_ids": imgs, "image_name": "n", "cis_level": 1})
        now = datetime.now(timezone.utc)
        lines = [
            rec((now - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ"), ["img-old1", "img-old2"]),
            rec((now - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ"), ["img-old3"]),
            rec(now.strftime("%Y-%m-%dT%H:%M:%SZ"), ["img-new"]),
        ]
        path.write_text("\n".join(lines) + "\n")
        return path

    def test_dry_run_no_delete(self, tmp_path):
        from ciscvm import cmd_cleanup_images
        self._seed_lineage(tmp_path, days_ago=60)
        with mock.patch("ciscvm._delete_images") as dele, \
             mock.patch("ciscvm._images_exist") as exist:
            rc = cmd_cleanup_images(mock.MagicMock(older_than=30, keep_latest=1, apply=False))
        assert rc == 0
        dele.assert_not_called()
        exist.assert_not_called()

    def test_apply_deletes_and_marks_retired(self, tmp_path):
        from ciscvm import cmd_cleanup_images
        path = self._seed_lineage(tmp_path, days_ago=60)
        with mock.patch("ciscvm._images_exist", return_value=["img-old1", "img-old2", "img-old3"]), \
             mock.patch("ciscvm._delete_images") as dele:
            rc = cmd_cleanup_images(mock.MagicMock(older_than=30, keep_latest=1, apply=True))
        assert rc == 0
        assert dele.call_count == 3  # 3 old images deleted, img-new kept
        recs = [json.loads(x) for x in path.read_text().splitlines()]
        retired = [r for r in recs if r.get("retired")]
        assert len(retired) == 2  # both old records retired
        assert all(not r.get("retired") for r in recs if "img-new" in (r.get("image_ids") or []))

    def test_keep_latest_protects_newest(self, tmp_path):
        from ciscvm import cmd_cleanup_images
        self._seed_lineage(tmp_path, days_ago=60)
        with mock.patch("ciscvm._images_exist", return_value=["img-old1", "img-old2", "img-old3"]), \
             mock.patch("ciscvm._delete_images") as dele:
            rc = cmd_cleanup_images(mock.MagicMock(older_than=30, keep_latest=2, apply=True))
        assert rc == 0
        # keep_latest=2: img-new + one old record protected -> only 2 old deleted
        assert dele.call_count == 2

    def test_nothing_to_clean(self, tmp_path):
        from ciscvm import cmd_cleanup_images
        self._seed_lineage(tmp_path, days_ago=1)
        with mock.patch("ciscvm._delete_images") as dele:
            rc = cmd_cleanup_images(mock.MagicMock(older_than=30, keep_latest=1, apply=True))
        assert rc == 0
        dele.assert_not_called()

    def test_tc3_signer_shape(self, tmp_path):
        """The TC3 signer must produce a well-formed signed request."""
        import ciscvm
        captured = {}
        def fake_urlopen(req, *a, **kw):
            hdr = {k.lower(): v for k, v in req.headers.items()}
            captured["url"] = req.full_url
            captured["auth"] = hdr.get("authorization", "")
            captured["action"] = hdr.get("x-tc-action", "")
            captured["region"] = hdr.get("x-tc-region", "")
            captured["body"] = req.data.decode()
            class R:
                def read(self):
                    return b'{"Response": {"ImageSet": [{"ImageId": "img-x"}]}}'
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    return False
            return R()
        with mock.patch("ciscvm.urllib.request.urlopen", side_effect=fake_urlopen):
            import os as _os
            with mock.patch.dict(_os.environ, {"TENCENTCLOUD_SECRET_ID": "AKIDtest", "TENCENTCLOUD_SECRET_KEY": "sk-test"}):
                out = ciscvm._images_exist("ap-guangzhou", ["img-x"])
        assert out == ["img-x"]
        assert captured["url"].endswith("cvm.tencentcloudapi.com")
        assert captured["auth"].startswith("TC3-HMAC-SHA256 Credential=AKIDtest/")
        assert "SignedHeaders=content-type;host;x-tc-action" in captured["auth"]
        assert captured["action"] == "DescribeImages"
        assert captured["region"] == "ap-guangzhou"


class TestIdempotencyAndSarif:
    """ciscvm test --idempotency + scan --sarif."""

    def test_idempotency_rendered(self, valid_toml, tmp_path):
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r, idempotency=True)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "__IDEMPOTENCY_BLOCK__" not in hcl
        assert hcl.count('playbook_file    = "ansible/site.yml"') == 2  # apply + re-apply
        assert hcl.count("{") == hcl.count("}")

    def test_idempotency_not_rendered_by_default(self, valid_toml, tmp_path):
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert hcl.count('playbook_file    = "ansible/site.yml"') == 1

    def test_cmd_test_pass(self, valid_toml, tmp_path):
        from ciscvm import PackerResult, cmd_test
        r = resolve(valid_toml)
        lines = ["==> building", "Applied:   0", "Pending:   0", "done"]
        with (
            mock.patch("ciscvm._load_resolve_preflight", return_value=(r, tmp_path / "b")),
            mock.patch("ciscvm.render_all"),
            mock.patch("ciscvm.run_packer",
                       return_value=PackerResult(exit_code=0, stdout_lines=lines)),
        ):
            rc = cmd_test(mock.MagicMock(config="x", workdir="b", quiet=True,
                                         debug=False, idempotency=True))
        assert rc == 0

    def test_cmd_test_fail_on_changes(self, valid_toml, tmp_path):
        from ciscvm import PackerResult, cmd_test
        r = resolve(valid_toml)
        lines = ["Applied:   0", "Applied:   5", "Pending:   2"]  # second run changed
        with (
            mock.patch("ciscvm._load_resolve_preflight", return_value=(r, tmp_path / "b")),
            mock.patch("ciscvm.render_all"),
            mock.patch("ciscvm.run_packer",
                       return_value=PackerResult(exit_code=0, stdout_lines=lines)),
        ):
            rc = cmd_test(mock.MagicMock(config="x", workdir="b", quiet=True,
                                         debug=False, idempotency=True))
        assert rc == 1

    def test_sarif_build(self):
        from ciscvm import _build_sarif
        out = _build_sarif([
            "==> something",
            "✗ 1.5.6 | kernel.kptr_restrict",
            "  runtime ok but not persisted",
            "✗ 5.4.3.2 | TMOUT",
        ])
        d = json.loads(out)
        assert d["version"] == "2.1.0"
        run = d["runs"][0]
        assert run["tool"]["driver"]["name"] == "ciscvm"
        assert len(run["results"]) == 2
        assert run["results"][0]["ruleId"] == "1.5.6"
        assert "not persisted" in run["results"][0]["message"]["text"]

    def test_scan_sarif_written(self, valid_toml, tmp_path):
        from ciscvm import PackerResult, cmd_scan
        r = resolve(valid_toml)
        out = tmp_path / "scan.sarif"
        with (
            mock.patch("ciscvm._load_resolve_preflight", return_value=(r, tmp_path / "b")),
            mock.patch("ciscvm.render_all"),
            mock.patch("ciscvm.run_packer",
                       return_value=PackerResult(exit_code=0, stdout_lines=[
                           "Score: 92.0%", "✗ 1.1.1.9 | squashfs disabled"])),
            mock.patch("ciscvm._record_lineage"),
            mock.patch("ciscvm._write_provenance"),
        ):
            rc = cmd_scan(mock.MagicMock(config="x", workdir="b", quiet=True, debug=False,
                                         min_score=85.0, sarif=str(out)))
        assert rc == 0
        assert out.exists()
        d = json.loads(out.read_text())
        assert d["runs"][0]["results"][0]["ruleId"] == "1.1.1.9"
