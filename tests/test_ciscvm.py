"""Tests for ciscvm — TencentOS CIS Image Builder."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path
from unittest import mock

import pytest

import ciscvm
from ciscvm import (
    ConfigError,
    PackerResult,
    ResolvedConfig,
    PROFILES,
    SAMPLE_CONFIG,
    _format_hcl_value,
    _validate_value_present,
    _bundle_role,
    _check_bundled_role,
    build_parser,
    cmd_build,
    cmd_clean,
    cmd_init,
    cmd_preflight,
    cmd_validate,
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

    def test_valid(self):
        assert _validate_value_present("x", "img-abc123") is None

    def test_none(self):
        assert _validate_value_present("x", None) is not None


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


# ---------------------------------------------------------------------------
# resolve()
# ---------------------------------------------------------------------------
class TestResolve:
    def test_tencentos3(self, valid_toml):
        r = resolve(valid_toml)
        assert isinstance(r, ResolvedConfig)
        assert r.profile_name == "tencentos3"
        assert r.level == 1
        assert r.cis_level_tag == "level1-server"
        assert r.ssh_username == "root"
        assert r.role_dir == "cis_tencentos3"
        assert r.associate_public_ip is True

    def test_tencentos4(self, valid_toml):
        valid_toml["build"]["profile"] = "tencentos4"
        # Remove [meta] so the profile default os_tag is used
        del valid_toml["meta"]
        r = resolve(valid_toml)
        assert r.profile_name == "tencentos4"
        assert r.role_dir == "cis_tencentos4"
        assert r.image_os_tag == "tencentos-4"

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


# ---------------------------------------------------------------------------
# Render functions
# ---------------------------------------------------------------------------
class TestRenderPkrvars:
    def test_output(self, valid_toml):
        r = resolve(valid_toml)
        out = render_pkrvars(r)
        assert "ssh_username" in out
        assert "tencentos" in out or "root" in out
        assert "true" in out or "false" in out


class TestRenderInstall:
    def test_tencentos3(self):
        p = PROFILES["tencentos3"]
        out = render_install(p)
        assert "cis-os engine" in out
        assert "dnf makecache" in out
        assert "ansible-core" in out

    def test_tencentos4(self):
        p = PROFILES["tencentos4"]
        out = render_install(p)
        assert "cis-os engine" in out
        assert "dnf makecache" in out


class TestRenderSite:
    def test_level1(self):
        p = PROFILES["tencentos3"]
        out = render_site(p, level=1)
        assert "cis_fail_on_findings" in out
        assert "cis_profile: L1" in out
        assert "cis_tencentos3" in out

    def test_level2(self):
        p = PROFILES["tencentos4"]
        out = render_site(p, level=2)
        assert "cis_profile: L2" in out
        assert "cis_tencentos4" in out


class TestRenderAll:
    def test_tencentos3(self, valid_toml, tmp_path):
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        assert (wd / "packer" / "main.pkr.hcl").exists()
        assert (wd / "packer" / "auto.pkrvars.hcl").exists()
        assert (wd / "ansible" / "site.yml").exists()
        assert (wd / "packer" / "scripts" / "install-ansible.sh").exists()
        assert os.access(wd / "packer" / "scripts" / "install-ansible.sh", os.X_OK)
        # Role was copied
        assert (wd / "ansible" / "roles" / "cis_tencentos3" / "tasks" / "main.yml").exists()
        # No verify script (gate is in-role)
        assert not (wd / "packer" / "scripts" / "verify-cis.sh").exists()

    def test_no_unreplaced_markers(self, valid_toml, tmp_path):
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "__CLEAN_CMD__" not in hcl
        assert "__WINRM_PASSWORD_ENV__" not in hcl

    def test_tencentos4(self, valid_toml, tmp_path):
        valid_toml["build"]["profile"] = "tencentos4"
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        assert (wd / "ansible" / "roles" / "cis_tencentos4" / "tasks" / "main.yml").exists()


# ---------------------------------------------------------------------------
# Bundled role helpers
# ---------------------------------------------------------------------------
class TestBundleRole:
    def test_copies_role(self, tmp_path):
        wd = tmp_path / "build"
        _bundle_role(wd, "cis_tencentos3")
        assert (wd / "ansible" / "roles" / "cis_tencentos3" / "tasks" / "main.yml").exists()

    def test_missing_role_warns(self, tmp_path, caplog):
        caplog.set_level(logging.WARNING, logger="ciscvm")
        wd = tmp_path / "build"
        _bundle_role(wd, "nonexistent_role")
        assert "not found" in caplog.text


class TestCheckBundledRole:
    def test_exists(self):
        assert _check_bundled_role("cis_tencentos3") is True

    def test_not_exists(self):
        assert _check_bundled_role("no_such_role") is False


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

        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout="", stderr=""),
                subprocess.CompletedProcess([], 0, stdout="OK", stderr=""),
            ]
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
        rc = cmd_clean(mock.MagicMock(workdir=str(wd)))
        assert rc == 0
        assert not wd.exists()

    def test_missing_directory_is_ok(self, tmp_path):
        wd = tmp_path / "nonexistent"
        rc = cmd_clean(mock.MagicMock(workdir=str(wd)))
        assert rc == 0


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
    def test_all_have_os_tag(self):
        for name, p in PROFILES.items():
            assert p.get("os_tag"), f"{name}: missing os_tag"

    def test_all_have_benchmark(self):
        for name, p in PROFILES.items():
            assert p.get("benchmark"), f"{name}: missing benchmark"

    def test_all_have_role_dir(self):
        for name, p in PROFILES.items():
            assert p.get("role_dir"), f"{name}: missing role_dir"

    def test_all_have_ssh_username(self):
        for name, p in PROFILES.items():
            assert p.get("ssh_username"), f"{name}: missing ssh_username"

    def test_all_have_pkg_install(self):
        for name, p in PROFILES.items():
            assert p.get("pkg_install"), f"{name}: missing pkg_install"
            assert p.get("pkg_update"), f"{name}: missing pkg_update"
            assert p.get("clean_cmd"), f"{name}: missing clean_cmd"

    def test_count_is_2(self):
        assert len(PROFILES) == 2, f"Expected 2 profiles, got {len(PROFILES)}"


# ---------------------------------------------------------------------------
# Integration: end-to-end render for all profiles
# ---------------------------------------------------------------------------
class TestAllProfilesRender:
    @pytest.mark.parametrize("profile_name", list(PROFILES))
    def test_profile_renders(self, profile_name, valid_toml, tmp_path):
        valid_toml["build"]["profile"] = profile_name
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        assert (wd / "packer" / "main.pkr.hcl").exists(), f"{profile_name}: no main.pkr.hcl"
        assert (wd / "ansible" / "site.yml").exists(), f"{profile_name}: no site.yml"

        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "__CLEAN_CMD__" not in hcl, f"{profile_name}: unreplaced __CLEAN_CMD__"
