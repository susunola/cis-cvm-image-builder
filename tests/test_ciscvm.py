"""Tests for ciscvm — CIS-hardened Golden Image Builder."""

from __future__ import annotations

import logging
import os
import subprocess
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
        assert r.associate_public_ip is True
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
        assert (wd / "ansible" / "roles" / "cis_tencentos3" / "tasks" / "main.yml").exists()
        assert not (wd / "packer" / "scripts" / "verify-cis.sh").exists()

    def test_no_unreplaced_markers(self, valid_toml, tmp_path):
        r = resolve(valid_toml)
        wd = tmp_path / "build"
        render_all(wd, r)
        hcl = (wd / "packer" / "main.pkr.hcl").read_text()
        assert "__CLEAN_CMD__" not in hcl
        assert "__WINRM_PASSWORD_ENV__" not in hcl
        assert ";" not in hcl, "semicolons are not valid in HCL"

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
            rc = cmd_build(mock.MagicMock(config="x", workdir=str(wd), yes=True, quiet=False))
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
            rc = cmd_build(mock.MagicMock(config="x", workdir=str(wd), yes=True, quiet=False))
        assert rc == 0
        # Image ID is surfaced via the logger (stderr), captured by caplog elsewhere;
        # here we just confirm the command succeeded and did not crash on parsing.

    def test_build_quiet_does_not_dump_log(self, tmp_path, capsys):
        """--quiet build shows only the summary, never the packer log."""
        from ciscvm import PackerResult, cmd_build

        r, wd = self._prep(tmp_path)
        packer_lines = ["==> building", "Created image ID: img-q", "done"]
        captured_quiet: dict[str, object] = {}

        def fake_run_packer(workdir, subcmd, quiet=False, capture=False, timeout=None, debug=False):
            captured_quiet["quiet"] = quiet
            captured_quiet["capture"] = capture
            return PackerResult(exit_code=0, stdout_lines=packer_lines)

        with (
            mock.patch("ciscvm._load_resolve_preflight", return_value=(r, wd)),
            mock.patch("ciscvm.render_all"),
            mock.patch("ciscvm.run_packer", side_effect=fake_run_packer),
        ):
            rc = cmd_build(mock.MagicMock(config="x", workdir=str(wd), yes=True, quiet=True))
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
            rc = cmd_build(mock.MagicMock(config="x", workdir=str(wd), yes=True, quiet=False))
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
