"""Tests for scripts/check_readme.py — the CI README-freshness guard."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import check_readme  # noqa: E402

ALL_CMDS = {"audit", "build", "check-source", "clean", "cleanup-images", "drift",
            "images", "init", "list", "pending", "preflight", "scan", "test",
            "validate", "verify", "verify-image"}


class TestReadmeDocumentedSubcommands:
    def test_all_present(self):
        readme = "\n".join(f"cis-image {c}" for c in ALL_CMDS)
        found = check_readme.readme_documented_subcommands(readme, ALL_CMDS)
        assert found == ALL_CMDS

    def test_verify_image_not_swallowed_by_verify(self):
        """`verify-image` must not be reported present just because `verify`
        appears; and `verify` must not be over-matched by `verify-image`."""
        readme = "cis-image verify\ncis-image verify-image\n"
        found = check_readme.readme_documented_subcommands(readme, ALL_CMDS)
        assert "verify" in found
        assert "verify-image" in found

    def test_missing_command_reported(self):
        readme = "cis-image build\ncis-image init\n"
        found = check_readme.readme_documented_subcommands(readme, ALL_CMDS)
        assert "build" in found and "init" in found
        missing = ALL_CMDS - found
        assert "audit" in missing and "verify-image" in missing

    def test_inline_flag_does_not_fake_presence(self):
        """A bare word like `build` inside prose (not `cis-image build`) must
        not count as documenting the command."""
        readme = "the build step runs packer\ncis-image init\n"
        found = check_readme.readme_documented_subcommands(readme, ALL_CMDS)
        assert "build" not in found  # only `cis-image init` is authoritative
        assert "init" in found


class TestReadmeDocumentedProfiles:
    def test_all_profiles_present(self):
        readme = " ".join(check_readme._PROFILE_NAMES)
        found = check_readme.readme_documented_profiles(readme)
        assert found == set(check_readme._PROFILE_NAMES)

    def test_missing_profile_reported(self):
        readme = "ubuntu2004 rhel9 win2022"
        found = check_readme.readme_documented_profiles(readme)
        assert "tencentos4" not in found


class TestCheckReadme:
    def test_returns_empty_when_current(self):
        readme = "\n".join(f"cis-image {c}" for c in ALL_CMDS) + "\n" + \
                 " ".join(check_readme._PROFILE_NAMES)
        assert check_readme.check_readme(readme, ALL_CMDS,
                                         set(check_readme._PROFILE_NAMES)) == []

    def test_reports_missing_command(self):
        readme = "cis-image init"
        errors = check_readme.check_readme(readme, ALL_CMDS,
                                           set(check_readme._PROFILE_NAMES))
        assert any("subcommand" in e for e in errors)
        assert "build" in errors[0]

    def test_reports_missing_profile(self):
        readme = "cis-image init\nubuntu2004 rhel9"
        errors = check_readme.check_readme(
            readme, {"init"}, {"ubuntu2004", "rhel9", "tencentos4"})
        assert any("profile" in e for e in errors)
        assert "tencentos4" in [e for e in errors if "profile" in e][0]


def monkeypatch_open(content: str):
    """Point check_readme's Path.read_text at an in-memory string and make any
    path look like it exists (so main() proceeds past the existence check)."""
    import unittest.mock as mock
    def fake_read_text(self, *a, **kw):  # noqa: ANN001
        return content
    return mock.patch.multiple(
        Path,
        read_text=fake_read_text,
        exists=lambda self: True,
    )


class TestMainExitCodes:
    def test_missing_readme_returns_1(self):
        assert check_readme.main(["--readme", "/nonexistent/README.md"]) == 1

    def test_main_returns_1_when_out_of_date(self, monkeypatch, capsys):
        """main() exits 1 (not 0) and prints the missing items when the
        README is missing a command."""
        readme = "cis-image init"
        monkeypatch.setattr(check_readme, "registered_subcommands",
                            lambda: set(ALL_CMDS))
        with monkeypatch_open(readme):
            rc = check_readme.main(["--readme", "/tmp/fake_readme.md"])
        assert rc == 1
        err = capsys.readouterr().err
        assert "build" in err

    def test_main_returns_0_when_current(self, monkeypatch):
        readme = "\n".join(f"cis-image {c}" for c in ALL_CMDS) + "\n" + \
                 " ".join(check_readme._PROFILE_NAMES)
        monkeypatch.setattr(check_readme, "registered_subcommands",
                            lambda: set(ALL_CMDS))
        with monkeypatch_open(readme):
            rc = check_readme.main(["--readme", "/tmp/fake_readme.md"])
        assert rc == 0


class TestCheckTestConsistency:
    """Tests for check_readme.check_test_consistency()."""

    def test_current_state_is_consistent(self):
        """The committed tests/test_check_readme.py matches the live CLI."""
        import cis_image
        registered = set(cis_image.build_parser()._subparsers._group_actions[0].choices)
        profiles = set(cis_image.PROFILES.keys())
        assert check_readme.check_test_consistency(registered, profiles) == []

    def test_reports_missing_command_in_all_cmds(self, tmp_path, monkeypatch):
        """If ALL_CMDS drops a command the CLI registers, it's reported."""
        src = (check_readme.REPO_ROOT / "tests" / "test_check_readme.py").read_text()
        # simulate ALL_CMDS missing 'audit' by stripping one entry
        src = src.replace('"audit", ', '')
        (tmp_path / "tests").mkdir()
        f = tmp_path / "tests" / "test_check_readme.py"
        f.write_text(src)
        monkeypatch.setattr(check_readme, "REPO_ROOT", tmp_path)
        errs = check_readme.check_test_consistency({"audit", "build"}, set())
        assert any("audit" in e and "ALL_CMDS" in e for e in errs)

    def test_reports_unknown_command_in_all_cmds(self, tmp_path, monkeypatch):
        """If ALL_CMDS lists a command the CLI doesn't register, it's reported."""
        src = (check_readme.REPO_ROOT / "tests" / "test_check_readme.py").read_text()
        src = src.replace("}",
            '"phantom-cmd"}', 1)
        (tmp_path / "tests").mkdir()
        f = tmp_path / "tests" / "test_check_readme.py"
        f.write_text(src)
        monkeypatch.setattr(check_readme, "REPO_ROOT", tmp_path)
        errs = check_readme.check_test_consistency({"audit"}, set())
        assert any("phantom-cmd" in e and "unknown" in e for e in errs)

    def test_reports_missing_test_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(check_readme, "REPO_ROOT", tmp_path)
        errs = check_readme.check_test_consistency({"audit"}, set())
        assert any("test file not found" in e for e in errs)
