"""Resolver tests for the benchmark-aware catalog layer.

These prove the core can select a non-CIS catalog without touching the engine:
CIS/legacy always map to ``rules.json``; a non-CIS benchmark resolves to
``rules_<slug>.json`` and falls back to ``rules.json`` when that file is absent.
"""
from __future__ import annotations

from pathlib import Path

from ohbs_image._catalog import (
    _catalog_basename,
    _catalog_path,
    benchmark_slug,
)


def test_slug_normalization():
    assert benchmark_slug("STIG-RHEL9") == "stig_rhel9"
    assert benchmark_slug("CIS-v5.1.0") == "cis_v5_1_0"
    assert benchmark_slug("NIST-800-53") == "nist_800_53"
    assert benchmark_slug("") == ""
    # Dashes and dots collapse to underscores; interior spaces are preserved
    # (benchmarks rarely contain them, but the slug must stay stable).
    assert benchmark_slug("  STIG RHEL9 ") == "stig rhel9"


def test_cis_maps_to_rules_json():
    # Legacy / CIS profiles must keep the historical rules.json (no rename,
    # so the 12 byte-identical engine copies and all existing tests are safe).
    for bm in ("", "CIS-v1.0.0", "cis", "CIS benchmark"):
        assert _catalog_basename("cis-rhel9", bm) == "rules.json"
        assert _catalog_path("cis-rhel9", bm).name == "rules.json"


def test_stig_resolves_to_specific_file_when_present(tmp_path, monkeypatch):
    # Simulate a bundled benchmark-specific catalog by redirecting the resolver's
    # roles root at a synthetic tree containing rules_stig_rhel9.json.
    files = tmp_path / "roles" / "cis-rhel9" / "files"
    files.mkdir(parents=True)
    (files / "rules.json").write_text("{}")
    (files / "rules_stig_rhel9.json").write_text('{"benchmark": "STIG-RHEL9"}')

    monkeypatch.setattr("ohbs_image._catalog._roles_dir", lambda: tmp_path / "roles")
    assert _catalog_basename("cis-rhel9", "STIG-RHEL9") == "rules_stig_rhel9.json"
    assert _catalog_path("cis-rhel9", "STIG-RHEL9").name == "rules_stig_rhel9.json"


def test_stig_falls_back_to_rules_json_when_absent():
    # No rules_stig_rhel9.json bundled yet -> fall back to rules.json so a
    # profile can declare a new benchmark before its catalog exists.
    assert _catalog_basename("cis-rhel9", "STIG-RHEL9") == "rules.json"


def test_workspace_rules_json_takes_precedence(tmp_path):
    # Once the workspace copy of rules.json exists (overrides applied there),
    # _catalog_path must return it regardless of benchmark.
    workdir = tmp_path / "build" / ".ohbs-image-build"
    files = workdir / "ansible" / "roles" / "cis-rhel9" / "files"
    files.mkdir(parents=True)
    (files / "rules.json").write_text('{"overrides": true}')

    resolved = _catalog_path("cis-rhel9", "STIG-RHEL9", workdir=workdir)
    assert resolved == (files / "rules.json").resolve()
