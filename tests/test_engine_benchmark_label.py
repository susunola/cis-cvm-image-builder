"""Prove the engine is benchmark-agnostic (no engine edits required).

The engine dispatches rules on ``family`` and labels results with whatever
``--benchmark`` string the caller passes.  This test loads the stock rhel9
engine, runs a rule under several benchmarks (including non-CIS ones), and
asserts the benchmark label flows into the result while rule selection still
happens via family.  Adding STIG/NIST thus needs zero engine changes — only a
catalog.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from tests.engine_fixtures import load_engine


def _make_opts(benchmark):
    return SimpleNamespace(
        mode="scan",
        allow_disruptive=False,
        backup_dir=None,
        benchmark=benchmark,
    )


@pytest.mark.parametrize("benchmark", ["", "CIS-v1.0.0", "STIG-RHEL9", "NIST-800-53"])
def test_engine_labels_result_with_any_benchmark(benchmark):
    eng = load_engine("cis-rhel9")
    opts = _make_opts(benchmark)
    ctx = eng.Ctx(opts)

    # A manual-family rule exercises run_rule's dispatch + labeling without
    # touching filesystem primitives — the point is the benchmark label, which
    # is pure metadata the engine copies straight through.
    rule = {
        "id": "1.1.1.1",
        "title": "Example control",
        "family": "manual",
        "levels": [1],
        "assessment": "Manual",
        "risk": "none",
    }
    res = eng.run_rule(ctx, rule)

    assert res["id"] == "1.1.1.1"
    assert res["family"] == "manual"
    assert res["benchmark"] == (benchmark or "")
    # rule_id = benchmark + " " + id (P0#2 cross-reference format).
    expected_rule_id = (benchmark + " " if benchmark else "") + "1.1.1.1"
    assert res["rule_id"] == expected_rule_id


def test_engine_dispatches_on_family_registry_not_benchmark():
    """The check/fix registry is keyed purely by family — a non-CIS benchmark
    string never appears as a dispatch key, so adding STIG/NIST families is a
    pure additive operation on the CHECKS/FIXES dicts."""
    eng = load_engine("cis-rhel9")
    # Real families resolve to callables regardless of any benchmark concept.
    for fam in ("kmod", "sysctl", "partition", "file_perm", "world_writable",
                "svc_disabled"):
        assert eng.CHECKS.get(fam) is not None, f"family {fam!r} has no check"
    # And the benchmark field is not used as a registry key at all.
    assert "STIG-RHEL9" not in eng.CHECKS
    assert "CIS-v1.0.0" not in eng.CHECKS
