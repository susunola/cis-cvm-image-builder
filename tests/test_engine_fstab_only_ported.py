"""Verify the PR #5 fstab_only / cis-sysctl-service logic was ported to all
Linux engines (task 3a).  We sample rhel9 (representative of the 7 engines the
logic was ported into) and assert the same behaviors as the ubuntu2404 tests.

This also guards the `test_all_linux_engines_in_sync` invariant: if the port
drifts, these tests fail alongside the sync test.
"""

from __future__ import annotations

import pytest

from tests.engine_fixtures import (
    FakeFs,
    apply_fs_mocks,
    load_engine,
    make_ctx,
    mock_mounts,
    mock_systemd,
)

ENG = load_engine("ohbs-rhel9")


def test_rhel9_has_pr5_symbols():
    assert callable(getattr(ENG, "_fstab_has_tmpfs", None))
    assert callable(getattr(ENG, "ensure_cis_sysctl_service", None))


def test_rhel9_c_partition_fstab_only_passes():
    fs = FakeFs()
    fs.set("/etc/fstab", "tmpfs  /tmp  tmpfs  defaults  0 0\n")
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        mock_mounts(mp, ENG, {})
        st, msg = ENG.c_partition(ctx, {"mount": "/tmp", "fstab_only": True})
    assert st == "pass" and "next boot" in msg


def test_rhel9_f_partition_fstab_only_idempotent():
    fs = FakeFs()
    fs.set("/etc/fstab", "# fstab\n")
    ctx = make_ctx(ENG)
    params = {"mount": "/tmp", "allow_tmpfs": True, "fstab_only": True}
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        mock_mounts(mp, ENG, {})
        ENG.f_partition(ctx, params)
        ENG.f_partition(ctx, params)
    content = fs.read("/etc/fstab")
    assert sum(1 for ln in content.splitlines() if "/tmp  tmpfs" in ln) == 1


def test_rhel9_ensure_sysctl_service_creates_unit():
    fs = FakeFs()
    sh_calls = []
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        mock_systemd(mp, ENG, present=True, sh_calls=sh_calls)
        ENG.ensure_cis_sysctl_service(ctx)
    unit = fs.read("/etc/systemd/system/cis-sysctl-apply.service")
    assert unit and "WantedBy=multi-user.target" in unit
    assert any("enable" in (c if isinstance(c, str) else " ".join(c)) for c in sh_calls)
