"""Unit tests for PR #5 (ubuntu2404-l1 100% gap closure).

Covers the four behaviors PR #5 added to ohbs-ubuntu2404's engine, all exercised
under mocked filesystem / mounts / systemd -- no root or real mounts required.

  * _fstab_has_tmpfs()
  * c_partition() -- fstab_only "pass at next boot" branch
  * f_partition() -- fstab_only "write fstab, no live-mount" branch
  * ensure_cis_sysctl_service() -- late-boot systemd unit creation
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

ENG = load_engine("ohbs-ubuntu2404")


# --------------------------------------------------------------------------
# _fstab_has_tmpfs
# --------------------------------------------------------------------------
def test_fstab_has_tmpfs_true():
    fs = FakeFs()
    fs.set("/etc/fstab", "tmpfs  /tmp  tmpfs  defaults,noexec  0 0\n")
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        assert ENG._fstab_has_tmpfs(ctx, "/tmp") is True


def test_fstab_has_tmpfs_absent_file():
    fs = FakeFs()
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        assert ENG._fstab_has_tmpfs(ctx, "/tmp") is False


def test_fstab_has_tmpfs_comment_ignored():
    fs = FakeFs()
    fs.set("/etc/fstab", "# tmpfs  /tmp  tmpfs  defaults  0 0\n")
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        assert ENG._fstab_has_tmpfs(ctx, "/tmp") is False


def test_fstab_has_tmpfs_wrong_mountpoint():
    fs = FakeFs()
    fs.set("/etc/fstab", "tmpfs  /var/tmp  tmpfs  defaults  0 0\n")
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        assert ENG._fstab_has_tmpfs(ctx, "/tmp") is False


def test_fstab_has_tmpfs_non_tmpfs_fstype():
    fs = FakeFs()
    fs.set("/etc/fstab", "ext4  /tmp  ext4  defaults  0 0\n")
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        assert ENG._fstab_has_tmpfs(ctx, "/tmp") is False


# --------------------------------------------------------------------------
# c_partition -- fstab_only branch
# --------------------------------------------------------------------------
def test_c_partition_fstab_only_present_passes():
    fs = FakeFs()
    fs.set("/etc/fstab", "tmpfs  /tmp  tmpfs  defaults  0 0\n")
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        mock_mounts(mp, ENG, {})  # /tmp NOT currently a mount
        st, msg = ENG.c_partition(ctx, {"mount": "/tmp", "fstab_only": True})
    assert st == "pass"
    assert "next boot" in msg


def test_c_partition_fstab_only_absent_fails():
    fs = FakeFs()
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        mock_mounts(mp, ENG, {})
        st, msg = ENG.c_partition(ctx, {"mount": "/tmp", "fstab_only": True})
    assert st == "fail"


def test_c_partition_require_tmpfs_mismatch_fails():
    """Regression: require_tmpfs=True with a non-tmpfs real mount fails."""
    fs = FakeFs()
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        mock_mounts(mp, ENG, {"/tmp": {"fstype": "ext4"}})
        st, msg = ENG.c_partition(ctx, {"mount": "/tmp", "require_tmpfs": True})
    assert st == "fail"
    assert "tmpfs required" in msg


# --------------------------------------------------------------------------
# f_partition -- fstab_only branch (writes fstab, never live-mounts)
# --------------------------------------------------------------------------
def test_f_partition_fstab_only_appends_and_is_idempotent():
    fs = FakeFs()
    fs.set("/etc/fstab", "# existing fstab\n")
    ctx = make_ctx(ENG)
    params = {"mount": "/tmp", "allow_tmpfs": True, "fstab_only": True}
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        mock_mounts(mp, ENG, {})  # not a real mount -> takes fstab_only path
        ok1, msg1 = ENG.f_partition(ctx, params)
        # second call must be idempotent (no duplicate line)
        ok2, msg2 = ENG.f_partition(ctx, params)
    assert ok1 is True
    assert "fstab" in msg1
    content = fs.read("/etc/fstab")
    assert "tmpfs  /tmp  tmpfs" in content
    # fstab_only must NOT live-mount: only /etc/fstab is recorded as changed.
    assert sum(1 for ln in content.splitlines() if "/tmp  tmpfs" in ln) == 1
    assert "/etc/fstab" in ctx.changed_files


def test_f_partition_fstab_only_reports_changed_file():
    fs = FakeFs()
    fs.set("/etc/fstab", "")
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        mock_mounts(mp, ENG, {})
        ENG.f_partition(ctx, {"mount": "/tmp", "allow_tmpfs": True, "fstab_only": True})
    assert "/etc/fstab" in ctx.changed_files


# --------------------------------------------------------------------------
# ensure_cis_sysctl_service -- late-boot systemd unit
# --------------------------------------------------------------------------
def test_ensure_sysctl_service_creates_unit_when_systemd():
    fs = FakeFs()
    sh_calls = []
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        mock_systemd(mp, ENG, present=True, sh_calls=sh_calls)
        ENG.ensure_cis_sysctl_service(ctx)
    unit = fs.read("/etc/systemd/system/cis-sysctl-apply.service")
    assert unit is not None
    assert "After=systemd-sysctl.service systemd-coredump.service apport.service" in unit
    assert "ExecStart=/sbin/sysctl -p /etc/sysctl.d/60-cis-hardening.conf" in unit
    assert "WantedBy=multi-user.target" in unit
    # daemon-reload + enable must have been issued
    assert any("daemon-reload" in (c if isinstance(c, str) else " ".join(c)) for c in sh_calls)
    assert any("enable" in (c if isinstance(c, str) else " ".join(c)) for c in sh_calls)


def test_ensure_sysctl_service_skipped_when_no_systemd():
    fs = FakeFs()
    sh_calls = []
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        mock_systemd(mp, ENG, present=False, sh_calls=sh_calls)
        ENG.ensure_cis_sysctl_service(ctx)
    assert fs.read("/etc/systemd/system/cis-sysctl-apply.service") is None
    assert sh_calls == []


def test_ensure_sysctl_service_idempotent_when_unit_exists():
    fs = FakeFs()
    # Pre-seed the unit file so the function early-returns.
    fs.set("/etc/systemd/system/cis-sysctl-apply.service", "[Unit]\n")
    sh_calls = []
    ctx = make_ctx(ENG)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, ENG, fs)
        mock_systemd(mp, ENG, present=True, sh_calls=sh_calls)
        ENG.ensure_cis_sysctl_service(ctx)
    # No enable/daemon-reload when the unit already exists.
    assert sh_calls == []
