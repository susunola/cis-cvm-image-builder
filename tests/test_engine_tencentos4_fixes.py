"""Unit tests for the 2026-08-21 tencentos4 re-audit fix round.

Covers the four findings from the v0.17.0 tencentos4-l1 image build:
  - tmp.mount ships MASKED on TencentOS 4, so a CIS /tmp tmpfs fstab entry
    never took effect at boot -> f_partition/f_mount_opt must unmask it.
  - The stock 'minimal' authselect profile has no feature files, so a
    custom profile based on it can never enable with-faillock (5.4.3) —
    _ensure_custom_profile must base the custom profile on sssd instead.
  - Vendor agents (barad_agent) re-create world-writable files under /run
    on every boot -> f_world_writable must persist the chmod via a
    .path/.service unit pair.
"""

import os

import pytest

from tests.engine_fixtures import (
    FakeFs,
    apply_fs_mocks,
    load_engine,
    make_ctx,
    mock_mounts,
    mock_systemd,
)


@pytest.fixture(scope="module")
def eng():
    return load_engine("cis-tencentos4")


# -- _unmask_mount_unit -----------------------------------------------------

def test_unmask_mount_unit_unmasks_masked_tmp(eng, monkeypatch):
    calls = []

    def fake_sh(cmd, timeout=60):
        calls.append(cmd)
        if cmd[:2] == ["systemctl", "is-enabled"]:
            return 1, "masked", ""
        return 0, "", ""

    monkeypatch.setattr(eng, "systemd_present", lambda: True)
    monkeypatch.setattr(eng, "sh", fake_sh)
    ctx = make_ctx(eng)
    eng._unmask_mount_unit(ctx, "/tmp")
    assert ["systemctl", "unmask", "tmp.mount"] in calls


def test_unmask_mount_unit_leaves_unmasked_alone(eng, monkeypatch):
    calls = []

    def fake_sh(cmd, timeout=60):
        calls.append(cmd)
        return 0, "generated", ""

    monkeypatch.setattr(eng, "systemd_present", lambda: True)
    monkeypatch.setattr(eng, "sh", fake_sh)
    ctx = make_ctx(eng)
    eng._unmask_mount_unit(ctx, "/tmp")
    assert not any(c[:2] == ["systemctl", "unmask"] for c in calls)


def test_mount_unit_name(eng):
    assert eng._mount_unit_name("/tmp") == "tmp.mount"
    assert eng._mount_unit_name("/dev/shm") == "dev-shm.mount"
    assert eng._mount_unit_name("/var/log/audit") == "var-log-audit.mount"


def test_partition_fstab_only_unmasks(eng, monkeypatch):
    """fstab_only /tmp must unmask tmp.mount or the entry is dead on TOS4."""
    fakefs = FakeFs()
    fakefs.set("/etc/fstab", "UUID=x / xfs defaults 1 1\n")
    apply_fs_mocks(monkeypatch, eng, fakefs)
    mock_mounts(monkeypatch, eng, {"/": {"fstype": "xfs"}})
    calls = []

    def fake_sh(cmd, timeout=60):
        calls.append(cmd)
        if cmd[:2] == ["systemctl", "is-enabled"]:
            return 1, "masked", ""
        return 0, "", ""

    monkeypatch.setattr(eng, "systemd_present", lambda: True)
    monkeypatch.setattr(eng, "sh", fake_sh)
    ctx = make_ctx(eng)
    ok, msg = eng.f_partition(ctx, {"mount": "/tmp", "allow_tmpfs": True,
                                    "fstab_only": True})
    assert ok, msg
    assert ["systemctl", "unmask", "tmp.mount"] in calls


# -- _ensure_custom_profile: base on sssd, not minimal ----------------------

def test_custom_profile_based_on_sssd_when_current_is_minimal(eng, monkeypatch):
    calls = []

    def fake_sh(cmd, timeout=60):
        calls.append(cmd)
        if cmd[:2] == ["authselect", "current"]:
            return 0, "Profile ID: minimal\nEnabled features: None\n", ""
        if cmd[:2] == ["authselect", "list"]:
            return 0, ("- minimal\t Local users only\n"
                       "- nis\t Enable NIS\n"
                       "- sssd\t Enable SSSD\n"), ""
        return 0, "", ""

    monkeypatch.setattr(eng, "have", lambda b: True)
    monkeypatch.setattr(eng, "sh", fake_sh)
    monkeypatch.setattr(os.path, "isdir", lambda p: True)
    ctx = make_ctx(eng)
    d = eng._ensure_custom_profile(ctx)
    assert d == "/etc/authselect/custom/cis"
    creates = [c for c in calls if c[:2] == ["authselect", "create-profile"]]
    assert creates, "create-profile was not called"
    assert "-b" in creates[0]
    assert creates[0][creates[0].index("-b") + 1] == "sssd"


def test_custom_profile_keeps_sssd_base(eng, monkeypatch):
    calls = []

    def fake_sh(cmd, timeout=60):
        calls.append(cmd)
        if cmd[:2] == ["authselect", "current"]:
            return 0, "Profile ID: sssd\n- with-faillock\n", ""
        return 0, "", ""

    monkeypatch.setattr(eng, "have", lambda b: True)
    monkeypatch.setattr(eng, "sh", fake_sh)
    monkeypatch.setattr(os.path, "isdir", lambda p: True)
    ctx = make_ctx(eng)
    eng._ensure_custom_profile(ctx)
    creates = [c for c in calls if c[:2] == ["authselect", "create-profile"]]
    assert creates[0][creates[0].index("-b") + 1] == "sssd"


# -- f_world_writable: persist chmod for tmpfs (boot-recreated) files -------

def _ww_engine(monkeypatch, eng, fakefs, world_files):
    apply_fs_mocks(monkeypatch, eng, fakefs)
    monkeypatch.setattr(eng, "_fs_scan",
                        lambda ctx: {"world_files": world_files})
    mock_mounts(monkeypatch, eng, {
        "/": {"fstype": "xfs"},
        "/run": {"fstype": "tmpfs"},
        "/dev/shm": {"fstype": "tmpfs"},
    })
    calls = []
    monkeypatch.setattr(eng, "systemd_present", lambda: True)

    def fake_sh(cmd, timeout=60):
        calls.append(cmd)
        return 0, "", ""

    monkeypatch.setattr(eng, "sh", fake_sh)
    return calls


def test_world_writable_installs_volatile_units_for_run_files(eng, monkeypatch):
    fakefs = FakeFs()
    calls = _ww_engine(monkeypatch, eng, fakefs,
                       ["/run/.barad_agent.pid", "/etc/uuid"])
    ctx = make_ctx(eng)
    ok, msg = eng.f_world_writable(ctx, {})
    assert ok, msg
    svc = fakefs.read("/etc/systemd/system/ohbs-cis-volatile-perms.service")
    assert svc, "volatile-perms service was not written"
    # the service re-scans the offending tmpfs mount generically (barad's
    # 0666 set varies boot to boot), retrying past the agents' late start;
    # /etc/uuid survives on disk and needs no boot-time handling
    assert "find /run -xdev -type f -perm -0002" in svc
    assert "chmod o-w" in svc
    assert "seq 1 180" in svc
    assert "Type=simple" in svc
    assert "RemainAfterExit" not in svc  # would suppress later activations
    assert "/etc/uuid" not in svc
    # no .path unit: PathExists re-triggers in a loop on persistent files
    assert fakefs.read("/etc/systemd/system/ohbs-cis-volatile-perms.path") is None
    assert ["systemctl", "enable",
            "ohbs-cis-volatile-perms.service"] in calls


def test_world_writable_no_units_when_all_on_disk(eng, monkeypatch):
    fakefs = FakeFs()
    _ww_engine(monkeypatch, eng, fakefs, ["/etc/uuid"])
    ctx = make_ctx(eng)
    ok, msg = eng.f_world_writable(ctx, {})
    assert ok, msg
    assert fakefs.read("/etc/systemd/system/ohbs-cis-volatile-perms.service") is None
    assert fakefs.read("/etc/systemd/system/ohbs-cis-volatile-perms.path") is None


def test_volatile_service_removes_stale_path_unit(eng, monkeypatch):
    fakefs = FakeFs()
    fakefs.set("/etc/systemd/system/ohbs-cis-volatile-perms.path",
               "[Path]\nPathExists=/run/barad_agent.lock\n")
    calls = _ww_engine(monkeypatch, eng, fakefs, ["/run/.barad_agent.pid"])
    unlinked = []
    monkeypatch.setattr(os, "unlink", unlinked.append)
    ctx = make_ctx(eng)
    eng.f_world_writable(ctx, {})
    assert "/etc/systemd/system/ohbs-cis-volatile-perms.path" in unlinked
    assert ["systemctl", "disable", "--now",
            "ohbs-cis-volatile-perms.path"] in calls


# -- f_mount_opt: tmpfs fstab persistence also unmasks ----------------------

def test_mount_opt_tmpfs_fstab_line_and_unmask(eng, monkeypatch):
    fakefs = FakeFs()
    fakefs.set("/etc/fstab", "UUID=x / xfs defaults 1 1\n")
    apply_fs_mocks(monkeypatch, eng, fakefs)
    written = {}

    def fake_atomic_write(path, content, mode=None, preserve_owner=True):
        written[path] = content

    monkeypatch.setattr(eng, "atomic_write", fake_atomic_write)
    mock_mounts(monkeypatch, eng, {
        "/": {"fstype": "xfs"},
        "/dev/shm": {"fstype": "tmpfs", "opts": {"rw", "nosuid", "nodev"}},
    })
    calls = []

    def fake_sh(cmd, timeout=60):
        calls.append(cmd)
        if cmd[:2] == ["systemctl", "is-enabled"]:
            return 0, "generated", ""
        return 0, "", ""

    monkeypatch.setattr(eng, "systemd_present", lambda: True)
    monkeypatch.setattr(eng, "sh", fake_sh)
    ctx = make_ctx(eng)
    ok, msg = eng.f_mount_opt(ctx, {"mount": "/dev/shm", "option": "noexec"})
    assert ok, msg
    fstab = written.get("/etc/fstab", "")
    shm_lines = [l for l in fstab.splitlines() if "/dev/shm" in l]
    assert shm_lines and "noexec" in shm_lines[0]
    assert ["systemctl", "is-enabled", "dev-shm.mount"] in calls


def test_mount_opt_tmpfs_records_late_boot_remount(eng, monkeypatch):
    """Successful tmpfs remount -> cis-mount-apply.service re-asserts the
    options at every boot (defeats flaky systemd-remount-fs passes)."""
    fakefs = FakeFs()
    fakefs.set("/etc/fstab", "UUID=x / xfs defaults 1 1\n")
    apply_fs_mocks(monkeypatch, eng, fakefs)
    monkeypatch.setattr(eng, "atomic_write",
                        lambda path, content, mode=None, preserve_owner=True:
                        fakefs.set(path, content))
    live_opts = {"rw", "nosuid", "nodev"}

    def mounts_src(ctx):
        return {
            "/": {"fstype": "xfs"},
            "/dev/shm": {"fstype": "tmpfs", "opts": set(live_opts)},
        }

    mock_mounts(monkeypatch, eng, mounts_src)
    calls = []

    def fake_sh(cmd, timeout=60):
        calls.append(cmd)
        if cmd[:1] == ["mount"]:
            live_opts.add("noexec")
        return 0, "", ""

    monkeypatch.setattr(eng, "systemd_present", lambda: True)
    monkeypatch.setattr(eng, "sh", fake_sh)
    ctx = make_ctx(eng)
    ok, msg = eng.f_mount_opt(ctx, {"mount": "/dev/shm", "option": "noexec"})
    assert ok, msg
    unit = fakefs.read("/etc/systemd/system/cis-mount-apply.service")
    assert unit, "cis-mount-apply.service was not written"
    assert "ExecStart=/bin/mount -o remount," in unit
    assert "noexec" in unit
    assert unit.rstrip().endswith("WantedBy=multi-user.target")
    assert ["systemctl", "enable", "cis-mount-apply.service"] in calls
