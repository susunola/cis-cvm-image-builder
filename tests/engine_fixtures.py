"""Reusable fixtures/helpers for unit-testing the per-OS ohbs_engine.py copies.

Each ohbs_image/roles/<role>/files/ohbs_engine.py is a standalone, stdlib-only
module (no Ansible imports), so it can be loaded directly via importlib and
exercised with mocked filesystem/os primitives -- no root, no real mounts,
no cloud.  PR #5 added ``fstab_only`` partition logic and a late-boot
``cis-sysctl-apply.service``; these helpers make that code path testable.

Design notes
------------
The engine reads/writes hardcoded absolute paths (/etc/fstab,
/etc/systemd/system/cis-sysctl-apply.service, /etc/sysctl.d/...).  Rather than
patching path strings, we monkeypatch the module-level primitives the engine
uses (``exists``, ``readlines``, ``write_file``, ``sh``, ``systemd_present``),
which is robust across all role copies.
"""

from __future__ import annotations

import importlib.util
import os

import pytest

# Map of role name -> engine file path (relative to repo root).
ENGINE_PATHS = {
    "cis-rhel8": "ohbs_image/roles/cis-rhel8/files/ohbs_engine.py",
    "cis-rhel9": "ohbs_image/roles/cis-rhel9/files/ohbs_engine.py",
    "cis-rhel10": "ohbs_image/roles/cis-rhel10/files/ohbs_engine.py",
    "cis-tencentos3": "ohbs_image/roles/cis-tencentos3/files/ohbs_engine.py",
    "cis-tencentos4": "ohbs_image/roles/cis-tencentos4/files/ohbs_engine.py",
    "cis-ubuntu2004": "ohbs_image/roles/cis-ubuntu2004/files/ohbs_engine.py",
    "cis-ubuntu2204": "ohbs_image/roles/cis-ubuntu2204/files/ohbs_engine.py",
    "cis-ubuntu2404": "ohbs_image/roles/cis-ubuntu2404/files/ohbs_engine.py",
}


def load_engine(role, repo_root=None):
    """Load a role's ohbs_engine.py as an importable module.

    Uses a unique module name per role so multiple engines can coexist in one
    test session without import-name collisions.
    """
    if role not in ENGINE_PATHS:
        raise ValueError("unknown role {!r} (known: {})".format(role, ", ".join(ENGINE_PATHS)))
    path = ENGINE_PATHS[role]
    if repo_root is not None:
        path = os.path.join(repo_root, path)
    # Resolve relative to CWD if not absolute.
    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"engine not found: {path}")
    spec = importlib.util.spec_from_file_location(f"ohbs_engine_{role}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeFs:
    """In-memory file store used to mock the engine's file reads/writes.

    Provides ``exists``, ``readlines``, and ``write_file`` callables that the
    engine is monkeypatched with.  Paths are normalized to their basename so
    tests can refer to "/etc/fstab" etc. without a real filesystem.
    """

    def __init__(self):
        self.files = {}
        self.written = []  # list of (path, content) for assertions

    def _norm(self, path):
        return os.path.basename(path)

    def set(self, path, content):
        self.files[self._norm(path)] = content

    def exists(self, path):
        return self._norm(path) in self.files

    def readlines(self, path):
        if not self.exists(path):
            return []
        return self.files[self._norm(path)].splitlines()

    def read(self, path):
        return self.files.get(self._norm(path))

    def write_file(self, ctx, path, content, mode=0o644):
        self.files[self._norm(path)] = content
        self.written.append((path, content))
        ctx.add_changed_file(path)
        return True, f"written {path}"

    class _Writer:
        def __init__(self, store, key):
            self._store = store
            self._key = key
            self._buf = []

        def write(self, data):
            self._buf.append(data)

        def flush(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            cur = self._store.files.get(self._key, "")
            self._store.files[self._key] = cur + "".join(self._buf)
            return False

    def open(self, path, mode="r", encoding=None):
        """Minimal open() supporting "a" (append) and "r" (read).

        Lets engine code that calls the builtin open() (e.g. f_partition's
        fstab append) run against the in-memory store instead of /etc.
        """
        key = self._norm(path)
        if mode.startswith("r"):
            return self._Reader(self, key)
        # append / write
        return self._Writer(self, key)

    class _Reader:
        def __init__(self, store, key):
            self._data = store.files.get(key, "")

        def read(self):
            return self._data

        def readlines(self):
            return self._data.splitlines()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False


class FakeCtx:
    """Minimal stand-in for the engine's Ctx, sharing the real caching/lock
    semantics by reusing the loaded module's Ctx when available, else a
    lightweight implementation."""

    def __init__(self, engine, backup_dir=None, mode="apply", allow_disruptive=True):
        self._engine = engine
        self.backup_dir = backup_dir
        self.mode = mode
        # The real Ctx exposes the CLI namespace as .opts (run_rule reads
        # ctx.opts.mode); mirror just enough of it for mode-dependent checks.
        import types as _t
        self.opts = _t.SimpleNamespace(mode=mode)
        self.allow_disruptive = allow_disruptive
        self.dry = mode != "apply"
        self.changed_files = []
        self.notes = []
        self._cache = {}
        import threading
        # Mirror of the real Ctx's package-manager lock (f_updates_applied
        # takes it directly, like _install_pkgs does).
        self._pkg_lock = threading.RLock()
        self.restarts = []  # defer_restart() captures queued service names

    # -- methods the engine calls -----------------------------------------
    def defer_restart(self, svc_name):
        self.restarts.append(svc_name)

    def flush_restarts(self):
        self.restarts.clear()

    def cached(self, key, producer):
        if key not in self._cache:
            self._cache[key] = producer()
        return self._cache[key]

    def file_lock(self, path):
        import contextlib

        return contextlib.nullcontext()

    def add_changed_file(self, path):
        if path not in self.changed_files:
            self.changed_files.append(path)

    def add_note(self, note):
        self.notes.append(note)

    def invalidate(self, *keys):
        for k in keys:
            self._cache.pop(k, None)


def make_ctx(engine, mode="apply", allow_disruptive=True, backup_dir=None):
    """Build a FakeCtx bound to the loaded engine module."""
    return FakeCtx(engine, backup_dir=backup_dir, mode=mode,
                   allow_disruptive=allow_disruptive)


def apply_fs_mocks(monkeypatch, engine, fakefs):
    """Redirect the engine's file primitives at ``fakefs``."""
    monkeypatch.setattr(engine, "exists", fakefs.exists)
    monkeypatch.setattr(engine, "readlines", fakefs.readlines)
    monkeypatch.setattr(engine, "read", fakefs.read)
    monkeypatch.setattr(engine, "write_file", fakefs.write_file)
    # f_partition's fstab_only branch calls the builtin open() directly for
    # the append; redirect it at the in-memory store so no real /etc write.
    monkeypatch.setattr("builtins.open", fakefs.open)


def mock_mounts(monkeypatch, engine, mounts):
    """Patch engine._mounts to return ``mounts`` (dict mp -> {fstype, opts}).

    ``mounts`` may be a dict directly, or a callable taking (ctx) for dynamic
    behavior.  opts, if omitted, default to an empty set.
    """
    def _fake_mounts(ctx):
        out = {}
        src = mounts if isinstance(mounts, dict) else mounts(ctx)
        for mp, info in src.items():
            opts = info.get("opts", set()) if isinstance(info, dict) else set()
            fstype = info.get("fstype") if isinstance(info, dict) else info
            out[mp] = {"src": "x", "fstype": fstype, "opts": set(opts)}
        return out

    monkeypatch.setattr(engine, "_mounts", _fake_mounts)
    return _fake_mounts


def mock_systemd(monkeypatch, engine, present=True, sh_calls=None):
    """Patch systemd_present() and sh().

    ``sh_calls`` (if given) is a list that receives every ``sh`` invocation
    (the cmd list/str) so tests can assert on systemctl behavior.
    """
    monkeypatch.setattr(engine, "systemd_present", lambda: present)

    def _fake_sh(cmd, timeout=60):
        if sh_calls is not None:
            sh_calls.append(cmd)
        return 0, "", ""

    monkeypatch.setattr(engine, "sh", _fake_sh)
    return _fake_sh


# -- a smoke test proving the harness loads an engine and mocks it ----------
def test_harness_loads_ubuntu2404_and_mocks():
    eng = load_engine("cis-ubuntu2404")
    assert callable(eng.c_partition)
    assert callable(getattr(eng, "_fstab_has_tmpfs", None)), \
        "PR #5 helper missing -- harness out of sync with engine"

    fakefs = FakeFs()
    ctx = make_ctx(eng)
    with pytest.MonkeyPatch().context() as mp:
        apply_fs_mocks(mp, eng, fakefs)
        # /etc/fstab absent -> helper returns False
        assert eng._fstab_has_tmpfs(ctx, "/tmp") is False
        # now present with a tmpfs entry for /tmp
        fakefs.set("/etc/fstab", "tmpfs  /tmp  tmpfs  defaults  0 0\n")
        assert eng._fstab_has_tmpfs(ctx, "/tmp") is True
        assert eng._fstab_has_tmpfs(ctx, "/var/tmp") is False
