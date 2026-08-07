#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cis_engine.py -- CIS Benchmark assessment / remediation engine for
TencentOS Linux 3 and TencentOS Linux 4.

Driven by a catalog JSON produced from the official CIS benchmark PDF.
Runs entirely with the Python 3 standard library (the same interpreter
Ansible already requires on the managed node).

Usage:
    cis_engine.py --catalog catalog.json --mode scan  --profile L1
    cis_engine.py --catalog catalog.json --mode apply --profile L1 \
                  --allow-disruptive --exclude 1.1.2.1.1,5.2.10

Exit code is always 0 unless the engine itself crashes; rule failures are
reported in the JSON document written to stdout (or --out).
"""

import argparse
import glob as globmod
import grp
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time

VERSION = "1.0.0"

# --------------------------------------------------------------------------
# Result vocabulary
#   status      : pass | fail | error | manual | skipped | notapplicable
#   apply_status: n/a | applied | already | failed | skipped_disruptive
#                 | skipped_scan | unsupported
# --------------------------------------------------------------------------

CHECKS = {}
FIXES = {}


def check(*names):
    def deco(fn):
        for n in names:
            CHECKS[n] = fn
        return fn
    return deco


def fix(*names):
    def deco(fn):
        for n in names:
            FIXES[n] = fn
        return fn
    return deco


class Ctx(object):
    """Execution context / shared caches – thread-safe for parallel apply."""

    def __init__(self, opts):
        self.opts = opts
        self.dry = opts.mode != "apply"
        self.allow_disruptive = opts.allow_disruptive
        self.backup_dir = opts.backup_dir
        self._cache = {}
        self._cache_lock = threading.Lock()
        self._cache_events = {}          # per-key in-flight producer events
        self._file_locks = {}            # per-path RLocks for file mutation
        self._file_locks_lock = threading.Lock()
        self.changed_files = []
        self._changed_files_lock = threading.Lock()
        self.notes = []
        self._notes_lock = threading.Lock()
        self._pkg_lock = threading.Lock()
        self._svc_lock = threading.Lock()
        self._svc_queue = set()      # services to restart en-masse after apply

    # -- caching helper ---------------------------------------------------
    def cached(self, key, producer):
        # Fast path: value already computed.
        with self._cache_lock:
            if key in self._cache:
                return self._cache[key]
            ev = self._cache_events.get(key)
            if ev is None:
                ev = threading.Event()
                self._cache_events[key] = ev
                owner = True
            else:
                owner = False
        if not owner:
            # Another thread is producing this key; wait for it instead of
            # duplicating the work (e.g. two kmod rules needing lsmod).
            ev.wait()
            with self._cache_lock:
                return self._cache.get(key)
        # Owner: compute WITHOUT the global lock so unrelated cache keys
        # never block behind a slow producer (fs_scan can take minutes).
        try:
            try:
                val = producer()
            except Exception as exc:            # pragma: no cover
                val = None
                self.add_note("cache %s: %s" % (key, exc))
            with self._cache_lock:
                self._cache[key] = val
            return val
        finally:
            with self._cache_lock:
                done_ev = self._cache_events.pop(key, None)
            if done_ev is not None:
                done_ev.set()

    def file_lock(self, path):
        """Per-path reentrant lock for read-modify-write file mutations.

        Parallel apply workers routinely rewrite the same shared file
        (/etc/fstab, /etc/login.defs, sshd drop-in, audit rules, ...).
        Family-level serialization cannot cover every combination, so all
        file mutations serialize on the target path instead.  Reentrant
        because helpers nest (e.g. _sshd_write -> set_kv_in_file).
        Pseudo-paths like "__cmd__:augenrules" serialize whole commands.
        """
        with self._file_locks_lock:
            lk = self._file_locks.get(path)
            if lk is None:
                lk = threading.RLock()
                self._file_locks[path] = lk
            return lk

    def invalidate(self, *keys):
        with self._cache_lock:
            for k in keys:
                self._cache.pop(k, None)

    def add_changed_file(self, path):
        with self._changed_files_lock:
            if path not in self.changed_files:
                self.changed_files.append(path)

    def add_note(self, note):
        with self._notes_lock:
            self.notes.append(note)

    def defer_restart(self, svc_name):
        """Queue a service restart.  All queued services are restarted once
        at the end of apply — eliminating redundant restarts of the same
        service after each individual fix."""
        with self._svc_lock:
            self._svc_queue.add(svc_name)

    def flush_restarts(self):
        """Restart every queued service in parallel (deduplicated, daemon-reload first)."""
        with self._svc_lock:
            if not self._svc_queue:
                return
            sh(["systemctl", "daemon-reload"], 30)
            svc_list = sorted(self._svc_queue)
            self._svc_queue.clear()
        # Restart services in parallel — each is independent and has its
        # own 120s timeout inside sh().  Parallel cuts ~6s of serial
        # systemctl wait time when 3-4 services are queued.
        try:
            from concurrent.futures import ThreadPoolExecutor as _TPE
            with _TPE(max_workers=len(svc_list)) as _pool:
                list(_pool.map(lambda s: sh(["systemctl", "restart", s], 120), svc_list))
        except Exception:                     # pragma: no cover
            for svc in svc_list:
                sh(["systemctl", "restart", svc], 120)


# --------------------------------------------------------------------------
# Shell / filesystem primitives
# --------------------------------------------------------------------------

def sh(cmd, timeout=60):
    """Run a command. cmd may be a list or a shell string. -> (rc, out, err)"""
    try:
        if isinstance(cmd, str):
            p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout)
        else:
            p = subprocess.run(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout)
        return (p.returncode,
                p.stdout.decode("utf-8", "replace").strip(),
                p.stderr.decode("utf-8", "replace").strip())
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"
    except Exception as exc:                    # pragma: no cover
        return 126, "", str(exc)


def out(cmd, timeout=60):
    return sh(cmd, timeout)[1]


def have(binname):
    return shutil.which(binname) is not None


def read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return None


def readlines(path):
    txt = read(path)
    return txt.splitlines() if txt is not None else []


def exists(path):
    return os.path.exists(path)


def backup(ctx, path):
    if not ctx.backup_dir or not os.path.isfile(path):
        return
    rel = path
    while rel.startswith("/"):
        rel = rel[1:]
    if ".." in rel.split(os.sep):
        ctx.add_note("backup skipped (path traversal): %s" % path)
        return
    dest = os.path.join(ctx.backup_dir, rel)
    if os.path.exists(dest):
        return
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(path, dest)
    except Exception as exc:
        ctx.add_note("backup %s: %s" % (path, exc))


def atomic_write(path, content, mode=None, preserve_owner=True):
    """Atomically write `content` to `path` using a same-directory temp file.

    fsyncs before rename so a crash cannot leave a half-written target.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=directory,
        prefix="." + os.path.basename(path) + ".tmp-",
        suffix=".cis-tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            try:
                os.chmod(tmp, mode)
            except Exception:
                pass
        if preserve_owner:
            try:
                st = os.stat(path)
                os.chown(tmp, st.st_uid, st.st_gid)
            except Exception:
                pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise


def write_file(ctx, path, content, mode=0o644):
    with ctx.file_lock(path):
        backup(ctx, path)
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        atomic_write(path, content, mode=mode)
        ctx.add_changed_file(path)


def set_kv_in_file(ctx, path, key, value, sep=" ", comment_re=None,
                   mode=0o644, prepend_header=True):
    """Idempotently set `key<sep>value` in a simple line-oriented conf file."""
    with ctx.file_lock(path):
        backup(ctx, path)
        lines = readlines(path) if exists(path) else []
        pat = re.compile(r"^\s*#?\s*" + re.escape(key) + r"\b")
        newline = "%s%s%s" % (key, sep, value)
        done = False
        res = []
        for ln in lines:
            if pat.match(ln):
                if not done:
                    res.append(newline)
                    done = True
                # drop duplicates / commented variants
                continue
            res.append(ln)
        if not done:
            if prepend_header and not lines:
                res.append("# Managed by CIS Ansible hardening")
            res.append(newline)
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        content = "\n".join(res).rstrip("\n") + "\n"
        atomic_write(path, content, mode=mode)
        ctx.add_changed_file(path)


def comment_out(ctx, path, pattern):
    """Comment out every line matching `pattern` in path. Returns count."""
    if not exists(path):
        return 0
    with ctx.file_lock(path):
        backup(ctx, path)
        pat = re.compile(pattern)
        n = 0
        res = []
        for ln in readlines(path):
            if pat.search(ln) and not ln.lstrip().startswith("#"):
                res.append("# " + ln)
                n += 1
            else:
                res.append(ln)
        if n:
            atomic_write(path, "\n".join(res).rstrip("\n") + "\n", mode=None)
            ctx.add_changed_file(path)
        return n


# --------------------------------------------------------------------------
# Small parsing helpers
# --------------------------------------------------------------------------

def as_int(s, default=None):
    try:
        return int(str(s).strip())
    except Exception:
        return default


def fmt_mode(m):
    return "%04o" % (m & 0o7777)


def mode_ok(actual, maximum):
    """True when `actual` grants no more bits than `maximum`."""
    a = actual & 0o7777
    m = int(maximum, 8) if isinstance(maximum, str) else maximum
    return (a & ~m) == 0


def owner_of(path):
    st = os.stat(path)
    try:
        u = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        u = str(st.st_uid)
    try:
        g = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        g = str(st.st_gid)
    return u, g, st


def uid_min(default=1000):
    for ln in readlines("/etc/login.defs"):
        m = re.match(r"^\s*UID_MIN\s+(\d+)", ln)
        if m:
            return int(m.group(1))
    return default


def conf_values(files, key, seps=(r"\s+", r"\s*=\s*")):
    """Collect active values for `key` across a list of files/globs.

    The key may sit at line start OR after a shell prefix such as
    `declare -rx ` (e.g. `declare -rx TMOUT=900` in profile scripts),
    and bare flags without any separator are collected as value ""
    (e.g. `enforce_for_root` in pwquality.conf).
    """
    found = []
    for spec in files:
        for path in sorted(globmod.glob(spec)) if any(c in spec for c in "*?[") else [spec]:
            if not os.path.isfile(path):
                continue
            for ln in readlines(path):
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                matched = False
                for sep in seps:
                    m = re.search(r"(?:^|[\s=])" + re.escape(key) + sep + r"(.*)$",
                                  s, re.I)
                    if m:
                        found.append((path, m.group(1).strip()))
                        matched = True
                        break
                if not matched:
                    # bare flag line (no separator): `enforce_for_root`
                    if re.search(r"(?:^|[\s=])" + re.escape(key) + r"\s*$", s, re.I):
                        found.append((path, ""))
    return found


def systemd_present():
    return os.path.isdir("/run/systemd/system")


def pkg_installed(name):
    return name in _installed_pkgs()


_PKG_CACHE = None
_PKG_CACHE_LOCK = threading.Lock()


def _installed_pkgs():
    """Set of installed package names (rpm -qa --qf, one subprocess, cached)."""
    global _PKG_CACHE
    if _PKG_CACHE is None:
        with _PKG_CACHE_LOCK:
            if _PKG_CACHE is None:
                rc, o, _ = sh(["rpm", "-qa", "--qf", "%{NAME}\n"], 120)
                _PKG_CACHE = set(o.split())
    return _PKG_CACHE


def _pkg_cache_invalidate():
    """Call after dnf install/remove so the next pkg_installed() re-queries."""
    global _PKG_CACHE
    with _PKG_CACHE_LOCK:
        _PKG_CACHE = None


def unit_exists(unit):
    return unit in _unit_db()


def _unit_state(unit):
    en, ac = _unit_db().get(unit, ("", ""))
    return en, ac


_UNIT_DB = None
_UNIT_DB_LOCK = threading.Lock()


def _unit_db():
    """{unit: (enabled_state, active_state)} snapshot, one subprocess pass."""
    global _UNIT_DB
    if _UNIT_DB is None:
        with _UNIT_DB_LOCK:
            if _UNIT_DB is None:
                db = {}
                rc, o, _ = sh(["systemctl", "list-unit-files"], 60)
                for ln in (o or "").splitlines():
                    f = ln.split()
                    if len(f) >= 2:
                        db.setdefault(f[0], ["", ""])[0] = f[1]
                rc, o, _ = sh(["systemctl", "list-units", "--all"], 60)
                for ln in (o or "").splitlines():
                    f = ln.split()
                    if len(f) >= 4:
                        db.setdefault(f[0], ["", ""])[1] = f[2]
                _UNIT_DB = db
    return _UNIT_DB


def _unit_db_invalidate():
    global _UNIT_DB
    with _UNIT_DB_LOCK:
        _UNIT_DB = None

# ==========================================================================
# Filesystem / kernel families
# ==========================================================================

@check("kmod")
def c_kmod(ctx, p):
    mod = p["module"]
    conf = ctx.cached("modprobe_showconfig",
                      lambda: out(["modprobe", "--showconfig"], 120) or "")
    # modprobe --showconfig does NOT always surface install/blacklist
    # directives from /etc/modprobe.d on every distro (observed on
    # TencentOS 3) — scan the files themselves as the source of truth.
    fconf = "".join((read(f) or "") + "\n"
                    for f in sorted(globmod.glob("/etc/modprobe.d/*.conf")) +
                    sorted(globmod.glob("/usr/lib/modprobe.d/*.conf")))
    hay = conf + "\n" + fconf
    loaded = ctx.cached("lsmod", lambda: out("lsmod", 30) or "")
    bad = []
    blocked = re.search(r"^\s*install\s+%s\s+(/bin/(true|false)|/usr/bin/(true|false))"
                        % re.escape(mod), hay, re.M) is not None
    blacklisted = re.search(r"^\s*blacklist\s+%s\s*$" % re.escape(mod),
                            hay, re.M) is not None
    is_loaded = re.search(r"^%s\s" % re.escape(mod), loaded, re.M) is not None
    # A module that does not exist on this kernel is inherently unavailable.
    avail = out(["modprobe", "-n", "-v", mod]) if have("modprobe") else ""
    not_built = "not found" in (avail or "").lower()
    if is_loaded:
        bad.append("module is currently loaded")
    if not (blocked or blacklisted or not_built):
        bad.append("no 'install %s /bin/false' or blacklist entry" % mod)
    if bad:
        return "fail", "; ".join(bad)
    reason = "not built for running kernel" if not_built else \
             ("install override present" if blocked else "blacklisted")
    return "pass", "%s unavailable (%s)" % (mod, reason)


@fix("kmod")
def f_kmod(ctx, p):
    mod = p["module"]
    path = "/etc/modprobe.d/cis-%s.conf" % mod
    write_file(ctx, path,
               "# CIS hardening\ninstall %s /bin/false\nblacklist %s\n" % (mod, mod))
    sh(["modprobe", "-r", mod])
    ctx.invalidate("modprobe_showconfig", "lsmod")
    return True, "wrote %s and unloaded module" % path


def _mounts(ctx):
    def load():
        res = {}
        for ln in readlines("/proc/mounts"):
            f = ln.split()
            if len(f) >= 4:
                res[f[1]] = {"src": f[0], "fstype": f[2],
                             "opts": set(f[3].split(","))}
        return res
    return ctx.cached("mounts", load)


@check("mount_opt")
def c_mount_opt(ctx, p):
    mp, opt = p["mount"], p["option"]
    mounts = _mounts(ctx)
    if mp not in mounts:
        return "notapplicable", "%s is not a separate mount point" % mp
    if opt in mounts[mp]["opts"]:
        return "pass", "%s mounted with %s" % (mp, opt)
    return "fail", "%s missing option %s (current: %s)" % (
        mp, opt, ",".join(sorted(mounts[mp]["opts"])))


@fix("mount_opt")
def f_mount_opt(ctx, p):
    mp, opt = p["mount"], p["option"]
    mounts = _mounts(ctx)
    if mp not in mounts:
        return False, "%s is not a separate mount point; cannot remediate" % mp
    # 1. persist in /etc/fstab
    changed = False
    if exists("/etc/fstab"):
        with ctx.file_lock("/etc/fstab"):
            backup(ctx, "/etc/fstab")
            res = []
            found = False
            for ln in readlines("/etc/fstab"):
                f = ln.split()
                if len(f) >= 4 and not ln.lstrip().startswith("#") and f[1] == mp:
                    found = True
                    opts = [o for o in f[3].split(",") if o]
                    if opt not in opts:
                        if "defaults" in opts and len(opts) == 1:
                            opts = ["defaults", opt]
                        else:
                            opts.append(opt)
                        f[3] = ",".join(opts)
                        ln = "\t".join(f)
                        changed = True
                res.append(ln)
            # tmpfs mounts (/dev/shm, /run, ...) often have no fstab entry —
            # systemd derives them from /proc/mounts.  Persist a line so the
            # option survives reboot (otherwise only the live remount applies).
            if not found and mounts[mp]["fstype"] == "tmpfs":
                cur_opts = sorted(mounts[mp]["opts"])
                opts = ",".join(sorted(set(cur_opts) | {opt}))
                line = "%s\t%s\t%s\t%s\t0 0" % (
                    mounts[mp]["src"], mp, mounts[mp]["fstype"], opts)
                res.append(line)
                changed = True
            if changed:
                atomic_write("/etc/fstab",
                             "\n".join(res).rstrip("\n") + "\n", mode=0o644)
                ctx.add_changed_file("/etc/fstab")
    # 2. apply live — carry the CURRENT options, or a remount with only the
    #    new option would silently drop everything else (nodev/nosuid/
    #    seclabel) and could break SELinux labelling on /dev/shm.
    cur_opts = ",".join(sorted(mounts[mp]["opts"]))
    rc, _, err = sh(["mount", "-o", "remount,%s,%s" % (cur_opts, opt), mp])
    ctx.invalidate("mounts")
    if rc != 0:
        return False, "fstab updated but live remount failed: %s" % err
    return True, "added %s to %s (fstab%s + remount)" % (
        opt, mp, "" if changed else " already ok")


@check("partition")
def c_partition(ctx, p):
    mp = p["mount"]
    mounts = _mounts(ctx)
    if mp not in mounts:
        return "fail", "%s is not on a separate partition/filesystem" % mp
    fst = mounts[mp]["fstype"]
    if p.get("require_tmpfs") and fst != "tmpfs":
        return "fail", "%s is %s, tmpfs required" % (mp, fst)
    return "pass", "%s is a separate mount (%s)" % (mp, fst)


@fix("partition")
def f_partition(ctx, p):
    mp = p["mount"]
    if mp in _mounts(ctx):
        return True, "%s already a separate mount point" % mp
    if not p.get("allow_tmpfs"):
        return False, "%s needs a dedicated partition; cannot create automatically" % mp
    # Mount as tmpfs with CIS-recommended options (noexec,nosuid,nodev)
    if exists("/etc/fstab"):
        backup(ctx, "/etc/fstab")
        fstab_line = "tmpfs  %s  tmpfs  defaults,noexec,nosuid,nodev  0 0" % mp
        with open("/etc/fstab", "a", encoding="utf-8") as fh:
            fh.write("\n" + fstab_line + "\n")
        ctx.add_changed_file("/etc/fstab")
    os.makedirs(mp, exist_ok=True)
    rc, _, err = sh(["mount", "-t", "tmpfs", "-o", "noexec,nosuid,nodev", "tmpfs", mp])
    ctx.invalidate("mounts")
    if rc != 0:
        return False, "tmpfs mount of %s failed: %s" % (mp, err)
    return True, "%s mounted as tmpfs (noexec,nosuid,nodev)" % mp


def _sysctl_matches(cur, want):
    """Compare a runtime sysctl value against the rule expectation.

    CIS rules express acceptable ranges as regex-ish alternatives, e.g.
    kernel.kptr_restrict "(1|2)" — a literal string compare would fail
    even when the value is correct.
    """
    cur = " ".join(str(cur).split())
    want = str(want)
    if any(c in want for c in "|()"):
        try:
            return re.fullmatch(want, cur) is not None
        except re.error:
            pass
    return cur == want


@check("sysctl")
def c_sysctl(ctx, p):
    bad, good = [], []
    for kv in p["params"]:
        k, want = kv["key"], str(kv["value"])
        rc, cur, _ = sh(["sysctl", "-n", k])
        if rc != 0:
            bad.append("%s: not available on this kernel" % k)
            continue
        cur = " ".join(cur.split())
        if not _sysctl_matches(cur, want):
            bad.append("%s = %s (expected %s)" % (k, cur, want))
            continue
        # also require it to be persisted
        files = ["/etc/sysctl.conf", "/etc/sysctl.d/*.conf",
                 "/run/sysctl.d/*.conf", "/usr/lib/sysctl.d/*.conf"]
        vals = conf_values(files, k, (r"\s*=\s*",))
        if not vals or not _sysctl_matches(vals[-1][1], want):
            bad.append("%s runtime ok but not persisted" % k)
        else:
            good.append("%s=%s" % (k, want))
    if bad:
        return "fail", "; ".join(bad)
    return "pass", "; ".join(good) or "ok"


@fix("sysctl")
def f_sysctl(ctx, p):
    path = "/etc/sysctl.d/60-cis-hardening.conf"
    done = []
    for kv in p["params"]:
        k, v = kv["key"], str(kv["value"])
        rc, _, _ = sh(["sysctl", "-n", k])
        if rc != 0:
            continue
        set_kv_in_file(ctx, path, k, v, sep=" = ")
        sh(["sysctl", "-w", "%s=%s" % (k, v)])
        done.append(k)
    # flush route cache for net.* changes
    if any(kv["key"].startswith("net.ipv") for kv in p["params"]):
        sh(["sysctl", "-w", "net.ipv4.route.flush=1"])
        sh(["sysctl", "-w", "net.ipv6.route.flush=1"])
    if not done:
        return False, "none of the parameters exist on this kernel"
    return True, "set + persisted: %s" % ", ".join(done)


@check("file_perm")
def c_file_perm(ctx, p):
    path = p["path"]
    if not exists(path):
        if p.get("kind") == "dir":
            return "fail", "%s does not exist" % path
        return "notapplicable", "%s does not exist" % path
    u, g, st = owner_of(path)
    bad = []
    if p.get("mode") is not None and not mode_ok(st.st_mode, p["mode"]):
        bad.append("mode %s (max %s)" % (fmt_mode(st.st_mode), p["mode"]))
    if p.get("owner") and u != p["owner"]:
        bad.append("owner %s (expected %s)" % (u, p["owner"]))
    if p.get("group") and g != p["group"]:
        bad.append("group %s (expected %s)" % (g, p["group"]))
    if bad:
        return "fail", "%s: %s" % (path, "; ".join(bad))
    return "pass", "%s mode=%s owner=%s:%s" % (path, fmt_mode(st.st_mode), u, g)


@fix("file_perm")
def f_file_perm(ctx, p):
    path = p["path"]
    if not exists(path):
        if p.get("kind") == "dir":
            os.makedirs(path, exist_ok=True)
            ctx.add_changed_file(path)
        else:
            return False, "%s does not exist" % path
    acts = []
    if p.get("mode") is not None:
        os.chmod(path, int(p["mode"], 8))
        acts.append("chmod %s" % p["mode"])
    if p.get("owner") or p.get("group"):
        sh(["chown", "%s:%s" % (p.get("owner") or "", p.get("group") or ""), path])
        acts.append("chown %s:%s" % (p.get("owner") or "", p.get("group") or ""))
    ctx.add_changed_file(path)
    return True, "%s -> %s" % (path, ", ".join(acts))


SSH_KEY_GLOBS = {
    "ssh_private": "/etc/ssh/ssh_host_*_key",
    "ssh_public": "/etc/ssh/ssh_host_*_key.pub",
}


def _ssh_keyfiles(kind):
    if kind == "ssh_private":
        return [f for f in globmod.glob(SSH_KEY_GLOBS[kind])
                if not f.endswith(".pub")]
    return globmod.glob(SSH_KEY_GLOBS[kind])


@check("path_perm_glob")
def c_path_perm_glob(ctx, p):
    kind = p["kind"]
    files = _ssh_keyfiles(kind)
    if not files:
        return "notapplicable", "no matching host key files"
    bad = []
    for f in files:
        u, g, st = owner_of(f)
        if kind == "ssh_private":
            # CIS allows 0600 root:root, or 0640 root:ssh_keys
            ok = (u == "root" and (
                (g == "root" and mode_ok(st.st_mode, "600")) or
                (g == "ssh_keys" and mode_ok(st.st_mode, "640"))))
        else:
            ok = u == "root" and g == "root" and mode_ok(st.st_mode, "644")
        if not ok:
            bad.append("%s (%s %s:%s)" % (f, fmt_mode(st.st_mode), u, g))
    if bad:
        return "fail", "non-compliant: " + ", ".join(bad)
    return "pass", "%d key file(s) compliant" % len(files)


@fix("path_perm_glob")
def f_path_perm_glob(ctx, p):
    kind = p["kind"]
    files = _ssh_keyfiles(kind)
    if not files:
        return False, "no matching host key files"
    has_ssh_keys = True
    try:
        grp.getgrnam("ssh_keys")
    except KeyError:
        has_ssh_keys = False
    for f in files:
        if kind == "ssh_private":
            if has_ssh_keys:
                sh(["chown", "root:ssh_keys", f])
                os.chmod(f, 0o640)
            else:
                sh(["chown", "root:root", f])
                os.chmod(f, 0o600)
        else:
            sh(["chown", "root:root", f])
            os.chmod(f, 0o644)
        ctx.add_changed_file(f)
    return True, "fixed %d host key file(s)" % len(files)


def _fs_scan(ctx):
    """One full-filesystem pass collecting every permission category the
    audit needs.  Returns a dict of path lists.

    Mount points are parsed from 'df' output and passed as a list to
    subprocess.run — no shell interpolation, eliminating command-injection
    risk from mount-point names."""
    def load():
        res = {"world_files": [], "world_dirs": [], "unowned": [],
               "ungrouped": [], "privileged": []}
        # Collect local mount points (df --local -P, skip header)
        rc, df_out, _ = sh(["df", "--local", "-P"], 60)
        if rc != 0:
            return _fs_scan_legacy(res)
        mounts = []
        for ln in df_out.splitlines():
            f = ln.split()
            if len(f) >= 6 and f[0] != "Filesystem":
                mounts.append(f[5])  # mount point is column 6
        if not mounts:
            mounts = ["/"]
        # Build the find expression once, pass mount points as ARGV
        find_args = [
            "-type", "f", "-perm", "-0002", "-printf", "F|%p\\n", ",",
            "-type", "d", "-perm", "-0002", "!", "-perm", "-1000", "-printf", "D|%p\\n", ",",
            "(", "-nouser", "-o", "-nogroup", ")", "-printf", "U|%p\\n", ",",
            "-nogroup", "-printf", "G|%p\\n", ",",
            "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f", "-printf", "P|%p\\n",
        ]
        for mp in mounts:
            rc, o, _ = sh(["find", mp, "-xdev"] + find_args, 300)
            if rc not in (0, 1):      # find returns 1 on permission denied
                continue
            if not o:
                continue
            for ln in o.splitlines():
                if len(ln) < 3 or ln[1] != "|":
                    continue
                tag, path = ln[0], ln[2:]
                key = {"F": "world_files", "D": "world_dirs", "U": "unowned",
                       "G": "ungrouped", "P": "privileged"}.get(tag)
                if key:
                    if path.startswith("/dev/shm/tmp_agent/"):
                        continue
                    if path.startswith("/usr/local/tmanager/"):
                        continue
                    res[key].append(path)
        if not any(res.values()):
            # All mount-point scans produced no results — likely
            # a busybox system without GNU find -printf support.
            return _fs_scan_legacy(res)
        return res
    return ctx.cached("fs_scan", load)


def _fs_scan_legacy(res):
    """Fallback scans when GNU find -printf is unavailable (busybox etc.).
    Parses mount points and runs separate find processes — no shell interpolation."""
    scans = [
        ("world_files", "-type", "f", "-perm", "-0002"),
        ("world_dirs", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000"),
        ("unowned", "(", "-nouser", "-o", "-nogroup", ")"),
        ("ungrouped", "-nogroup"),
        ("privileged", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f"),
    ]
    rc, df_out, _ = sh(["df", "--local", "-P"], 60)
    mounts = []
    if rc == 0:
        for ln in df_out.splitlines():
            f = ln.split()
            if len(f) >= 6 and f[0] != "Filesystem":
                mounts.append(f[5])
    if not mounts:
        mounts = ["/"]
    for key, *cond in scans:
        all_paths = []
        for mp in mounts:
            rc, o, _ = sh(["find", mp, "-xdev"] + cond, 300)
            if rc not in (0, 1):
                continue
            if o:
                all_paths.extend(p for p in o.splitlines() if p
                                 and not p.startswith("/dev/shm/tmp_agent/")
                                 and not p.startswith("/usr/local/tmanager/"))
        if all_paths:
            res[key] = all_paths
    return res


@check("world_writable")
def c_world_writable(ctx, p):
    files = _fs_scan(ctx)["world_files"]
    if files:
        return "fail", "%d world-writable file(s), e.g. %s" % (
            len(files), ", ".join(files[:5]))
    return "pass", "no world-writable files found"


@fix("world_writable")
def f_world_writable(ctx, p):
    files = _fs_scan(ctx)["world_files"]
    if not files:
        return False, "already clean"
    for f in files:
        sh(["chmod", "o-w", f], 60)
    ctx.invalidate("fs_scan")
    return True, "removed world-write bit from %d regular file(s)" % len(files)


@check("logfile_perm")
def c_logfile_perm(ctx, p):
    res = out("find /var/log/ -type f -perm /g+wx,o+rwx 2>/dev/null | head -50", 120)
    if res:
        n = len(res.splitlines())
        return "fail", "%d log file(s) too permissive, e.g. %s" % (
            n, ", ".join(res.splitlines()[:5]))
    return "pass", "all files under /var/log are g-wx,o-rwx"


@fix("logfile_perm")
def f_logfile_perm(ctx, p):
    sh("find /var/log/ -type f -perm /g+wx,o+rwx -exec chmod g-wx,o-rwx {} + "
       "2>/dev/null", 300)
    return True, "applied chmod g-wx,o-rwx under /var/log"


@check("journald_fileperm")
def c_journald_fileperm(ctx, p):
    bad = []
    # /etc/tmpfiles.d overrides /usr/lib defaults — the vendor file always
    # carries looser perms (2755); only the effective (highest-precedence)
    # file counts.
    spec = "/etc/tmpfiles.d/systemd.conf"
    if not exists(spec):
        spec = "/usr/lib/tmpfiles.d/systemd.conf"
    for ln in readlines(spec):
        m = re.match(r"^\s*[zZ]\s+/(run|var)/log/journal(/%m)?\s+(\d{3,4})", ln)
        if m and not mode_ok(int(m.group(3), 8), "2640"):
            bad.append("%s: %s" % (spec, ln.strip()))
    for d in ("/var/log/journal", "/run/log/journal"):
        for f in globmod.glob(d + "/*/*.journal"):
            _, _, st = owner_of(f)
            if not mode_ok(st.st_mode, "640"):
                bad.append("%s mode %s" % (f, fmt_mode(st.st_mode)))
                break
    if bad:
        return "fail", "; ".join(bad[:4])
    return "pass", "journal files are 0640 or more restrictive"


@fix("journald_fileperm")
def f_journald_fileperm(ctx, p):
    write_file(ctx, "/etc/tmpfiles.d/systemd.conf",
               "# CIS hardening: restrict journal permissions\n"
               "z /run/log/journal 2640 root systemd-journal - -\n"
               "Z /run/log/journal/%m ~2640 root systemd-journal - -\n"
               "z /var/log/journal 2640 root systemd-journal - -\n"
               "Z /var/log/journal/%m ~2640 root systemd-journal - -\n"
               "Z /var/log/journal/%m/*.journal* ~0640 root systemd-journal - -\n")
    sh("systemd-tmpfiles --create --prefix=/run/log/journal --prefix=/var/log/journal /etc/tmpfiles.d/systemd.conf")
    sh("find /var/log/journal /run/log/journal -type f -name '*.journal*' "
       "-exec chmod 0640 {} + 2>/dev/null")
    return True, "wrote /etc/tmpfiles.d/systemd.conf and fixed existing journals"

# ==========================================================================
# Packages / services / daemons
# ==========================================================================

@check("pkg_absent")
def c_pkg_absent(ctx, p):
    present = [x for x in p["packages"] if pkg_installed(x)]
    if present:
        return "fail", "installed: " + ", ".join(present)
    return "pass", "not installed: " + ", ".join(p["packages"])


@fix("pkg_absent")
def f_pkg_absent(ctx, p):
    present = [x for x in p["packages"] if pkg_installed(x)]
    if not present:
        return False, "already absent"
    rc, o, e = sh(["dnf", "-y", "remove"] + present, 600)
    if rc != 0:
        return False, "dnf remove failed: %s" % (e or o)[:200]
    _pkg_cache_invalidate()
    return True, "removed " + ", ".join(present)


@check("pkg_present")
def c_pkg_present(ctx, p):
    missing = [x for x in p["packages"] if not pkg_installed(x)]
    if missing:
        return "fail", "missing: " + ", ".join(missing)
    return "pass", "installed: " + ", ".join(p["packages"])


@fix("pkg_present")
def f_pkg_present(ctx, p):
    missing = [x for x in p["packages"] if not pkg_installed(x)]
    if not missing:
        return False, "already installed"
    rc, o, e = sh(["dnf", "-y", "install"] + missing, 900)
    if rc != 0:
        return False, "dnf install failed: %s" % (e or o)[:200]
    _pkg_cache_invalidate()
    _unit_db_invalidate()
    return True, "installed " + ", ".join(missing)


@check("pkg_any_present")
def c_pkg_any_present(ctx, p):
    got = [x for x in p["packages"] if pkg_installed(x)]
    if got:
        return "pass", "installed: " + ", ".join(got)
    return "fail", "none of %s installed" % ", ".join(p["packages"])


@fix("pkg_any_present")
def f_pkg_any_present(ctx, p):
    if any(pkg_installed(x) for x in p["packages"]):
        return False, "already satisfied"
    tgt = p.get("install") or p["packages"][0]
    rc, o, e = sh(["dnf", "-y", "install", tgt], 900)
    if rc != 0:
        return False, "dnf install %s failed: %s" % (tgt, (e or o)[:200])
    _pkg_cache_invalidate()
    _unit_db_invalidate()
    return True, "installed " + tgt


@check("svc_disabled")
def c_svc_disabled(ctx, p):
    units = p.get("units") or []
    pkgs = p.get("packages") or []
    if not units and not pkgs:
        # A rule with no unit/package targets cannot be evaluated honestly.
        # Report it as an error instead of a silent pass (which would inflate
        # the score for catalogs with incomplete data).
        return "error", "rule has no units/packages configured (incomplete catalog)"
    if pkgs and not any(pkg_installed(x) for x in pkgs):
        return "pass", "provider package not installed (%s)" % ", ".join(pkgs)
    bad, seen = [], []
    for u in units:
        if not unit_exists(u):
            continue
        seen.append(u)
        en, ac = _unit_state(u)
        if en in ("enabled", "enabled-runtime", "static", "indirect", "alias"):
            if en not in ("static", "indirect"):
                bad.append("%s is %s" % (u, en))
        if ac == "active":
            bad.append("%s is active" % u)
    if not seen:
        return "pass", "unit(s) not present on this system"
    if bad:
        return "fail", "; ".join(sorted(set(bad)))
    return "pass", "%s disabled and stopped" % ", ".join(seen)


@fix("svc_disabled")
def f_svc_disabled(ctx, p):
    units = [u for u in (p.get("units") or []) if unit_exists(u)]
    pkgs = p.get("packages") or []
    if pkgs and not any(pkg_installed(x) for x in pkgs):
        return False, "provider package not installed"
    if not units:
        return False, "no matching units present"
    for u in units:
        sh(["systemctl", "stop", u], 120)
        sh(["systemctl", "--now", "disable", u], 120)
        sh(["systemctl", "mask", u], 120)
    _unit_db_invalidate()
    return True, "stopped, disabled and masked: " + ", ".join(units)


@check("svc_enabled")
def c_svc_enabled(ctx, p):
    units = p.get("units") or []
    pkgs = p.get("packages") or []
    if not units and not pkgs:
        return "error", "rule has no units/packages configured (incomplete catalog)"
    missing_pkg = [x for x in pkgs if not pkg_installed(x)]
    if pkgs and missing_pkg == pkgs:
        return "fail", "required package(s) not installed: " + ", ".join(pkgs)
    bad, seen = [], []
    for u in units:
        if not unit_exists(u):
            bad.append("%s not present" % u)
            continue
        seen.append(u)
        en, ac = _unit_state(u)
        if en not in ("enabled", "enabled-runtime", "static", "indirect"):
            bad.append("%s is %s" % (u, en or "disabled"))
        if ac != "active":
            bad.append("%s is %s" % (u, ac or "inactive"))
    if bad:
        return "fail", "; ".join(sorted(set(bad)))
    return "pass", "%s enabled and running" % ", ".join(seen)


def _install_pkgs(ctx, pkgs, timeout=900):
    """Platform-aware package install (dnf / apt-get / zypper)."""
    if have("dnf"):
        cmd = ["dnf", "-y", "install"] + pkgs
    elif have("apt-get"):
        cmd = ["apt-get", "-y", "install"] + pkgs
    elif have("zypper"):
        cmd = ["zypper", "--non-interactive", "install"] + pkgs
    else:
        return False, "no supported package manager found"
    rc, o, e = sh(cmd, timeout)
    if rc != 0:
        return False, (e or o)[:200]
    _pkg_cache_invalidate()
    _unit_db_invalidate()
    return True, None


def _bootstrap_journal_upload(ctx):
    """CIS 6.2.1.2.3 — journal-upload cannot stay active without an HTTP
    endpoint, so run systemd-journal-remote as a LOOPBACK receiver on
    127.0.0.1:19532 and point journal-upload at it (self -> self).

    This avoids needing an external log server while making the service
    genuinely active, and leaves a local archived copy of the journal in
    /var/log/journal/remote/.  Pitfalls handled:
      1. journal-upload.conf syntax differs by systemd version:
         URL= (>= 245 / RHEL9) vs UploadServer= (< 245 / RHEL8).
      2. the remote archive grows unbounded — a logrotate rule caps it.
      3. no upload loop: remote stores into /var/log/journal/remote,
         which journal-upload never reads.
    """
    missing = [p for p in ("systemd-journal-remote",) if not pkg_installed(p)]
    if missing:
        ok, err = _install_pkgs(ctx, missing)
        if not ok:
            ctx.add_note("journal-upload: cannot install %s: %s"
                         % (", ".join(missing), err))
            return False, "cannot install systemd-journal-remote: %s" % err
    # 1. Loopback receiver — drop-in overrides on the stock units.
    write_file(ctx,
               "/etc/systemd/system/systemd-journal-remote.socket.d/ciscvm.conf",
               "[Socket]\nListenStream=\nListenStream=127.0.0.1:19532\n", 0o644)
    rem = out("command -v systemd-journal-remote 2>/dev/null || "
              "echo /usr/lib/systemd/systemd-journal-remote", 20).strip()
    write_file(ctx,
               "/etc/systemd/system/systemd-journal-remote.service.d/ciscvm.conf",
               "[Service]\nExecStart=\nExecStart=%s --listen-http=127.0.0.1:19532 "
               "--output=/var/log/journal/remote/ --split-mode=host\n" % rem, 0o644)
    sh(["systemctl", "daemon-reload"], 30)
    sh(["systemctl", "enable", "--now", "systemd-journal-remote.socket"], 120)
    sh(["systemctl", "enable", "--now", "systemd-journal-remote.service"], 120)
    # 2. journal-upload target — version-aware syntax.
    ver = as_int((out("systemd --version 2>/dev/null | head -1 | "
                      "awk '{print $2}'", 20) or "").strip()) or 0
    if ver >= 245:
        upload_cfg = "[Upload]\nURL=http://127.0.0.1:19532\n"
    else:
        upload_cfg = "[Upload]\nUploadServer=127.0.0.1:19532\n"
    write_file(ctx, "/etc/systemd/journal-upload.conf", upload_cfg, 0o600)
    # 3. Cap the archived-copy growth (journald does NOT rotate
    #    /var/log/journal/remote — this is on us).
    write_file(ctx, "/etc/logrotate.d/ciscvm-journal-remote",
               "/var/log/journal/remote/*.journal {\n"
               "    daily\n    rotate 7\n    maxsize 100M\n    compress\n"
               "    missingok\n    notifempty\n"
               "    postrotate\n"
               "        systemctl restart systemd-journal-remote.service "
               "2>/dev/null || true\n"
               "    endscript\n}\n", 0o644)
    ctx.defer_restart("systemd-journal-upload")
    return True, None


@fix("svc_enabled")
def f_svc_enabled(ctx, p):
    pkgs = p.get("packages") or []
    missing = [x for x in pkgs if not pkg_installed(x)]
    if missing:
        ok, err = _install_pkgs(ctx, missing)
        if not ok:
            return False, "cannot install %s: %s" % (", ".join(missing), err)
    # CIS 6.2.1.2.3 special case: journal-upload needs a receiver to be
    # active — bootstrap the loopback self-upload first.
    if any("systemd-journal-upload.service" == u for u in (p.get("units") or [])):
        ok, err = _bootstrap_journal_upload(ctx)
        if not ok:
            return False, "journal-upload bootstrap failed: %s" % err
    acts = []
    for u in p.get("units") or []:
        if u == "aidecheck.timer" and not unit_exists("aidecheck.timer"):
            _create_aidecheck_units(ctx)
        if not unit_exists(u):
            continue
        sh(["systemctl", "unmask", u], 60)
        sh(["systemctl", "--now", "enable", u], 180)
        acts.append(u)
    if not acts:
        return False, "no matching units present"
    _unit_db_invalidate()
    return True, "enabled and started: " + ", ".join(acts)


@check("dnf_flag")
def c_dnf_flag(ctx, p):
    key, want = p["key"], str(p["value"])
    files = ["/etc/dnf/dnf.conf", "/etc/yum.conf"]
    repos = sorted(globmod.glob("/etc/yum.repos.d/*.repo"))
    bad = []
    vals = conf_values(files, key, (r"\s*=\s*",))
    if not vals:
        bad.append("%s not set in dnf.conf" % key)
    elif vals[-1][1] != want:
        bad.append("dnf.conf %s=%s (expected %s)" % (key, vals[-1][1], want))
    for rp in repos:
        rv = conf_values([rp], key, (r"\s*=\s*",))
        for _, v in rv:
            if v != want:
                bad.append("%s: %s=%s" % (os.path.basename(rp), key, v))
    if bad:
        return "fail", "; ".join(bad[:6])
    return "pass", "%s=%s in dnf.conf and all repos" % (key, want)


@fix("dnf_flag")
def f_dnf_flag(ctx, p):
    key, want = p["key"], str(p["value"])
    if exists("/etc/dnf/dnf.conf"):
        set_kv_in_file(ctx, "/etc/dnf/dnf.conf", key, want, sep="=")
    for rp in sorted(globmod.glob("/etc/yum.repos.d/*.repo")):
        backup(ctx, rp)
        lines = readlines(rp)
        chg = False
        res = []
        for ln in lines:
            m = re.match(r"^\s*" + re.escape(key) + r"\s*=\s*(.*)$", ln, re.I)
            if m and m.group(1).strip() != want:
                res.append("%s=%s" % (key, want))
                chg = True
            else:
                res.append(ln)
        if chg:
            with open(rp, "w", encoding="utf-8") as fh:
                fh.write("\n".join(res).rstrip("\n") + "\n")
            ctx.add_changed_file(rp)
    return True, "set %s=%s in dnf.conf and repo files" % (key, want)


BANNER_BAD = re.compile(r"(\\v|\\r|\\m|\\s|\$\(uname|\bTencentOS\b|\bCentOS\b|"
                        r"\bRed\s*Hat\b|\bFedora\b)", re.I)

DEFAULT_BANNER = (
    "Authorized uses only. All activity may be monitored and reported.\n")


@check("banner")
def c_banner(ctx, p):
    path = p["path"]
    txt = read(path)
    if txt is None:
        return "fail", "%s does not exist" % path
    if not txt.strip():
        return "pass", "%s is empty" % path
    m = BANNER_BAD.search(txt)
    if m:
        return "fail", "%s contains OS/escape reference: %r" % (path, m.group(0))
    return "pass", "%s contains no OS or escape references" % path


@fix("banner")
def f_banner(ctx, p):
    write_file(ctx, p["path"], DEFAULT_BANNER, 0o644)
    sh(["chown", "root:root", p["path"]])
    return True, "replaced %s with a neutral legal banner" % p["path"]


def _dconf_sources(ctx):
    return ctx.cached("dconf_files",
                      lambda: sorted(globmod.glob("/etc/dconf/db/*.d/*")))


@check("gdm_dconf")
def c_gdm_dconf(ctx, p):
    # Only applicable when GDM is actually present, not when a
    # stray /etc/dconf/db directory exists (dconf may be installed
    # as a dependency of other packages on a server image).
    if not (pkg_installed("gdm") or exists("/etc/gdm/custom.conf")):
        return "notapplicable", "GDM is not installed"
    wanted = [(p["dpath"], p["key"], str(p["value"]))]
    for ex in p.get("extra") or []:
        wanted.append((p["dpath"], ex["key"], str(ex["value"])))
    files = [f for f in _dconf_sources(ctx) if os.path.isfile(f)]
    bad = []
    for dpath, key, val in wanted:
        hit = False
        for f in files:
            sec = None
            for ln in readlines(f):
                s = ln.strip()
                if s.startswith("[") and s.endswith("]"):
                    sec = s[1:-1].strip("/")
                    continue
                if sec == dpath.strip("/"):
                    m = re.match(r"^" + re.escape(key) + r"\s*=\s*(.*)$", s)
                    if m and m.group(1).strip().strip("'\"") == val:
                        hit = True
        if not hit:
            bad.append("%s/%s != %s" % (dpath, key, val))
    if bad:
        return "fail", "; ".join(bad)
    return "pass", "dconf keys set: " + ", ".join(k for _, k, _ in wanted)


@fix("gdm_dconf")
def f_gdm_dconf(ctx, p):
    if not (pkg_installed("gdm") or exists("/etc/gdm/custom.conf")):
        return False, "GDM is not installed"
    db = "gdm" if "login-screen" in p["dpath"] else "local"
    path = "/etc/dconf/db/%s.d/00-cis-hardening" % db
    body = ["[%s]" % p["dpath"].strip("/"),
            "%s=%s" % (p["key"], p["value"])]
    for ex in p.get("extra") or []:
        body.append("%s=%s" % (ex["key"], ex["value"]))
    # merge with any existing CIS-managed content
    with ctx.file_lock(path):
        old = read(path) or ""
        sec = "\n".join(body)
        if sec not in old:
            old = (old.rstrip("\n") + "\n\n" + sec + "\n").lstrip("\n")
        write_file(ctx, path, old)
    # lock the keys
    lockdir = "/etc/dconf/db/%s.d/locks" % db
    lock = os.path.join(lockdir, "00-cis-hardening")
    keys = ["/%s/%s" % (p["dpath"].strip("/"), p["key"])]
    for ex in p.get("extra") or []:
        keys.append("/%s/%s" % (p["dpath"].strip("/"), ex["key"]))
    with ctx.file_lock(lock):
        oldlock = read(lock) or ""
        for k in keys:
            if k not in oldlock:
                oldlock = oldlock.rstrip("\n") + "\n" + k + "\n"
        write_file(ctx, lock, oldlock.lstrip("\n"))
    # ensure profile exists for gdm db
    if db == "gdm" and not exists("/etc/dconf/profile/gdm"):
        write_file(ctx, "/etc/dconf/profile/gdm",
                   "user-db:user\nsystem-db:gdm\n"
                   "file-db:/usr/share/gdm/greeter-dconf-defaults\n")
    with ctx.file_lock("__cmd__:dconf"):
        sh(["dconf", "update"], 120)
    ctx.invalidate("dconf_files")
    return True, "wrote %s and ran dconf update" % path


@check("gdm_conf")
def c_gdm_conf(ctx, p):
    path = "/etc/gdm/custom.conf"
    if not exists(path):
        return "notapplicable", "GDM not installed"
    sec, want = p["section"], str(p["value"]).lower()
    cur = None
    inside = False
    for ln in readlines(path):
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            inside = s[1:-1] == sec
            continue
        if inside:
            m = re.match(r"^\s*" + re.escape(p["key"]) + r"\s*=\s*(\S+)", s, re.I)
            if m:
                cur = m.group(1).lower()
    if cur == want:
        return "pass", "[%s] %s=%s" % (sec, p["key"], want)
    return "fail", "[%s] %s=%s (expected %s)" % (sec, p["key"], cur, want)


@fix("gdm_conf")
def f_gdm_conf(ctx, p):
    path = "/etc/gdm/custom.conf"
    if not exists(path):
        return False, "GDM not installed"
    backup(ctx, path)
    lines = readlines(path)
    res, inside, done = [], False, False
    for ln in lines:
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            if inside and not done:
                res.append("%s=%s" % (p["key"], p["value"]))
                done = True
            inside = s[1:-1] == p["section"]
            res.append(ln)
            continue
        if inside and re.match(r"^\s*#?\s*" + re.escape(p["key"]) + r"\s*=", s, re.I):
            if not done:
                res.append("%s=%s" % (p["key"], p["value"]))
                done = True
            continue
        res.append(ln)
    if not done:
        if inside:
            res.append("%s=%s" % (p["key"], p["value"]))
        else:
            res.append("[%s]" % p["section"])
            res.append("%s=%s" % (p["key"], p["value"]))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(res).rstrip("\n") + "\n")
    ctx.add_changed_file(path)
    return True, "set [%s] %s=%s in %s" % (p["section"], p["key"], p["value"], path)


@check("xdmcp")
def c_xdmcp(ctx, p):
    hits = []
    for path in ["/etc/gdm/custom.conf"] + globmod.glob("/etc/gdm/*.conf"):
        if not exists(path):
            continue
        inside = False
        for ln in readlines(path):
            s = ln.strip()
            if s.startswith("[") and s.endswith("]"):
                inside = s[1:-1].lower() == "xdmcp"
                continue
            if inside and re.match(r"^\s*Enable\s*=\s*true", s, re.I):
                hits.append(path)
    if hits:
        return "fail", "XDMCP enabled in " + ", ".join(sorted(set(hits)))
    return "pass", "XDMCP is not enabled"


@fix("xdmcp")
def f_xdmcp(ctx, p):
    n = 0
    for path in set(["/etc/gdm/custom.conf"] + globmod.glob("/etc/gdm/*.conf")):
        if exists(path):
            n += comment_out(ctx, path, r"^\s*Enable\s*=\s*true")
    if not n:
        return False, "nothing to change"
    return True, "commented out %d XDMCP Enable line(s)" % n


@check("wireless")
def c_wireless(ctx, p):
    if not os.path.isdir("/sys/class/net"):
        return "pass", "no network class directory"
    wifi = [d for d in os.listdir("/sys/class/net")
            if os.path.isdir("/sys/class/net/%s/wireless" % d)
            or os.path.exists("/sys/class/net/%s/phy80211" % d)]
    if not wifi:
        return "notapplicable", "no wireless interfaces present"
    if have("nmcli"):
        rc, o, _ = sh(["nmcli", "radio", "all"])
        if rc == 0 and "enabled" not in o.lower():
            return "pass", "wireless radios disabled (nmcli: %s)" % o.replace("\n", " ")
    return "fail", "wireless interface(s) present and enabled: " + ", ".join(wifi)


@fix("wireless")
def f_wireless(ctx, p):
    if have("nmcli"):
        sh(["nmcli", "radio", "all", "off"], 60)
    mods = set()
    for d in os.listdir("/sys/class/net"):
        link = "/sys/class/net/%s/device/driver/module" % d
        if os.path.isdir("/sys/class/net/%s/wireless" % d) and os.path.islink(link):
            mods.add(os.path.basename(os.path.realpath(link)))
    for m in mods:
        write_file(ctx, "/etc/modprobe.d/cis-%s.conf" % m,
                   "install %s /bin/false\nblacklist %s\n" % (m, m))
        sh(["modprobe", "-r", m])
    return True, "radios off; blacklisted driver(s): %s" % (", ".join(sorted(mods)) or "none")


@check("mta_local")
def c_mta_local(ctx, p):
    if not (pkg_installed("postfix") or exists("/etc/postfix/main.cf")):
        listening = out("ss -plntu 2>/dev/null | grep -E ':25\\s' || true", 30)
        if listening:
            return "fail", "something is listening on port 25: %s" % listening.splitlines()[0]
        return "pass", "no MTA installed and nothing listening on :25"
    vals = conf_values(["/etc/postfix/main.cf"], "inet_interfaces", (r"\s*=\s*",))
    cur = vals[-1][1] if vals else "(unset)"
    if cur.lower() in ("loopback-only", "localhost", "127.0.0.1", "127.0.0.1, ::1"):
        return "pass", "postfix inet_interfaces = %s" % cur
    listening = out("ss -plntu 2>/dev/null | grep -E ':25\\s' | "
                    "grep -Ev '127\\.0\\.0\\.1|\\[::1\\]' || true", 30)
    if not listening and vals:
        return "pass", "inet_interfaces=%s but only loopback is bound" % cur
    return "fail", "postfix inet_interfaces = %s (expected loopback-only)" % cur


@fix("mta_local")
def f_mta_local(ctx, p):
    if not exists("/etc/postfix/main.cf"):
        return False, "postfix not installed"
    set_kv_in_file(ctx, "/etc/postfix/main.cf", "inet_interfaces",
                   "loopback-only", sep=" = ")
    ctx.defer_restart("postfix")
    return True, "set inet_interfaces = loopback-only"


@check("chrony_user")
def c_chrony_user(ctx, p):
    if not pkg_installed("chrony"):
        return "notapplicable", "chrony is not installed"
    running = out("ps -eo user:32,comm 2>/dev/null | awk '$2==\"chronyd\"{print $1}' | "
                  "sort -u", 30)
    if running and running.strip() != "chrony":
        return "fail", "chronyd running as %s (expected chrony)" % running.replace("\n", ",")
    files = ["/etc/sysconfig/chronyd"]
    vals = conf_values(files, "OPTIONS", (r"\s*=\s*",))
    txt = vals[-1][1] if vals else ""
    if "-u chrony" not in txt and not running:
        return "fail", "OPTIONS in /etc/sysconfig/chronyd does not contain -u chrony"
    return "pass", "chronyd runs as the chrony user"


@fix("chrony_user")
def f_chrony_user(ctx, p):
    if not pkg_installed("chrony"):
        return False, "chrony is not installed"
    set_kv_in_file(ctx, "/etc/sysconfig/chronyd", "OPTIONS",
                   '"-F 2 -u chrony"', sep="=")
    ctx.defer_restart("chronyd")
    return True, "forced -u chrony in /etc/sysconfig/chronyd"


@check("shells_nologin")
def c_shells_nologin(ctx, p):
    bad = [ln.strip() for ln in readlines("/etc/shells")
           if "nologin" in ln and not ln.strip().startswith("#")]
    if bad:
        return "fail", "/etc/shells lists: " + ", ".join(bad)
    return "pass", "/etc/shells does not reference nologin"


@fix("shells_nologin")
def f_shells_nologin(ctx, p):
    n = comment_out(ctx, "/etc/shells", r"nologin")
    if not n:
        return False, "nothing to change"
    return True, "commented out %d nologin entry/entries in /etc/shells" % n


RSYSLOG_FILES = ["/etc/rsyslog.conf", "/etc/rsyslog.d/*.conf"]


@check("rsyslog_filecreatemode")
def c_rsyslog_filecreatemode(ctx, p):
    if not pkg_installed("rsyslog"):
        return "notapplicable", "rsyslog is not installed"
    want = int(p["mode"], 8)
    vals = conf_values(RSYSLOG_FILES, "FileCreateMode", (r"\s+",))
    if not vals:
        return "fail", "$FileCreateMode is not configured"
    bad = [(f, v) for f, v in vals if not mode_ok(int(v.strip(), 8), want)]
    if bad:
        return "fail", "; ".join("%s: %s" % (f, v) for f, v in bad)
    return "pass", "$FileCreateMode %s" % vals[-1][1]


@fix("rsyslog_filecreatemode")
def f_rsyslog_filecreatemode(ctx, p):
    if not pkg_installed("rsyslog"):
        return False, "rsyslog is not installed"
    for f, v in conf_values(RSYSLOG_FILES, "FileCreateMode", (r"\s+",)):
        comment_out(ctx, f, r"^\s*\$FileCreateMode")
    set_kv_in_file(ctx, "/etc/rsyslog.d/60-cis.conf", "$FileCreateMode",
                   p["mode"], sep=" ")
    ctx.defer_restart("rsyslog")
    return True, "set $FileCreateMode %s in /etc/rsyslog.d/60-cis.conf" % p["mode"]


RSYSLOG_RECV = [
    (r'^\s*\$ModLoad\s+imtcp', "$ModLoad imtcp"),
    (r'^\s*module\(load="?imtcp"?\)', 'module(load="imtcp")'),
    (r'^\s*\$InputTCPServerRun', "$InputTCPServerRun"),
    (r'^\s*input\(type="?imtcp"?', 'input(type="imtcp")'),
]


@check("rsyslog_no_receive")
def c_rsyslog_no_receive(ctx, p):
    if not pkg_installed("rsyslog"):
        return "notapplicable", "rsyslog is not installed"
    hits = []
    for spec in RSYSLOG_FILES:
        paths = sorted(globmod.glob(spec)) if "*" in spec else [spec]
        for path in paths:
            for ln in readlines(path):
                if ln.lstrip().startswith("#"):
                    continue
                for rx, label in RSYSLOG_RECV:
                    if re.match(rx, ln):
                        hits.append("%s: %s" % (os.path.basename(path), label))
    if hits:
        return "fail", "log reception enabled -> " + "; ".join(sorted(set(hits)))
    return "pass", "rsyslog is not configured to receive remote logs"


@fix("rsyslog_no_receive")
def f_rsyslog_no_receive(ctx, p):
    if not pkg_installed("rsyslog"):
        return False, "rsyslog is not installed"
    n = 0
    for spec in RSYSLOG_FILES:
        paths = sorted(globmod.glob(spec)) if "*" in spec else [spec]
        for path in paths:
            for rx, _ in RSYSLOG_RECV:
                n += comment_out(ctx, path, rx)
    if not n:
        return False, "nothing to change"
    ctx.defer_restart("rsyslog")
    return True, "commented out %d imtcp directive(s)" % n

# ==========================================================================
# Generic key/value configuration family
# ==========================================================================

def _kv_targets(p):
    files = list(p.get("files") or [])
    files += list(p.get("globs") or [])
    return files


def _kv_current(p):
    seps = (r"\s*=\s*",) if p.get("sep") == "=" else (r"\s+", r"\s*=\s*")
    vals = conf_values(_kv_targets(p), p["key"], seps)
    return vals


@check("kv_conf")
def c_kv_conf(ctx, p):
    op = p.get("op", "eq")
    key, want = p["key"], str(p.get("value", ""))

    if op == "limits_core":
        hits = []
        for spec in ["/etc/security/limits.conf", "/etc/security/limits.d/*.conf"]:
            for path in sorted(globmod.glob(spec)) if "*" in spec else [spec]:
                for ln in readlines(path):
                    if re.match(r"^\s*\*\s+hard\s+core\s+0\s*$", ln):
                        hits.append(path)
        soft_bad = out("grep -Ers '^\\s*\\*\\s+soft\\s+core\\s+' /etc/security/limits.conf "
                       "/etc/security/limits.d/ 2>/dev/null | grep -v ' 0$' || true", 30)
        if hits and not soft_bad:
            return "pass", "'* hard core 0' set in " + ", ".join(sorted(set(hits)))
        why = [] if hits else ["'* hard core 0' not configured"]
        if soft_bad:
            why.append("non-zero soft core limit: " + soft_bad.splitlines()[0])
        return "fail", "; ".join(why)

    vals = _kv_current(p)
    if not vals:
        return "fail", "%s is not configured in %s" % (
            key, ", ".join(_kv_targets(p)))
    path, cur = vals[-1]
    curc = cur.split("#")[0].strip().strip('"').strip("'")

    if op in ("eq", "set"):
        ok = curc.lower() == want.lower()
    elif op == "present":
        ok = bool(curc)
    elif op == "bool_present":
        ok = curc == "" or curc.lower() in ("1", "true", "yes", "on")
    elif op == "ge":
        n, w = as_int(curc), as_int(want)
        ok = n is not None and w is not None and n >= w
    elif op == "le_pos":
        n, w = as_int(curc), as_int(want)
        ok = n is not None and w is not None and 0 < n <= w
    elif op.startswith("ne:"):
        ok = curc != op[3:]
    elif op.startswith("in:"):
        ok = curc.lower() in [x.strip().lower() for x in op[3:].split(",")]
    elif op == "filemode":
        n = as_int(curc.lstrip("0") or "0", None)
        try:
            ok = mode_ok(int(curc, 8), want)
        except Exception:
            ok = False
    elif op == "umask":
        try:
            ok = (int(curc, 8) & ~int(want, 8)) == 0
        except Exception:
            ok = False
    elif op == "unlock_time":
        n = as_int(curc)
        w = as_int(want, 900)
        ok = n is not None and (n == 0 or n >= w)
    elif op == "tmout":
        # If the file uses bare TMOUT=900 without bash guard,
        # companion lines like "readonly TMOUT" / "export TMOUT"
        # cause "TMOUT: command not found" in non-bash shells.
        if path.endswith(".sh"):
            try:
                with open(path) as fh:
                    content = fh.read()
                if "BASH_VERSION" not in content or "declare -rx TMOUT" not in content:
                    return "fail", (
                        "TMOUT uses broken bare syntax in %s, "
                        "needs declare -rx with bash guard"
                    ) % os.path.basename(path)
            except Exception:
                pass
        n, w = as_int(curc), as_int(want, 900)
        ok = n is not None and 0 < n <= w
    else:
        ok = curc == want

    if ok:
        return "pass", "%s = %s (%s)" % (key, curc, os.path.basename(path))
    return "fail", "%s = %s in %s (expected %s %s)" % (
        key, curc or "(empty)", os.path.basename(path), op, want or "set")


@fix("kv_conf")
def f_kv_conf(ctx, p):
    op = p.get("op", "eq")
    key = p["key"]
    want = str(p.get("value", ""))
    sep = p.get("sep", "=")

    if op == "limits_core":
        write_file(ctx, "/etc/security/limits.d/60-cis-coredump.conf",
                   "# CIS hardening: disable core dumps\n"
                   "* hard core 0\n* soft core 0\n")
        return True, "wrote /etc/security/limits.d/60-cis-coredump.conf"

    if op == "tmout":
        target = (p.get("files") or ["/etc/cis-hardening.conf"])[0]
        # Write with bash guard so non-bash shells (sh, scp) don't
        # choke on bare "readonly TMOUT" / "export TMOUT".
        write_file(ctx, target,
                   "# CIS hardening: idle shell timeout\n"
                   '[ -n "$BASH_VERSION" ] || return 0\n'
                   "declare -rx TMOUT=%s\n" % want)
        return True, "TMOUT=%s enforced via %s" % (want, os.path.basename(target))

    target = (p.get("files") or ["/etc/cis-hardening.conf"])[0]
    # systemd-style drop-in: when the rule's globs cover <main>.d/*.conf,
    # write the drop-in instead of the main file so a reboot (which may
    # restore the distro's packaged main file) cannot revert our setting
    # (e.g. journald.conf -> journald.conf.d/99-cis.conf).
    dropin_glob = os.path.join(target + ".d", "*.conf")
    if dropin_glob in (p.get("globs") or []):
        target = os.path.join(target + ".d", "99-cis.conf")
    if op == "bool_present":
        val = ""
        sepc = ""
    elif op == "present" and not want:
        return False, "value is site-specific; set it manually"
    else:
        val = want
        sepc = " = " if sep == "=" else " "
    # remove conflicting definitions elsewhere first
    for path, _ in _kv_current(p):
        if os.path.abspath(path) != os.path.abspath(target):
            comment_out(ctx, path, r"^\s*\$?" + re.escape(key) + r"\b")
    if op == "bool_present":
        lines = readlines(target) if exists(target) else []
        if not any(re.match(r"^\s*" + re.escape(key) + r"\s*$", x) for x in lines):
            backup(ctx, target)
            os.makedirs(os.path.dirname(target) or "/", exist_ok=True)
            with open(target, "a", encoding="utf-8") as fh:
                fh.write("\n%s\n" % key)
            ctx.add_changed_file(target)
        return True, "ensured flag %s in %s" % (key, target)
    mode = 0o644
    if target.endswith(".sh"):
        mode = 0o644
    set_kv_in_file(ctx, target, key, val, sep=sepc, mode=mode)
    return True, "set %s%s%s in %s" % (key, sepc, val, target)


# ==========================================================================
# SSH
# ==========================================================================

def sshd_effective(ctx):
    def load():
        rc, o, _ = sh(["sshd", "-T"], 60)
        if rc != 0:
            rc, o, _ = sh("sshd -T -C user=root,host=localhost,addr=127.0.0.1", 60)
        if rc != 0:
            return {}
        d = {}
        for ln in o.splitlines():
            if " " in ln:
                k, v = ln.split(" ", 1)
                d.setdefault(k.lower(), []).append(v.strip())
        return d
    return ctx.cached("sshd_T", load)


def _sshd_one(ctx, key):
    d = sshd_effective(ctx)
    v = d.get(key.lower())
    return v[-1] if v else None


def _sshd_compare(cur, op, want):
    if cur is None:
        return False
    if op == "eq":
        return cur.strip().lower() == str(want).strip().lower()
    if op == "le":
        n, w = as_int(cur), as_int(want)
        return n is not None and w is not None and n <= w
    if op == "ge":
        n, w = as_int(cur), as_int(want)
        return n is not None and w is not None and n >= w
    if op == "in":
        return cur.strip().lower() in [x.lower() for x in want]
    if op == "deny_list":
        denied = set(x.strip().lower() for x in str(want).split(",") if x.strip())
        current = set(x.strip().lower() for x in cur.split(",") if x.strip())
        return not (current & denied)
    if op == "maxstartups":
        cur_parts = [as_int(x.strip()) for x in cur.split(":")]
        want_parts = [as_int(x.strip()) for x in str(want).split(":")]
        if None in cur_parts or None in want_parts \
           or len(cur_parts) < 3 or len(want_parts) < 3:
            return False
        return (cur_parts[0] <= want_parts[0]
                and cur_parts[1] <= want_parts[1]
                and cur_parts[2] <= want_parts[2])
    return cur.strip() == str(want)


@check("sshd_param")
def c_sshd_param(ctx, p):
    if not sshd_effective(ctx):
        return "error", "unable to run 'sshd -T' (openssh-server missing?)"
    items = p.get("params") or [{"key": p.get("key"), "op": p.get("op", "eq"),
                                 "value": p.get("value")}]
    bad, good = [], []
    for it in items:
        cur = _sshd_one(ctx, it["key"])
        if _sshd_compare(cur, it.get("op", "eq"), it["value"]):
            good.append("%s %s" % (it["key"], cur))
        else:
            bad.append("%s = %s (expected %s %s)" % (
                it["key"], cur if cur is not None else "(unset)",
                it.get("op", "eq"), it["value"]))
    if bad:
        return "fail", "; ".join(bad)
    return "pass", "; ".join(good)


SSHD_DROPIN = "/etc/ssh/sshd_config.d/60-cis-hardening.conf"


def _sshd_write(ctx, pairs):
    """Write directives into a drop-in (TOS4/RHEL9) or the main file (TOS3)."""
    # Snapshot both targets so a failed `sshd -t` can be rolled back — an
    # image whose sshd config is invalid boots with NO remote access (P0).
    snap_dropin = read(SSHD_DROPIN)
    snap_main = read("/etc/ssh/sshd_config")
    with ctx.file_lock(SSHD_DROPIN):
        supports_dropin = os.path.isdir("/etc/ssh/sshd_config.d") or \
            bool(re.search(r"^\s*Include\s+/etc/ssh/sshd_config\.d/",
                           read("/etc/ssh/sshd_config") or "", re.M | re.I))
        if supports_dropin:
            os.makedirs("/etc/ssh/sshd_config.d", exist_ok=True)
            body = ["# Managed by CIS Ansible hardening"]
            old = {}
            for ln in readlines(SSHD_DROPIN):
                m = re.match(r"^\s*(\w+)\s+(.*)$", ln)
                if m:
                    old[m.group(1).lower()] = (m.group(1), m.group(2))
            for k, v in pairs:
                old[k.lower()] = (k, v)
            for k, v in old.values():
                body.append("%s %s" % (k, v))
            write_file(ctx, SSHD_DROPIN, "\n".join(body) + "\n", 0o600)
            # ensure Include directive exists; comment out conflicting directives
            # so the drop-in (60-cis-hardening.conf) always takes precedence
            main_lines = readlines("/etc/ssh/sshd_config")
            has_include = any(
                re.search(r"^\s*Include\s+/etc/ssh/sshd_config\.d/", ln, re.I)
                for ln in main_lines)
            if not has_include:
                main_lines.insert(0, "Include /etc/ssh/sshd_config.d/*.conf")
            keys_lower = {k.lower() for k, v in pairs}
            commented = False
            for i, ln in enumerate(main_lines):
                m = re.match(r"^\s*(\w+)\s+", ln)
                if m and m.group(1).lower() in keys_lower \
                   and not ln.lstrip().startswith("#"):
                    main_lines[i] = "# " + ln
                    commented = True
            if not has_include or commented:
                backup(ctx, "/etc/ssh/sshd_config")
                write_file(ctx, "/etc/ssh/sshd_config",
                           "\n".join(main_lines).rstrip("\n") + "\n", 0o600)
            tgt = SSHD_DROPIN
        else:
            for k, v in pairs:
                comment_out(ctx, "/etc/ssh/sshd_config", r"^\s*" + re.escape(k) + r"\s")
                set_kv_in_file(ctx, "/etc/ssh/sshd_config", k, v, sep=" ", mode=0o600)
            tgt = "/etc/ssh/sshd_config"
        rc, _, err = sh(["sshd", "-t"], 30)
        if rc != 0:
            # Roll back both files to their pre-write state so the image
            # never ships a config that prevents sshd from starting.
            if snap_dropin is None:
                try:
                    os.unlink(SSHD_DROPIN)
                except OSError:
                    pass
            else:
                atomic_write(SSHD_DROPIN, snap_dropin, mode=0o600)
            if snap_main is not None:
                atomic_write("/etc/ssh/sshd_config", snap_main, mode=0o600)
            return tgt, err
        ctx.defer_restart("sshd")
        ctx.invalidate("sshd_T")
        return tgt, None


@fix("sshd_param")
def f_sshd_param(ctx, p):
    items = p.get("params") or [{"key": p.get("key"), "value": p.get("value")}]
    pairs = []
    for it in items:
        if it.get("op") == "deny_list":
            denied = set(x.strip().lower()
                         for x in str(it["value"]).split(",") if x.strip())
            cur_val = _sshd_one(ctx, it["key"])
            if cur_val:
                cur_set = [x.strip() for x in cur_val.split(",") if x.strip()]
                allowed = [x for x in cur_set if x.lower() not in denied]
                pairs.append((it["key"], ",".join(allowed)))
            else:
                pairs.append((it["key"], ""))
        else:
            pairs.append((it["key"], str(it["value"])))
    # Writing an empty value (`Key ""`) makes `sshd -t` fail and would
    # brick SSH on the image; omit the key and fail honestly instead.
    skipped = [k for k, v in pairs if v == ""]
    pairs = [(k, v) for k, v in pairs if v != ""]
    if skipped:
        ctx.add_note("sshd_param: omitted empty-value keys %s" % ", ".join(skipped))
    if not pairs:
        return False, ("deny_list would empty every value for %s; "
                       "refusing to write an invalid sshd config" % ", ".join(skipped))
    tgt, err = _sshd_write(ctx, pairs)
    if err:
        return False, "sshd config test failed: %s" % err[:200]
    return True, "set %s in %s" % (
        ", ".join("%s %s" % kv for kv in pairs), tgt)


@check("sshd_idle")
def c_sshd_idle(ctx, p):
    if not sshd_effective(ctx):
        return "error", "unable to run 'sshd -T'"
    iv = as_int(_sshd_one(ctx, "clientaliveinterval"))
    cm = as_int(_sshd_one(ctx, "clientalivecountmax"))
    bad = []
    if iv is None or not (0 < iv <= p.get("interval_max", 900)):
        bad.append("ClientAliveInterval=%s (expected 1..%d)" % (iv, p.get("interval_max", 900)))
    if cm is None or cm > p.get("countmax", 0):
        bad.append("ClientAliveCountMax=%s (expected <=%d)" % (cm, p.get("countmax", 0)))
    if bad:
        return "fail", "; ".join(bad)
    return "pass", "ClientAliveInterval=%s ClientAliveCountMax=%s" % (iv, cm)


@fix("sshd_idle")
def f_sshd_idle(ctx, p):
    pairs = [("ClientAliveInterval", str(p.get("interval_max", 900))),
             ("ClientAliveCountMax", str(p.get("countmax", 0)))]
    tgt, err = _sshd_write(ctx, pairs)
    if err:
        return False, "sshd config test failed: %s" % err[:200]
    return True, "set ClientAlive* in %s" % tgt


@check("sshd_access")
def c_sshd_access(ctx, p):
    d = sshd_effective(ctx)
    if not d:
        return "error", "unable to run 'sshd -T'"
    got = {k: d[k][-1] for k in ("allowusers", "allowgroups", "denyusers", "denygroups")
           if d.get(k) and d[k][-1].strip()}
    if got:
        return "pass", "; ".join("%s %s" % (k, v) for k, v in got.items())
    return "manual", ("no AllowUsers/AllowGroups/DenyUsers/DenyGroups configured - "
                      "the allowed user list is site-specific and must be set manually")


@check("sshd_crypto_policy")
def c_sshd_crypto_policy(ctx, p):
    path = "/etc/sysconfig/sshd"
    if not exists(path):
        return "pass", "%s does not exist; system-wide crypto policy applies" % path
    active = [ln.strip() for ln in readlines(path)
              if re.match(r"^\s*CRYPTO_POLICY\s*=", ln)]
    if active:
        return "fail", "system-wide crypto policy overridden: " + active[-1]
    return "pass", "CRYPTO_POLICY is not set; system-wide policy applies"


@fix("sshd_crypto_policy")
def f_sshd_crypto_policy(ctx, p):
    n = comment_out(ctx, "/etc/sysconfig/sshd", r"^\s*CRYPTO_POLICY\s*=")
    if not n:
        return False, "nothing to change"
    ctx.defer_restart("sshd")
    return True, "commented out CRYPTO_POLICY in /etc/sysconfig/sshd"


@check("sshd_config_perm")
def c_sshd_config_perm(ctx, p):
    targets = ["/etc/ssh/sshd_config"] + sorted(globmod.glob("/etc/ssh/sshd_config.d/*.conf"))
    bad = []
    for f in targets:
        if not exists(f):
            continue
        u, g, st = owner_of(f)
        if not mode_ok(st.st_mode, "600") or u != "root" or g != "root":
            bad.append("%s (%s %s:%s)" % (f, fmt_mode(st.st_mode), u, g))
    if bad:
        return "fail", "non-compliant: " + ", ".join(bad)
    return "pass", "%d sshd config file(s) are 0600 root:root" % len(targets)


@fix("sshd_config_perm")
def f_sshd_config_perm(ctx, p):
    targets = ["/etc/ssh/sshd_config"] + sorted(globmod.glob("/etc/ssh/sshd_config.d/*.conf"))
    n = 0
    for f in targets:
        if exists(f):
            sh(["chown", "root:root", f])
            os.chmod(f, 0o600)
            ctx.add_changed_file(f)
            n += 1
    return True, "set 0600 root:root on %d file(s)" % n


# ==========================================================================
# PAM / authselect
# ==========================================================================

PAM_FILES = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]


def _pam_paths(ctx):
    def load():
        paths = [f for f in PAM_FILES if exists(f)]
        rc, o, _ = sh(["authselect", "current"], 30)
        if rc == 0:
            m = re.search(r"custom/(\S+)", o)
            if m:
                base = "/etc/authselect/custom/%s" % m.group(1)
                for n in ("system-auth", "password-auth"):
                    if exists(os.path.join(base, n)):
                        paths.append(os.path.join(base, n))
        return paths
    return ctx.cached("pam_paths", load)


@check("pam_module")
def c_pam_module(ctx, p):
    mod = p["module"]
    hits = []
    for f in _pam_paths(ctx):
        for ln in readlines(f):
            if ln.lstrip().startswith("#"):
                continue
            if re.search(r"\b" + re.escape(mod) + r"\b", ln):
                hits.append(os.path.basename(f))
                break
    if hits:
        return "pass", "%s enabled in %s" % (mod, ", ".join(sorted(set(hits))))
    return "fail", "%s is not present in the PAM stack" % mod


@check("pam_arg")
def c_pam_arg(ctx, p):
    mod, arg, mode = p["module"], p["arg"], p.get("mode", "present")
    lines = []
    for f in _pam_paths(ctx):
        for ln in readlines(f):
            if ln.lstrip().startswith("#"):
                continue
            if re.search(r"\b" + re.escape(mod) + r"\b", ln):
                lines.append((f, ln.strip()))
    if not lines:
        if mode == "absent":
            return "pass", "%s is not used" % mod
        return "fail", "%s is not present in the PAM stack" % mod

    def argval(ln):
        m = re.search(r"\b" + re.escape(arg) + r"\s*=\s*(\S+)", ln)
        return m.group(1) if m else None

    def hasflag(ln):
        return re.search(r"(^|\s)" + re.escape(arg) + r"(\s|=|$)", ln) is not None

    if mode == "absent":
        bad = ["%s: %s" % (os.path.basename(f), ln) for f, ln in lines if hasflag(ln)]
        if bad:
            return "fail", "%s present -> %s" % (arg, "; ".join(bad[:3]))
        return "pass", "%s is not set on %s" % (arg, mod)
    if mode in ("present", "flag"):
        ok = [f for f, ln in lines if hasflag(ln)]
        if ok:
            return "pass", "%s %s set in %s" % (
                mod, arg, ", ".join(sorted({os.path.basename(x) for x in ok})))
        return "fail", "%s does not set %s" % (mod, arg)
    if mode == "present_any":
        ok = [f for f, ln in lines if hasflag(ln)]
        if ok:
            return "pass", "%s %s present" % (mod, arg)
        return "fail", "%s does not set %s in any PAM file" % (mod, arg)
    if mode.startswith("ge:"):
        want = as_int(mode[3:], 0)
        vals = [as_int(argval(ln)) for _, ln in lines]
        vals = [v for v in vals if v is not None]
        if vals and min(vals) >= want:
            return "pass", "%s %s=%s (>= %s)" % (mod, arg, min(vals), want)
        return "fail", "%s %s=%s (expected >= %s)" % (
            mod, arg, vals[0] if vals else "(unset)", want)
    return "fail", "unsupported mode %s" % mode


@check("authselect_profile")
def c_authselect_profile(ctx, p):
    if not have("authselect"):
        return "notapplicable", "authselect is not installed"
    rc, o, _ = sh(["authselect", "current"], 30)
    if rc != 0:
        return "fail", "no authselect profile is selected"
    if "custom/" in o:
        return "pass", o.splitlines()[0].strip()
    return "fail", "a custom authselect profile is required, found: %s" % \
        o.splitlines()[0].strip()


@check("authselect_feature")
def c_authselect_feature(ctx, p):
    if not have("authselect"):
        return "notapplicable", "authselect is not installed"
    rc, o, _ = sh(["authselect", "current"], 30)
    if rc != 0:
        return "fail", "no authselect profile is selected"
    if p["feature"] in o:
        return "pass", "profile includes %s" % p["feature"]
    return "fail", "profile does not include %s" % p["feature"]


@fix("authselect_feature")
def f_authselect_feature(ctx, p):
    if not have("authselect"):
        return False, "authselect is not installed"
    rc, o, e = sh(["authselect", "enable-feature", p["feature"]], 60)
    if rc != 0:
        return False, "authselect enable-feature failed: %s" % (e or o)[:200]
    sh(["authselect", "apply-changes"], 60)
    ctx.invalidate("pam_paths")
    return True, "enabled authselect feature %s" % p["feature"]


# ==========================================================================
# sudo
# ==========================================================================

def _sudoers_lines(ctx):
    def load():
        res = []
        for spec in ["/etc/sudoers", "/etc/sudoers.d/*"]:
            for path in sorted(globmod.glob(spec)) if "*" in spec else [spec]:
                if not os.path.isfile(path):
                    continue
                for ln in readlines(path):
                    s = ln.strip()
                    if s and not s.startswith("#"):
                        res.append((path, s))
        return res
    return ctx.cached("sudoers", load)


@check("sudo_defaults")
def c_sudo_defaults(ctx, p):
    key, op, want = p["key"], p.get("op", "flag"), p.get("value")
    lines = [(f, l) for f, l in _sudoers_lines(ctx) if l.startswith("Defaults")]
    if op == "flag":
        hit = [f for f, l in lines
               if re.search(r"(^|[,\s])!?" + re.escape(key) + r"(\s|,|$)", l)
               and not re.search(r"(^|[,\s])!" + re.escape(key) + r"(\s|,|$)", l)]
        if hit:
            return "pass", "Defaults %s is set" % key
        return "fail", "Defaults %s is not set" % key
    if op == "absent_tag":
        hit = ["%s: %s" % (os.path.basename(f), l) for f, l in _sudoers_lines(ctx)
               if re.search(re.escape(key), l)]
        if hit:
            return "fail", "%s found -> %s" % (key, "; ".join(hit[:3]))
        return "pass", "%s is not used in sudoers" % key
    vals = []
    for f, l in lines:
        m = re.search(re.escape(key) + r"\s*=\s*(\"?)([^\",]+)\1", l)
        if m:
            vals.append((f, m.group(2).strip()))
    if op == "kv":
        if any(v == str(want) for _, v in vals):
            return "pass", "%s=%s" % (key, want)
        return "fail", "%s=%s (expected %s)" % (
            key, vals[-1][1] if vals else "(unset)", want)
    if op == "kv_le":
        nums = [as_int(v) for _, v in vals]
        nums = [n for n in nums if n is not None]
        if nums and max(nums) <= as_int(want, 0):
            return "pass", "%s=%s (<= %s)" % (key, max(nums), want)
        return "fail", "%s=%s (expected <= %s)" % (
            key, nums[0] if nums else "(unset)", want)
    return "fail", "unsupported op %s" % op


SUDO_DROPIN = "/etc/sudoers.d/60-cis-hardening"


def _sudo_append(ctx, line):
    with ctx.file_lock(SUDO_DROPIN):
        old = read(SUDO_DROPIN) or "# Managed by CIS Ansible hardening\n"
        key = line.split("=")[0].strip()
        keep = [l for l in old.splitlines()
                if not l.strip().startswith(key.split()[0] + " " + key.split()[-1])
                and l.strip() != line]
        keep = [l for l in keep if key not in l or l.startswith("#")]
        keep.append(line)
        content = "\n".join(keep).rstrip("\n") + "\n"
        directory = os.path.dirname(SUDO_DROPIN) or "/etc"
        fd, tmp = tempfile.mkstemp(
            dir=directory,
            prefix=".sudoers-cis-tmp-",
            suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o440)
            rc, o, e = sh(["visudo", "-cqf", tmp], 30)
            if rc != 0:
                os.unlink(tmp)
                return False, "visudo validation failed: %s" % (e or o)[:200]
            backup(ctx, SUDO_DROPIN)
            os.replace(tmp, SUDO_DROPIN)
            os.chmod(SUDO_DROPIN, 0o440)
            ctx.add_changed_file(SUDO_DROPIN)
            ctx.invalidate("sudoers")
            return True, "added %r to %s" % (line, SUDO_DROPIN)
        except Exception as exc:
            try:
                os.unlink(tmp)
            except Exception:
                pass
            return False, "_sudo_append failed: %s" % exc


@fix("sudo_defaults")
def f_sudo_defaults(ctx, p):
    key, op, want = p["key"], p.get("op", "flag"), p.get("value")
    if op == "absent_tag":
        n = 0
        for spec in ["/etc/sudoers", "/etc/sudoers.d/*"]:
            for path in sorted(globmod.glob(spec)) if "*" in spec else [spec]:
                if os.path.isfile(path):
                    n += comment_out(ctx, path, re.escape(key))
        ctx.invalidate("sudoers")
        if not n:
            return False, "nothing to change"
        return True, "commented out %d line(s) containing %s" % (n, key)
    if op == "flag":
        return _sudo_append(ctx, "Defaults %s" % key)
    return _sudo_append(ctx, "Defaults %s=%s" % (key, want))


@check("sudo_timeout")
def c_sudo_timeout(ctx, p):
    mx = p.get("max", 15)
    vals = []
    for f, l in _sudoers_lines(ctx):
        if not l.startswith("Defaults"):
            continue
        m = re.search(r"timestamp_timeout\s*=\s*(-?\d+)", l)
        if m:
            vals.append((f, int(m.group(1))))
    if not vals:
        return "fail", "timestamp_timeout is not configured (default 5 min is ok " \
                       "but CIS requires it to be explicit)"
    bad = [(f, v) for f, v in vals if v < 0 or v > mx]
    if bad:
        return "fail", "; ".join("%s: timestamp_timeout=%s" % (os.path.basename(f), v)
                                 for f, v in bad)
    return "pass", "timestamp_timeout=%s (<= %s)" % (vals[-1][1], mx)


@fix("sudo_timeout")
def f_sudo_timeout(ctx, p):
    return _sudo_append(ctx, "Defaults timestamp_timeout=%d" % p.get("max", 15))


# ==========================================================================
# login.defs / shell defaults / root
# ==========================================================================

@check("login_defs")
def c_login_defs(ctx, p):
    key, op, want = p["key"], p.get("op", "eq"), str(p["value"])
    vals = conf_values(["/etc/login.defs"], key, (r"\s+",))
    if not vals:
        return "fail", "%s is not set in /etc/login.defs" % key
    cur = vals[-1][1].split()[0]
    n, w = as_int(cur), as_int(want)
    ok = {"ge": lambda: n is not None and n >= w,
          "le": lambda: n is not None and n <= w,
          "eq": lambda: cur == want}.get(op, lambda: cur == want)()
    # also verify existing users
    bad_users = []
    if key == "PASS_MIN_DAYS":
        bad_users = out("awk -F: '$2 ~ /^\\$/ {print $1}' /etc/shadow 2>/dev/null | "
                        "while read -r u; do d=$(chage --list \"$u\" 2>/dev/null | "
                        "awk -F: '/Minimum number/{print $2}'); "
                        "[ -n \"$d\" ] && [ \"$d\" -lt %s ] && echo \"$u\"; "
                        "done | head -10" % want, 120).splitlines()
    if ok and not bad_users:
        return "pass", "%s %s" % (key, cur)
    why = [] if ok else ["%s=%s (expected %s %s)" % (key, cur, op, want)]
    if bad_users:
        why.append("non-conforming users: " + ", ".join(bad_users[:5]))
    return "fail", "; ".join(why)


@fix("login_defs")
def f_login_defs(ctx, p):
    key, want = p["key"], str(p["value"])
    set_kv_in_file(ctx, "/etc/login.defs", key, want, sep="\t")
    if key == "PASS_MIN_DAYS":
        sh("awk -F: '$2 ~ /^\\$/ {print $1}' /etc/shadow | "
           "xargs -r -n1 chage --mindays %s" % want, 180)
    return True, "set %s %s in /etc/login.defs" % (key, want)


@check("umask_default")
def c_umask_default(ctx, p):
    want = p.get("umask", "027")
    files = ["/etc/profile", "/etc/bashrc", "/etc/profile.d/*.sh", "/etc/login.defs"]
    found = []
    for spec in files:
        for path in sorted(globmod.glob(spec)) if "*" in spec else [spec]:
            if not os.path.isfile(path):
                continue
            for ln in readlines(path):
                if ln.lstrip().startswith("#"):
                    continue
                m = re.search(r"^\s*(?:UMASK\s+|umask\s+)(\d{3,4})", ln, re.I)
                if m:
                    found.append((path, m.group(1)))
    if not found:
        return "fail", "no umask is configured in /etc/profile*, /etc/bashrc or login.defs"
    bad = []
    for path, v in found:
        try:
            if (int(v, 8) & ~int(want, 8)) != 0:
                bad.append("%s: umask %s" % (os.path.basename(path), v))
        except Exception:
            bad.append("%s: umask %s (unparsable)" % (os.path.basename(path), v))
    if bad:
        return "fail", "too permissive -> " + "; ".join(bad[:4])
    return "pass", "umask %s or more restrictive everywhere" % want


@fix("umask_default")
def f_umask_default(ctx, p):
    want = p.get("umask", "027")
    for spec in ["/etc/profile", "/etc/bashrc", "/etc/profile.d/*.sh"]:
        for path in sorted(globmod.glob(spec)) if "*" in spec else [spec]:
            if os.path.isfile(path) and not path.endswith("60-cis-umask.sh"):
                comment_out(ctx, path, r"^\s*umask\s+\d")
    set_kv_in_file(ctx, "/etc/login.defs", "UMASK", want, sep="\t")
    write_file(ctx, "/etc/profile.d/60-cis-umask.sh",
               "# CIS hardening: default umask\numask %s\n" % want)
    return True, "umask %s enforced via /etc/profile.d/60-cis-umask.sh" % want


@check("shell_timeout")
def c_shell_timeout(ctx, p):
    mx = p.get("max", 900)
    vals = []
    for spec in ["/etc/profile", "/etc/bashrc", "/etc/profile.d/*.sh"]:
        for path in sorted(globmod.glob(spec)) if "*" in spec else [spec]:
            if not os.path.isfile(path):
                continue
            for ln in readlines(path):
                if ln.lstrip().startswith("#"):
                    continue
                m = re.search(r"^\s*(?:(?:readonly|export|declare)\s+(?:-[a-z]+\s+)?)?TMOUT\s*=\s*(\d+)", ln)
                if m:
                    vals.append((path, int(m.group(1))))
    # Ensure 60-cis-tmout.sh uses declare -rx with bash guard.
    # SCP and /bin/sh sessions do NOT have $BASH_VERSION, so bare
    # "TMOUT=900; readonly TMOUT" causes "TMOUT: command not found".
    tmout_path = "/etc/profile.d/60-cis-tmout.sh"
    if os.path.isfile(tmout_path):
        try:
            with open(tmout_path) as fh:
                content = fh.read()
        except Exception as exc:
            return "fail", "TMOUT file unreadable: %s" % exc
        # Must have both the bash guard AND declare -rx
        if "BASH_VERSION" not in content or "declare -rx TMOUT" not in content:
            return "fail", "TMOUT file missing declare -rx or bash guard, will rewrite"
    if not vals:
        return "fail", "TMOUT is not configured"
    bad = [(f, v) for f, v in vals if v == 0 or v > mx]
    if bad:
        return "fail", "; ".join("%s: TMOUT=%s" % (os.path.basename(f), v)
                                 for f, v in bad[:4])
    return "pass", "TMOUT=%s (<= %s)" % (vals[-1][1], mx)


@fix("shell_timeout")
def f_shell_timeout(ctx, p):
    mx = p.get("max", 900)
    for spec in ["/etc/profile", "/etc/bashrc", "/etc/profile.d/*.sh"]:
        for path in sorted(globmod.glob(spec)) if "*" in spec else [spec]:
            if os.path.isfile(path) and not path.endswith("60-cis-tmout.sh"):
                comment_out(ctx, path, r"^\s*(readonly\s+|export\s+)?TMOUT\s*=")
    write_file(ctx, "/etc/profile.d/60-cis-tmout.sh",
               "# CIS hardening: idle shell timeout\n"
               '[ -n "$BASH_VERSION" ] || return 0\n'
               "declare -rx TMOUT=%d\n" % mx)
    return True, "TMOUT=%d enforced via /etc/profile.d/60-cis-tmout.sh" % mx


@check("root_gid")
def c_root_gid(ctx, p):
    try:
        gid = pwd.getpwnam("root").pw_gid
    except KeyError:
        return "error", "root account not found"
    if gid == 0:
        return "pass", "root primary group is GID 0"
    return "fail", "root primary group is GID %d" % gid


@fix("root_gid")
def f_root_gid(ctx, p):
    rc, o, e = sh(["usermod", "-g", "0", "root"], 30)
    if rc != 0:
        return False, "usermod failed: %s" % (e or o)[:200]
    return True, "set root primary group to GID 0"


@check("root_access")
def c_root_access(ctx, p):
    rc, o, _ = sh(["passwd", "-S", "root"], 30)
    if rc != 0:
        return "error", "unable to query the root account status"
    f = o.split()
    st = f[1] if len(f) > 1 else "?"
    if st.startswith("P"):
        return "pass", "root password is set (status %s)" % st
    if st.startswith("L"):
        return "pass", "root account is locked (status %s)" % st
    return "fail", "root has no password and is not locked (status %s)" % st


@check("useradd_inactive")
def c_useradd_inactive(ctx, p):
    mx = p.get("max", 30)
    rc, o, _ = sh("useradd -D | grep INACTIVE", 30)
    cur = as_int(o.split("=")[-1]) if "=" in o else None
    bad = []
    if cur is None or cur < 0 or cur > mx:
        bad.append("useradd default INACTIVE=%s (expected 0..%d)" % (cur, mx))
    # Any non-empty, non-"*" password field counts — locked accounts
    # (root on cloud images has "!!") are still login-capable via keys and
    # must get an inactivity lock too.
    users = out("awk -F: '$2 != \"\" && $2 != \"*\" {print $1}' /etc/shadow 2>/dev/null | "
                "while read -r u; do i=$(chage --list \"$u\" 2>/dev/null | "
                "awk -F: '/Password inactive/{print $2}' | tr -d ' '); "
                "echo \"$u:$i\"; done", 120)
    off = []
    for ln in users.splitlines():
        if ln.endswith(":never") or ln.endswith(":"):
            off.append(ln.split(":")[0])
    if off:
        bad.append("users without inactivity lock: " + ", ".join(off[:5]))
    if bad:
        return "fail", "; ".join(bad)
    return "pass", "INACTIVE=%s and all password users conform" % cur


@fix("useradd_inactive")
def f_useradd_inactive(ctx, p):
    mx = p.get("max", 30)
    sh(["useradd", "-D", "-f", str(mx)], 30)
    sh("awk -F: '$2 != \"\" && $2 != \"*\" {print $1}' /etc/shadow | "
       "xargs -r -n1 chage --inactive %d" % mx, 180)
    return True, "set default inactivity to %d days and updated existing users" % mx


# ==========================================================================
# SELinux / crypto policy
# ==========================================================================

@check("selinux")
def c_selinux(ctx, p):
    kind = p["kind"]
    if kind == "bootloader":
        cmdline = read("/proc/cmdline") or ""
        hits = [t for t in cmdline.split()
                if re.match(r"^(selinux=0|enforcing=0)$", t)]
        grubcfg = out("grep -Prs '^\\s*(GRUB_CMDLINE_LINUX|kernelopts)' "
                      "/etc/default/grub /boot/grub2/grubenv 2>/dev/null | "
                      "grep -Eo '(selinux|enforcing)=0' | sort -u", 30)
        if hits or grubcfg:
            return "fail", "SELinux disabled on the kernel command line: %s" % (
                " ".join(hits) or grubcfg.replace("\n", " "))
        return "pass", "no selinux=0 / enforcing=0 in the bootloader configuration"
    if kind == "policy":
        want = (p.get("value") or "targeted").lower()
        vals = conf_values(["/etc/selinux/config"], "SELINUXTYPE", (r"\s*=\s*",))
        cur = vals[-1][1].lower() if vals else None
        rc, o, _ = sh(["sestatus"], 30)
        loaded = ""
        m = re.search(r"Loaded policy name:\s*(\S+)", o or "")
        if m:
            loaded = m.group(1).lower()
        if cur == want and (not loaded or loaded == want):
            return "pass", "SELINUXTYPE=%s (loaded: %s)" % (cur, loaded or "n/a")
        return "fail", "SELINUXTYPE=%s loaded=%s (expected %s)" % (cur, loaded, want)
    if kind in ("mode_not_disabled", "mode_enforcing"):
        rc, cur, _ = sh(["getenforce"], 30)
        cur = (cur or "").strip()
        vals = conf_values(["/etc/selinux/config"], "SELINUX", (r"\s*=\s*",))
        cfg = vals[-1][1].lower() if vals else None
        if kind == "mode_not_disabled":
            ok = cur.lower() in ("enforcing", "permissive") and cfg in ("enforcing", "permissive")
            exp = "enforcing or permissive"
        else:
            ok = cur.lower() == "enforcing" and cfg == "enforcing"
            exp = "enforcing"
        if ok:
            return "pass", "runtime=%s config=%s" % (cur, cfg)
        return "fail", "runtime=%s config=%s (expected %s)" % (cur, cfg, exp)
    if kind == "no_unconfined":
        o = out("ps -eZ 2>/dev/null | grep -E 'unconfined_service_t' | "
                "awk '{print $NF}' | sort -u | head -20", 60)
        if o:
            return "fail", "unconfined services: " + ", ".join(o.split())
        return "pass", "no unconfined services running"
    return "error", "unknown selinux kind %s" % kind


@fix("selinux")
def f_selinux(ctx, p):
    kind = p["kind"]
    if kind == "bootloader":
        if exists("/etc/default/grub"):
            with ctx.file_lock("/etc/default/grub"):
                backup(ctx, "/etc/default/grub")
                txt = read("/etc/default/grub") or ""
                new = re.sub(r"\s*\b(selinux|enforcing)=0\b", "", txt)
                if new != txt:
                    write_file(ctx, "/etc/default/grub", new)
        with ctx.file_lock("__cmd__:grub2-mkconfig"):
            sh("grub2-mkconfig -o \"$(dirname \"$(find /boot -name grub.cfg "
               "-print -quit 2>/dev/null)\")/grub.cfg\" >/dev/null 2>&1", 300)
        return True, "removed selinux=0/enforcing=0 and regenerated grub.cfg (reboot required)"
    if kind == "policy":
        set_kv_in_file(ctx, "/etc/selinux/config", "SELINUXTYPE",
                       p.get("value") or "targeted", sep="=")
        return True, "set SELINUXTYPE in /etc/selinux/config (reboot required)"
    if kind in ("mode_not_disabled", "mode_enforcing"):
        mode = "enforcing"
        set_kv_in_file(ctx, "/etc/selinux/config", "SELINUX", mode, sep="=")
        rc, cur, _ = sh(["getenforce"], 30)
        if (cur or "").strip().lower() == "disabled":
            return True, "SELINUX=%s written; a reboot with relabel is required" % mode
        sh(["setenforce", "1"], 30)
        return True, "SELINUX=%s written and setenforce 1 applied" % mode
    return False, "no automated remediation for %s" % kind


def crypto_policy_now(ctx):
    return ctx.cached("crypto_policy",
                      lambda: (out(["update-crypto-policies", "--show"], 30) or "").strip())


# ── SSH-side crypto hardening (CIS 1.6.3-1.6.6) ──
# Tightens sshd's MACs/Ciphers directly so the four rules can pass WITHOUT
# touching the system-wide crypto policy (TencentOS ships LEGACY by design;
# switching it to DEFAULT affects every service, not just SSH).
SSH_CRYPTO_DROPIN = "/etc/ssh/sshd_config.d/60-cis-crypto.conf"

# OpenSSH built-in defaults (server side) — the baseline every rule trims.
_SSH_BASE_MACS = ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
                  "hmac-sha1-etm@openssh.com", "umac-64-etm@openssh.com",
                  "umac-128-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512",
                  "hmac-sha1", "umac-64", "umac-128"]
_SSH_BASE_CIPHERS = ["chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr",
                     "aes256-ctr", "aes128-gcm@openssh.com",
                     "aes256-gcm@openssh.com", "aes128-cbc", "aes192-cbc",
                     "aes256-cbc"]


def _sshd_algos(ctx, key):
    """Effective MACs/Ciphers list from `sshd -T` (None when sshd unavailable)."""
    d = sshd_effective(ctx)
    if not d:
        return None
    v = d.get(key)
    if not v:
        return list(_SSH_BASE_MACS) if key == "macs" else list(_SSH_BASE_CIPHERS)
    return [x.strip() for x in v[-1].split(",") if x.strip()]


def _sshd_crypto_dropin_current():
    """(macs, ciphers) already pinned in the drop-in, or None for unset."""
    txt = read(SSH_CRYPTO_DROPIN) or ""
    macs = ciphers = None
    for ln in txt.splitlines():
        m = re.match(r"^\s*MACs\s+(.+)$", ln, re.I)
        if m:
            macs = [x.strip() for x in m.group(1).split(",") if x.strip()]
            continue
        m = re.match(r"^\s*Ciphers\s+(.+)$", ln, re.I)
        if m:
            ciphers = [x.strip() for x in m.group(1).split(",") if x.strip()]
    return macs, ciphers


def _fix_sshd_crypto(ctx, kind):
    """Trim the cumulative sshd MACs/Ciphers whitelist for one 1.6.x family.

    Each family drops only its own weak algorithms from the shared drop-in,
    so the four rules compose correctly regardless of apply order (the
    per-path lock serialises the read-modify-write).
    """
    with ctx.file_lock(SSH_CRYPTO_DROPIN):
        macs, ciphers = _sshd_crypto_dropin_current()
        if macs is None:
            macs = list(_SSH_BASE_MACS)
        if ciphers is None:
            ciphers = list(_SSH_BASE_CIPHERS)
        if kind == "no_weak_mac":
            macs = [m for m in macs
                    if not (m.lower().startswith("hmac-md5")
                            or m.lower().startswith("hmac-sha1")
                            or m.lower().startswith("umac-64"))]
        elif kind == "no_etm_ssh":
            macs = [m for m in macs if "etm" not in m.lower()]
        elif kind == "no_cbc_ssh":
            ciphers = [c for c in ciphers if not c.lower().endswith("-cbc")]
        elif kind == "no_chacha_ssh":
            ciphers = [c for c in ciphers if "chacha20" not in c.lower()]
        body = ("# CIS hardening: SSH crypto policy (1.6.x)\n"
                "MACs %s\nCiphers %s\n" % (",".join(macs), ",".join(ciphers)))
        write_file(ctx, SSH_CRYPTO_DROPIN, body, 0o600)
    # OpenSSH honours the FIRST-obtained value for list params — make sure
    # the drop-in loads before any sshd_config MACs/Ciphers directive, and
    # neutralise ones already in the main file.
    main = read("/etc/ssh/sshd_config") or ""
    if not re.search(r"^\s*Include\s+/etc/ssh/sshd_config\.d/", main, re.M | re.I):
        backup(ctx, "/etc/ssh/sshd_config")
        write_file(ctx, "/etc/ssh/sshd_config",
                   "Include /etc/ssh/sshd_config.d/*.conf\n" + main, 0o600)
    comment_out(ctx, "/etc/ssh/sshd_config", r"^\s*MACs\s")
    comment_out(ctx, "/etc/ssh/sshd_config", r"^\s*Ciphers\s")
    ctx.defer_restart("sshd")
    ctx.invalidate("sshd_T")
    return True, "tightened sshd %s in %s" % (kind, SSH_CRYPTO_DROPIN)


CRYPTO_BACKENDS = "/etc/crypto-policies/back-ends"


@check("crypto_policy")
def c_crypto_policy(ctx, p):
    kind = p["kind"]
    if kind not in ("no_weak_mac", "no_etm_ssh", "no_cbc_ssh", "no_chacha_ssh"):
        if not have("update-crypto-policies"):
            return "notapplicable", "crypto-policies is not installed"
    cur = crypto_policy_now(ctx)
    if kind == "not_legacy":
        if cur.upper().startswith("LEGACY"):
            return "fail", "system-wide crypto policy is %s" % cur
        return "pass", "system-wide crypto policy is %s" % cur
    if kind == "future_or_fips":
        base = cur.split(":")[0].upper()
        if base in ("FUTURE", "FIPS"):
            return "pass", "system-wide crypto policy is %s" % cur
        return "fail", "system-wide crypto policy is %s (expected FUTURE or FIPS)" % cur

    def backend(name):
        return read(os.path.join(CRYPTO_BACKENDS, name)) or ""

    if kind == "no_sha1":
        bad = []
        for f in ("openssl.config", "gnutls.config", "opensshserver.config",
                  "openssh.config", "nss.config", "java.config"):
            txt = backend(f)
            if re.search(r"(?<![A-Za-z0-9-])SHA1(?![0-9])", txt, re.I) and \
                    not re.search(r"-SHA1", txt):
                bad.append(f)
        if bad:
            return "fail", "SHA1 still permitted in: " + ", ".join(bad)
        return "pass", "SHA1 is not permitted by the active crypto policy (%s)" % cur
    if kind in ("no_weak_mac", "no_etm_ssh", "no_cbc_ssh", "no_chacha_ssh"):
        # SSH-side hardening: judge the EFFECTIVE sshd config, not the
        # system-wide crypto policy (which may be LEGACY by business
        # decision).  These four rules compose into one sshd drop-in.
        if not sshd_effective(ctx):
            return "error", "unable to run 'sshd -T'"
        if kind in ("no_weak_mac", "no_etm_ssh"):
            macs = _sshd_algos(ctx, "macs")
            if kind == "no_weak_mac":
                weak = [m for m in macs
                        if m.lower().startswith("hmac-md5")
                        or m.lower().startswith("hmac-sha1")
                        or m.lower().startswith("umac-64")]
                if weak:
                    return "fail", "weak MACs permitted: " + ", ".join(weak)
                return "pass", "no weak MACs in the effective sshd MACs"
            etm = [m for m in macs if "etm" in m.lower()]
            if etm:
                return "fail", "EtM MACs are permitted for SSH: " + ", ".join(etm)
            return "pass", "no EtM MACs for SSH"
        ciphers = _sshd_algos(ctx, "ciphers")
        if kind == "no_cbc_ssh":
            cbc = [c for c in ciphers if c.lower().endswith("-cbc")]
            if cbc:
                return "fail", "CBC ciphers are permitted for SSH: " + ", ".join(cbc)
            return "pass", "no CBC ciphers for SSH"
        chacha = [c for c in ciphers if "chacha20" in c.lower()]
        if chacha:
            return "fail", "chacha20-poly1305 is permitted for SSH"
        return "pass", "chacha20-poly1305 not permitted for SSH"
    return "error", "unknown crypto policy kind %s" % kind


CRYPTO_MODULES = {
    "no_sha1": ("NO-SHA1", "hash = -SHA1\nsign = -*-SHA1\nsha1_in_certs = 0\n"),
    "no_weak_mac": ("NO-WEAKMAC", "mac = -*-64* -HMAC-MD5 -HMAC-SHA1\n"),
    "no_cbc_ssh": ("NO-SSHCBC", "cipher@SSH = -*-CBC\n"),
    "no_chacha_ssh": ("NO-SSHCHACHA20", "cipher@SSH = -CHACHA20-POLY1305\n"),
    "no_etm_ssh": ("NO-SSHETM", "etm@SSH = DISABLE_ETM\n"),
}


@fix("crypto_policy")
def f_crypto_policy(ctx, p):
    if not have("update-crypto-policies"):
        return False, "crypto-policies is not installed"
    kind = p["kind"]
    if kind in ("no_weak_mac", "no_etm_ssh", "no_cbc_ssh", "no_chacha_ssh"):
        # SSH-side only — no system-wide policy change, not disruptive.
        return _fix_sshd_crypto(ctx, kind)
    if kind in ("not_legacy", "future_or_fips"):
        target = "DEFAULT" if kind == "not_legacy" else "FUTURE"
        rc, o, e = sh(["update-crypto-policies", "--set", target], 120)
        if rc != 0:
            return False, "update-crypto-policies failed: %s" % (e or o)[:200]
        ctx.invalidate("crypto_policy")
        return True, "set the system-wide crypto policy to %s (reboot recommended)" % target
    name, body = CRYPTO_MODULES[kind]
    modpath = "/etc/crypto-policies/policies/modules/%s.pmod" % name
    write_file(ctx, modpath, "# CIS hardening\n" + body)
    cur = crypto_policy_now(ctx) or "DEFAULT"
    base = cur.split(":")[0]
    mods = [m for m in cur.split(":")[1:] if m]
    if name not in mods:
        mods.append(name)
    newpol = ":".join([base] + mods)
    rc, o, e = sh(["update-crypto-policies", "--set", newpol], 120)
    if rc != 0:
        return False, "update-crypto-policies --set %s failed: %s" % (newpol, (e or o)[:160])
    ctx.invalidate("crypto_policy")
    return True, "applied crypto policy %s (reboot recommended)" % newpol

# ==========================================================================
# auditd
# ==========================================================================

def _auditd_conf(key, default=None):
    vals = conf_values(["/etc/audit/auditd.conf"], key, (r"\s*=\s*",))
    return vals[-1][1].strip() if vals else default


AUDIT_TOOLS = ["/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace",
               "/sbin/auditd", "/sbin/augenrules", "/sbin/audisp-remote",
               "/sbin/rsyslogd"]


def _audit_targets(kind):
    logfile = _auditd_conf("log_file", "/var/log/audit/audit.log")
    logdir = os.path.dirname(logfile)
    if kind in ("logfile", "logfiles"):
        files = sorted(globmod.glob(os.path.join(logdir, "*")))
        return [f for f in files if os.path.isfile(f)] or (
            [logfile] if exists(logfile) else [])
    if kind == "logdir":
        return [logdir] if os.path.isdir(logdir) else []
    if kind in ("conf", "conffiles"):
        res = [f for f in ["/etc/audit/auditd.conf", "/etc/audit/audit.rules"]
               if exists(f)]
        res += sorted(globmod.glob("/etc/audit/rules.d/*.rules"))
        res += sorted(globmod.glob("/etc/audit/*.conf"))
        return sorted(set(f for f in res if os.path.isfile(f)))
    if kind == "tools":
        return [t for t in AUDIT_TOOLS if exists(t) and "rsyslogd" not in t]
    return []


@check("audit_perm")
def c_audit_perm(ctx, p):
    kind = p["kind"]
    targets = _audit_targets(kind)
    if not targets:
        return "notapplicable", "no %s targets found (auditd installed?)" % kind
    bad = []
    for f in targets:
        u, g, st = owner_of(f)
        if p.get("mode") and not mode_ok(st.st_mode, p["mode"]):
            bad.append("%s mode %s" % (f, fmt_mode(st.st_mode)))
        if p.get("owner") and u != p["owner"]:
            bad.append("%s owner %s" % (f, u))
        if p.get("group") and g != p["group"]:
            bad.append("%s group %s" % (f, g))
    if bad:
        return "fail", "%d/%d non-compliant: %s" % (
            len(bad), len(targets), "; ".join(bad[:4]))
    want = []
    if p.get("mode"):
        want.append("mode<=%s" % p["mode"])
    if p.get("owner"):
        want.append("owner=%s" % p["owner"])
    if p.get("group"):
        want.append("group=%s" % p["group"])
    return "pass", "%d %s target(s) satisfy %s" % (len(targets), kind, ", ".join(want))


@fix("audit_perm")
def f_audit_perm(ctx, p):
    targets = _audit_targets(p["kind"])
    if not targets:
        return False, "no targets found"
    for f in targets:
        if p.get("mode"):
            try:
                os.chmod(f, int(p["mode"], 8))
            except Exception as exc:
                ctx.add_note("chmod %s: %s" % (f, exc))
        if p.get("owner") or p.get("group"):
            sh(["chown", "%s:%s" % (p.get("owner") or "", p.get("group") or ""), f])
        ctx.add_changed_file(f)
    if p["kind"] in ("logfile", "logfiles") and p.get("mode"):
        set_kv_in_file(ctx, "/etc/audit/auditd.conf", "log_group", "root", sep=" = ")
    return True, "applied to %d %s target(s)" % (len(targets), p["kind"])


def _norm_rule(r):
    r = re.sub(r"\s+", " ", r.strip())
    r = r.replace("__UID_MIN__", str(uid_min()))
    r = re.sub(r"-F\s+auid!=(unset|4294967295|-1)", "-F auid!=-1", r)
    r = re.sub(r'["\']', "", r)
    return r


def _running_rules(ctx):
    return ctx.cached("auditctl_l",
                      lambda: [_norm_rule(x) for x in
                               (out(["auditctl", "-l"], 60) or "").splitlines()
                               if x.strip() and x.strip() != "No rules"])


def _ondisk_rules(ctx):
    def load():
        res = []
        for f in sorted(globmod.glob("/etc/audit/rules.d/*.rules")):
            for ln in readlines(f):
                s = ln.strip()
                if s and not s.startswith("#"):
                    res.append(_norm_rule(s))
        return res
    return ctx.cached("rulesd", load)


def _rule_present(want, pool):
    w = _norm_rule(want)
    if w in pool:
        return True
    # auditctl -l renders -w/-p as -a always,exit -F path=... -F perm=...
    m = re.match(r"^-w\s+(\S+)\s+-p\s+(\S+)\s+-k\s+(\S+)$", w)
    if m:
        path, perm, key = m.groups()
        for r in pool:
            if ("-F path=%s" % path) in r and ("-F perm=%s" % perm) in r \
                    and r.endswith("-F key=%s" % key):
                return True
        return False
    # normalise -k vs -F key=
    w2 = re.sub(r"\s-k\s+(\S+)$", r" -F key=\1", w)
    if w2 in pool:
        return True
    wset = set(w2.split(" -F "))
    for r in pool:
        if set(r.split(" -F ")) == wset:
            return True
    return False


@check("audit_rule")
def c_audit_rule(ctx, p):
    if not pkg_installed("audit"):
        return "notapplicable", "the audit package is not installed"
    running = _running_rules(ctx)
    ondisk = _ondisk_rules(ctx)
    miss_run, miss_disk = [], []
    for r in p["rules"]:
        if not _rule_present(r, running):
            miss_run.append(r)
        if not _rule_present(r, ondisk):
            miss_disk.append(r)
    if not miss_run and not miss_disk:
        return "pass", "%d rule(s) loaded and persisted" % len(p["rules"])
    why = []
    if miss_disk:
        why.append("not in /etc/audit/rules.d: %s" % "; ".join(miss_disk[:2]))
    if miss_run:
        why.append("not loaded in the running config: %s" % "; ".join(miss_run[:2]))
    return "fail", " | ".join(why)


AUDIT_CIS_RULES = "/etc/audit/rules.d/60-cis-hardening.rules"


@fix("audit_rule")
def f_audit_rule(ctx, p):
    if not pkg_installed("audit"):
        return False, "the audit package is not installed"
    existing = readlines(AUDIT_CIS_RULES) if exists(AUDIT_CIS_RULES) else \
        ["# Managed by CIS Ansible hardening"]
    pool = [_norm_rule(x) for x in existing if x.strip() and not x.startswith("#")]
    added = []
    for r in p["rules"]:
        rr = _norm_rule(r)
        if rr not in pool:
            existing.append(rr)
            pool.append(rr)
            added.append(rr)
    if added:
        write_file(ctx, AUDIT_CIS_RULES, "\n".join(existing).rstrip("\n") + "\n", 0o640)
    with ctx.file_lock("__cmd__:augenrules"):
        rc, o, e = sh(["augenrules", "--load"], 120)
    ctx.invalidate("auditctl_l", "rulesd")
    note = ""
    if rc != 0:
        note = " (augenrules reported: %s)" % (e or o)[:120]
    if not added:
        return True, "rules already present; reloaded audit rules" + note
    return True, "added %d rule(s) to %s and reloaded%s" % (
        len(added), AUDIT_CIS_RULES, note)


@check("audit_privileged")
def c_audit_privileged(ctx, p):
    if not pkg_installed("audit"):
        return "notapplicable", "the audit package is not installed"
    umin = uid_min()
    binaries = _fs_scan(ctx)["privileged"]
    if not binaries:
        return "pass", "no setuid/setgid binaries found"
    pool = _running_rules(ctx) + _ondisk_rules(ctx)
    missing = []
    for b in binaries:
        want = ("-a always,exit -F path=%s -F perm=x -F auid>=%d -F auid!=-1 "
                "-k privileged" % (b, umin))
        if not any(("-F path=%s " % b) in r and "-F perm=x" in r for r in pool):
            missing.append(b)
    if missing:
        return "fail", "%d/%d privileged binaries lack an audit rule, e.g. %s" % (
            len(missing), len(binaries), ", ".join(missing[:4]))
    return "pass", "all %d privileged binaries are audited" % len(binaries)


@fix("audit_privileged")
def f_audit_privileged(ctx, p):
    if not pkg_installed("audit"):
        return False, "the audit package is not installed"
    umin = uid_min()
    binaries = _fs_scan(ctx)["privileged"]
    if not binaries:
        return False, "no setuid/setgid binaries found"
    lines = ["# CIS hardening: privileged command execution"]
    for b in binaries:
        lines.append("-a always,exit -F path=%s -F perm=x -F auid>=%d "
                     "-F auid!=unset -k privileged" % (b, umin))
    write_file(ctx, "/etc/audit/rules.d/61-cis-privileged.rules",
               "\n".join(lines) + "\n", 0o640)
    with ctx.file_lock("__cmd__:augenrules"):
        sh(["augenrules", "--load"], 120)
    ctx.invalidate("auditctl_l", "rulesd")
    return True, "wrote audit rules for %d privileged binaries" % len(binaries)


@check("audit_immutable")
def c_audit_immutable(ctx, p):
    if not pkg_installed("audit"):
        return "notapplicable", "the audit package is not installed"
    disk = _ondisk_rules(ctx)
    last_e = [r for r in disk if re.match(r"^-e\s+\d", r)]
    rc, o, _ = sh(["auditctl", "-s"], 30)
    enabled = None
    m = re.search(r"^enabled\s+(\d)", o or "", re.M)
    if m:
        enabled = m.group(1)
    if last_e and last_e[-1].split()[-1] == "2" and (enabled in (None, "2")):
        return "pass", "audit configuration is immutable (-e 2)"
    return "fail", "'-e 2' is not the final rule (rules.d: %s, running enabled=%s)" % (
        last_e[-1] if last_e else "absent", enabled)


@fix("audit_immutable")
def f_audit_immutable(ctx, p):
    if not pkg_installed("audit"):
        return False, "the audit package is not installed"
    path = "/etc/audit/rules.d/99-finalize.rules"
    with ctx.file_lock(path):
        body = read(path) or "# CIS hardening\n"
        # Merge instead of overwrite: strip any existing -e lines, keep
        # everything else (notably a "-f N" from audit_failure_mode, which
        # must precede -e), then re-append -e 2 as the final rule.
        if not re.search(r"^-e\s+2\s*$", body, re.M):
            lines = [l for l in body.splitlines()
                     if not re.match(r"^-e\s+\d", l)]
            lines.append("-e 2")
            write_file(ctx, path, "\n".join(lines) + "\n", 0o640)
    with ctx.file_lock("__cmd__:augenrules"):
        sh(["augenrules", "--load"], 120)
    ctx.invalidate("auditctl_l", "rulesd")
    return True, ("wrote /etc/audit/rules.d/99-finalize.rules with '-e 2'; "
                  "a reboot is required for it to take effect")


@check("audit_failure_mode")
def c_audit_failure_mode(ctx, p):
    if not pkg_installed("audit"):
        return "notapplicable", "the audit package is not installed"
    disk = [r for r in _ondisk_rules(ctx) if re.match(r"^-f\s+\d", r)]
    rc, o, _ = sh(["auditctl", "-s"], 30)
    m = re.search(r"^failure\s+(\d)", o or "", re.M)
    run = m.group(1) if m else None
    ok_disk = bool(disk) and disk[-1].split()[-1] in ("1", "2")
    ok_run = run in ("1", "2")
    if ok_disk and ok_run:
        return "pass", "failure mode %s (rules.d: %s)" % (run, disk[-1])
    return "fail", "failure mode running=%s rules.d=%s (expected 1 or 2)" % (
        run, disk[-1] if disk else "absent")


@fix("audit_failure_mode")
def f_audit_failure_mode(ctx, p):
    if not pkg_installed("audit"):
        return False, "the audit package is not installed"
    path = "/etc/audit/rules.d/99-finalize.rules"
    with ctx.file_lock(path):
        body = read(path) or "# CIS hardening\n"
        if not re.search(r"^-f\s+\d", body, re.M):
            # -f must come before -e 2
            lines = [l for l in body.splitlines() if not re.match(r"^-e\s+\d", l)]
            lines.append("-f 1")
            if re.search(r"^-e\s+\d", body, re.M):
                lines.append("-e 2")
            body = "\n".join(lines) + "\n"
            write_file(ctx, path, body, 0o640)
    with ctx.file_lock("__cmd__:augenrules"):
        sh(["augenrules", "--load"], 120)
    ctx.invalidate("auditctl_l", "rulesd")
    return True, "set audit failure mode to 1 in %s" % path


@check("audit_running_sync")
def c_audit_running_sync(ctx, p):
    if not pkg_installed("audit"):
        return "notapplicable", "the audit package is not installed"
    rc, o, e = sh(["augenrules", "--check"], 60)
    txt = (o or "") + (e or "")
    if "No change" in txt:
        return "pass", "augenrules --check reports no change"
    running = set(_running_rules(ctx))
    disk = set(_ondisk_rules(ctx))
    diff = (disk - running) | (running - disk)
    if not diff:
        return "pass", "running rules match /etc/audit/rules.d"
    return "fail", "%d rule(s) differ between disk and the running config" % len(diff)


@fix("audit_running_sync")
def f_audit_running_sync(ctx, p):
    if not pkg_installed("audit"):
        return False, "the audit package is not installed"
    with ctx.file_lock("__cmd__:augenrules"):
        rc, o, e = sh(["augenrules", "--load"], 120)
    ctx.invalidate("auditctl_l", "rulesd")
    if rc != 0:
        return False, "augenrules --load failed: %s" % (e or o)[:200]
    return True, "reloaded audit rules from /etc/audit/rules.d"


AIDE_AUDIT_TOOLS = ["/sbin/auditctl", "/sbin/auditd", "/sbin/ausearch",
                    "/sbin/aureport", "/sbin/autrace", "/sbin/augenrules"]
AIDE_SEL = "p+i+n+u+g+s+b+acl+xattrs+sha512"


def _create_aidecheck_units(ctx):
    """Create aidecheck.service + aidecheck.timer when the aide package
    doesn't ship them (common on TencentOS 3 / older RHEL)."""
    svc_tmpl = (
        "[Unit]\n"
        "Description=AIDE daily filesystem integrity check\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/sbin/aide --check\n"
        "Nice=19\n"
        "IOSchedulingClass=idle\n"
    )
    timer_tmpl = (
        "[Unit]\n"
        "Description=Daily AIDE check\n"
        "[Timer]\n"
        "OnCalendar=daily\n"
        "AccuracySec=12h\n"
        "Persistent=true\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    for path, content in [("/etc/systemd/system/aidecheck.service", svc_tmpl),
                          ("/etc/systemd/system/aidecheck.timer", timer_tmpl)]:
        if not exists(path):
            write_file(ctx, path, content, 0o644)
    sh(["systemctl", "daemon-reload"], 30)
    _unit_db_invalidate()


def _aide_conf():
    for c in ("/etc/aide.conf", "/etc/aide/aide.conf"):
        if exists(c):
            return c
    return None


@check("aide_audit_tools")
def c_aide_audit_tools(ctx, p):
    if not pkg_installed("aide"):
        return "fail", "aide is not installed, so audit tool integrity is not monitored"
    conf = _aide_conf()
    if not conf:
        return "fail", "no aide.conf found"
    txt = read(conf) or ""
    for extra in globmod.glob(os.path.join(os.path.dirname(conf), "aide.conf.d/*")):
        txt += read(extra) or ""
    missing = [t for t in AIDE_AUDIT_TOOLS
               if exists(t) and not re.search(r"^\s*%s\s+\S*sha512" % re.escape(t),
                                              txt, re.M)]
    if missing:
        return "fail", "not protected by AIDE: " + ", ".join(missing)
    return "pass", "all audit tools are covered by AIDE selection lines"


@fix("aide_audit_tools")
def f_aide_audit_tools(ctx, p):
    if not pkg_installed("aide"):
        return False, "aide is not installed"
    conf = _aide_conf()
    if not conf:
        return False, "no aide.conf found"
    txt = read(conf) or ""
    add = [t for t in AIDE_AUDIT_TOOLS
           if exists(t) and not re.search(r"^\s*%s\s" % re.escape(t), txt, re.M)]
    if not add:
        return False, "already configured"
    backup(ctx, conf)
    with open(conf, "a", encoding="utf-8") as fh:
        fh.write("\n# CIS hardening: audit tools\n")
        for t in add:
            fh.write("%s %s\n" % (t, AIDE_SEL))
    ctx.add_changed_file(conf)
    return True, "added %d audit tool selection line(s) to %s" % (len(add), conf)


# ==========================================================================
# Bootloader
# ==========================================================================

def _grub_cfg():
    for c in ("/boot/grub2/grub.cfg", "/boot/efi/EFI/tencentos/grub.cfg",
              "/boot/efi/EFI/centos/grub.cfg", "/boot/efi/EFI/redhat/grub.cfg",
              "/boot/grub/grub.cfg"):
        if exists(c):
            return c
    hits = out("find /boot -maxdepth 4 -name grub.cfg 2>/dev/null | head -1", 60)
    return hits.strip() or None


@check("grub_flag")
def c_grub_flag(ctx, p):
    cmdline = read("/proc/cmdline") or ""
    if "match" in p:
        m = re.search(p["match"], cmdline)
        cur = as_int(m.group(1)) if m else None
        if cur is not None and cur >= p.get("min", 0):
            return "pass", "kernel command line has %s" % m.group(0)
        return "fail", "kernel command line %s (expected >= %s)" % (
            m.group(0) if m else "missing audit_backlog_limit", p.get("min"))
    key, want = p["key"], str(p["value"])
    m = re.search(r"(?:^|\s)%s=(\S+)" % re.escape(key), cmdline)
    if m and m.group(1) == want:
        return "pass", "%s=%s on the kernel command line" % (key, want)
    return "fail", "%s=%s on the kernel command line (expected %s)" % (
        key, m.group(1) if m else "(absent)", want)


@fix("grub_flag")
def f_grub_flag(ctx, p):
    if "match" in p:
        flag = p["flag"]
        key = flag.split("=")[0]
    else:
        key, flag = p["key"], "%s=%s" % (p["key"], p["value"])
    path = "/etc/default/grub"
    if not exists(path):
        return False, "%s does not exist" % path
    with ctx.file_lock(path):
        backup(ctx, path)
        txt = read(path) or ""
        m = re.search(r'^(GRUB_CMDLINE_LINUX)=(["\'])(.*?)\2\s*$', txt, re.M | re.S)
        if m:
            cur = re.sub(r"\s*\b%s=\S+" % re.escape(key), "", m.group(3)).strip()
            newval = (cur + " " + flag).strip()
            txt = txt[:m.start()] + '%s="%s"' % (m.group(1), newval) + txt[m.end():]
        else:
            txt = txt.rstrip("\n") + '\nGRUB_CMDLINE_LINUX="%s"\n' % flag
        write_file(ctx, path, txt)
    cfg = _grub_cfg()
    if cfg:
        with ctx.file_lock("__cmd__:grub2-mkconfig"):
            sh(["grub2-mkconfig", "-o", cfg], 300)
    return True, "added %s to GRUB_CMDLINE_LINUX and regenerated %s (reboot required)" % (
        flag, cfg or "grub.cfg")


@check("bootloader_password")
def c_bootloader_password(ctx, p):
    files = ["/boot/grub2/user.cfg", "/boot/grub2/grub.cfg",
             "/etc/grub.d/01_users", "/etc/grub.d/40_custom"]
    cfg = _grub_cfg()
    if cfg and cfg not in files:
        files.append(cfg)
    has_pw = False
    has_su = False
    for f in files:
        txt = read(f) or ""
        if re.search(r"^\s*(GRUB2_PASSWORD|password_pbkdf2)", txt, re.M):
            has_pw = True
        if re.search(r"^\s*set\s+superusers", txt, re.M):
            has_su = True
    if has_pw and has_su:
        return "pass", "a GRUB superuser and password hash are configured"
    miss = []
    if not has_su:
        miss.append("no 'set superusers'")
    if not has_pw:
        miss.append("no password_pbkdf2 / GRUB2_PASSWORD")
    return "fail", "; ".join(miss)
# no automated fix: the password must be chosen by an operator


@check("bootloader_perm")
def c_bootloader_perm(ctx, p):
    cfg = _grub_cfg()
    targets = [x for x in [cfg, "/boot/grub2/grubenv", "/boot/grub2/user.cfg"]
               if x and exists(x)]
    if not targets:
        return "notapplicable", "no GRUB configuration files found"
    bad = []
    for f in targets:
        u, g, st = owner_of(f)
        if u != "root" or g != "root" or not mode_ok(st.st_mode, "600"):
            bad.append("%s (%s %s:%s)" % (f, fmt_mode(st.st_mode), u, g))
    if bad:
        return "fail", "non-compliant: " + ", ".join(bad)
    return "pass", "%d bootloader file(s) are 0600 root:root" % len(targets)


@fix("bootloader_perm")
def f_bootloader_perm(ctx, p):
    cfg = _grub_cfg()
    targets = [x for x in [cfg, "/boot/grub2/grubenv", "/boot/grub2/user.cfg"]
               if x and exists(x)]
    for f in targets:
        sh(["chown", "root:root", f])
        os.chmod(f, 0o600)
        ctx.add_changed_file(f)
    if not targets:
        return False, "no bootloader files found"
    return True, "set 0600 root:root on %d file(s)" % len(targets)


@check("single_user_auth")
def c_single_user_auth(ctx, p):
    bad = []
    for unit in ("rescue.service", "emergency.service"):
        rc, o, _ = sh(["systemctl", "cat", unit], 30)
        if rc != 0:
            continue
        m = re.search(r"^ExecStart=.*$", o, re.M)
        if not m or "sulogin" not in m.group(0):
            bad.append("%s: %s" % (unit, m.group(0) if m else "no ExecStart"))
    if bad:
        return "fail", "; ".join(bad)
    return "pass", "rescue and emergency modes require the root password (sulogin)"


@fix("single_user_auth")
def f_single_user_auth(ctx, p):
    tmpl = ("[Service]\nExecStart=\n"
            "ExecStart=-/usr/lib/systemd/systemd-sulogin-shell %s\n")
    for unit, mode in (("rescue.service", "rescue"), ("emergency.service", "emergency")):
        d = "/etc/systemd/system/%s.d" % unit
        write_file(ctx, os.path.join(d, "60-cis.conf"), tmpl % mode)
    sh(["systemctl", "daemon-reload"], 60)
    _unit_db_invalidate()
    return True, "forced sulogin for rescue.service and emergency.service"


@check("firewalld_zone_target")
def c_firewalld_zone_target(ctx, p):
    if not pkg_installed("firewalld"):
        return "notapplicable", "firewalld is not installed"
    rc, o, _ = sh(["firewall-cmd", "--state"], 30)
    if rc != 0:
        return "fail", "firewalld is not running"
    zones = out("firewall-cmd --get-active-zones 2>/dev/null | "
                "grep -v '^\\s' | grep -v '^$'", 30).splitlines()
    bad = []
    for z in zones:
        z = z.strip()
        if not z:
            continue
        t = out(["firewall-cmd", "--zone=%s" % z, "--get-target"], 30).strip()
        if t == "ACCEPT":
            bad.append("%s -> ACCEPT" % z)
    if not zones:
        return "fail", "no active firewalld zone is configured"
    if bad:
        return "fail", "active zone target is ACCEPT: " + ", ".join(bad)
    return "pass", "active zone(s) %s do not target ACCEPT" % ", ".join(z.strip() for z in zones)


def _detect_ssh_port():
    """Read Port from /etc/ssh/sshd_config, fallback to 22."""
    try:
        with open("/etc/ssh/sshd_config") as fh:
            for line in fh:
                m = re.match(r'^\s*Port\s+(\d+)', line, re.I)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return "22"


@fix("firewalld_zone_target")
def f_firewalld_zone_target(ctx, p):
    if not pkg_installed("firewalld"):
        return False, "firewalld is not installed"
    zones = [z.strip() for z in
             out("firewall-cmd --get-active-zones 2>/dev/null | grep -v '^\\s'",
                 30).splitlines() if z.strip()]
    if not zones:
        return False, "no active firewalld zones"
    ssh_port = _detect_ssh_port()
    # Always whitelist SSH port on every active zone, even when the
    # target is already DROP.  Without this, a base image whose zone
    # already targets DROP will lock out SSH after reboot because the
    # permanent config never includes an allow rule for the ssh port.
    for z in zones:
        sh(["firewall-cmd", "--zone=%s" % z,
            "--add-port=%s/tcp" % ssh_port, "--permanent"], 60)
    target_changed = []
    for z in zones:
        if out(["firewall-cmd", "--zone=%s" % z, "--get-target"], 30).strip() == "ACCEPT":
            sh(["firewall-cmd", "--zone=%s" % z, "--set-target=DROP", "--permanent"], 60)
            target_changed.append(z)
    sh(["firewall-cmd", "--reload"], 60)
    msgs = ["SSH port %s/tcp whitelisted on zone(s): %s" % (ssh_port, ", ".join(zones))]
    if target_changed:
        msgs.append("set target=DROP on zone(s): " + ", ".join(target_changed))
    else:
        msgs.append("zone target(s) already DROP")
    return True, "; ".join(msgs)

# ==========================================================================
# User / group hygiene  (family: user_audit)
# ==========================================================================

def _interactive_users(ctx):
    """(name, uid, gid, home, shell) for real interactive accounts."""
    def load():
        umin = uid_min()
        res = []
        for e in pwd.getpwall():
            if e.pw_shell.rstrip("/").split("/")[-1] in ("nologin", "false", "sync",
                                                         "shutdown", "halt"):
                continue
            if e.pw_name == "root" or (umin <= e.pw_uid < 65534):
                res.append(e)
        return res
    return ctx.cached("interactive_users", load)


def _passwd_entries():
    """Parse /etc/passwd — cached: called ~10× per audit scan."""
    global _PASSWD_CACHE
    if _PASSWD_CACHE is None:
        _PASSWD_CACHE = [ln.split(":") for ln in readlines("/etc/passwd") if ln.count(":") >= 6]
    return _PASSWD_CACHE


_PASSWD_CACHE = None


def _shadow_entries():
    """Parse /etc/shadow — cached."""
    global _SHADOW_CACHE
    if _SHADOW_CACHE is None:
        _SHADOW_CACHE = [ln.split(":") for ln in readlines("/etc/shadow") if ln.count(":") >= 8]
    return _SHADOW_CACHE


_SHADOW_CACHE = None


def _group_entries():
    """Parse /etc/group — cached."""
    global _GROUP_CACHE
    if _GROUP_CACHE is None:
        _GROUP_CACHE = [ln.split(":") for ln in readlines("/etc/group") if ln.count(":") >= 3]
    return _GROUP_CACHE


_GROUP_CACHE = None


def _ua_su_wheel(ctx):
    lines = [l for _, l in _sudoers_lines(ctx)]
    pam = read("/etc/pam.d/su") or ""
    m = re.search(r"^\s*auth\s+(?:required|requisite)\s+pam_wheel\.so\s+(.*)$",
                  pam, re.M)
    if not m:
        return "fail", "/etc/pam.d/su does not enforce pam_wheel.so use_uid"
    args = m.group(1)
    if "use_uid" not in args:
        return "fail", "pam_wheel.so is present but lacks use_uid"
    gm = re.search(r"group=(\S+)", args)
    if not gm:
        return "fail", "pam_wheel.so does not specify group="
    gname = gm.group(1)
    try:
        members = grp.getgrnam(gname).gr_mem
    except KeyError:
        return "fail", "group %s referenced by pam_wheel.so does not exist" % gname
    if members:
        return "fail", "group %s must be empty but contains: %s" % (
            gname, ", ".join(members))
    return "pass", "su restricted to the empty group '%s' via pam_wheel.so use_uid" % gname


def _ua_pw_change_past(ctx):
    today = int(time.time() // 86400)
    bad = []
    for f in _shadow_entries():
        name, pw, lastchg = f[0], f[1], f[2]
        if not pw.startswith("$"):
            continue
        n = as_int(lastchg)
        if n is None:
            continue
        if n > today:
            bad.append("%s (%d days in the future)" % (name, n - today))
    if bad:
        return "fail", "last password change is in the future: " + ", ".join(bad[:6])
    return "pass", "all password change dates are in the past"


def _ua_uid0_root_only(ctx):
    names = [f[0] for f in _passwd_entries() if f[2] == "0"]
    if names == ["root"]:
        return "pass", "root is the only UID 0 account"
    return "fail", "UID 0 accounts: " + ", ".join(names)


GID0_WHITELIST = frozenset({"root", "sync", "shutdown", "halt", "operator"})


def _ua_gid0_root_only(ctx):
    names = [f[0] for f in _passwd_entries() if f[3] == "0"]
    extra = [n for n in names if n not in GID0_WHITELIST]
    if not extra:
        return "pass", "only allowlisted accounts have primary GID 0: " + \
                        ", ".join(names)
    return "fail", "unexpected accounts with primary GID 0: " + ", ".join(extra)


def _ua_gid0_group_root(ctx):
    names = [f[0] for f in _group_entries() if f[2] == "0"]
    if names == ["root"]:
        return "pass", "root is the only GID 0 group"
    return "fail", "GID 0 groups: " + ", ".join(names)


def _ua_root_path(ctx):
    rc, o, _ = sh("sudo -Hiu root env 2>/dev/null | grep '^PATH=' || echo \"PATH=$PATH\"", 60)
    path = o.split("=", 1)[1] if "=" in o else ""
    bad = []
    parts = path.split(":")
    if "" in parts or "." in parts:
        bad.append("PATH contains an empty or '.' entry")
    for d in parts:
        if not d or d == ".":
            continue
        if not os.path.isdir(d):
            bad.append("%s is not a directory" % d)
            continue
        _, _, st = owner_of(d)
        if st.st_mode & stat.S_IWGRP:
            bad.append("%s is group writable" % d)
        if st.st_mode & stat.S_IWOTH:
            bad.append("%s is world writable" % d)
        try:
            if pwd.getpwuid(st.st_uid).pw_name != "root":
                bad.append("%s is not owned by root" % d)
        except KeyError:
            bad.append("%s has an unknown owner" % d)
    if bad:
        return "fail", "; ".join(bad[:6])
    return "pass", "root PATH integrity is intact (%d entries)" % len(parts)


def _ua_system_shell(ctx):
    umin = uid_min()
    bad = []
    for f in _passwd_entries():
        name, uid, shell = f[0], as_int(f[2], -1), f[6]
        if name == "root" or uid is None:
            continue
        if uid >= umin or uid == 65534:
            continue
        base = shell.rstrip("/").split("/")[-1]
        if base not in ("nologin", "false", "sync", "shutdown", "halt", ""):
            bad.append("%s (%s)" % (name, shell))
    if bad:
        return "fail", "system accounts with a login shell: " + ", ".join(bad[:8])
    return "pass", "no system account has a valid login shell"


def _ua_nologin_locked(ctx):
    bad = []
    shadow = {f[0]: f[1] for f in _shadow_entries()}
    for f in _passwd_entries():
        name, shell = f[0], f[6]
        base = shell.rstrip("/").split("/")[-1]
        if base not in ("nologin", "false"):
            continue
        if name == "root":
            continue
        pw = shadow.get(name, "")
        if pw and not pw.startswith(("!", "*")):
            bad.append(name)
    if bad:
        return "fail", "accounts without a valid shell that are not locked: " + \
            ", ".join(bad[:8])
    return "pass", "all accounts without a valid login shell are locked"


def _ua_world_writable(ctx):
    return c_world_writable(ctx, {})


def _ua_sticky_bit(ctx):
    dirs = _fs_scan(ctx)["world_dirs"]
    if dirs:
        return "fail", "%d world-writable dir(s) without the sticky bit, e.g. %s" % (
            len(dirs), ", ".join(dirs[:4]))
    return "pass", "all world-writable directories have the sticky bit"


def _ua_unowned(ctx):
    paths = _fs_scan(ctx)["unowned"]
    if paths:
        return "fail", "%d unowned/ungrouped path(s), e.g. %s" % (
            len(paths), ", ".join(paths[:4]))
    return "pass", "no unowned or ungrouped files or directories"


def _ua_ungrouped(ctx):
    paths = _fs_scan(ctx)["ungrouped"]
    if paths:
        return "fail", "%d ungrouped path(s), e.g. %s" % (
            len(paths), ", ".join(paths[:4]))
    return "pass", "no ungrouped files or directories"


def _ua_passwd_shadowed(ctx):
    bad = [f[0] for f in _passwd_entries() if f[1] != "x"]
    if bad:
        return "fail", "/etc/passwd entries not using shadow: " + ", ".join(bad[:8])
    return "pass", "all /etc/passwd entries use shadowed passwords"


def _ua_shadow_not_empty(ctx):
    bad = [f[0] for f in _shadow_entries() if f[1] == ""]
    if bad:
        return "fail", "accounts with an empty password field: " + ", ".join(bad[:8])
    return "pass", "no empty password fields in /etc/shadow"


_ua_empty_password = _ua_shadow_not_empty


def _ua_groups_exist(ctx):
    gids = {f[2] for f in _group_entries()}
    bad = ["%s(gid %s)" % (f[0], f[3]) for f in _passwd_entries() if f[3] not in gids]
    if bad:
        return "fail", "GIDs in /etc/passwd with no /etc/group entry: " + ", ".join(bad[:8])
    return "pass", "every GID referenced in /etc/passwd exists in /etc/group"


def _dups(values):
    seen, dup = set(), set()
    for v in values:
        if v in seen:
            dup.add(v)
        seen.add(v)
    return sorted(dup)


def _ua_dup_uid(ctx):
    d = _dups([f[2] for f in _passwd_entries()])
    return ("fail", "duplicate UIDs: " + ", ".join(d)) if d else \
           ("pass", "no duplicate UIDs")


def _ua_dup_gid(ctx):
    d = _dups([f[2] for f in _group_entries()])
    return ("fail", "duplicate GIDs: " + ", ".join(d)) if d else \
           ("pass", "no duplicate GIDs")


def _ua_dup_user(ctx):
    d = _dups([f[0] for f in _passwd_entries()])
    return ("fail", "duplicate user names: " + ", ".join(d)) if d else \
           ("pass", "no duplicate user names")


def _ua_dup_group(ctx):
    d = _dups([f[0] for f in _group_entries()])
    return ("fail", "duplicate group names: " + ", ".join(d)) if d else \
           ("pass", "no duplicate group names")


def _ua_home_exists(ctx):
    bad = [e.pw_name for e in _interactive_users(ctx) if not os.path.isdir(e.pw_dir)]
    if bad:
        return "fail", "users without a home directory: " + ", ".join(bad[:8])
    return "pass", "all interactive users have a home directory"


def _ua_home_owner(ctx):
    bad = []
    for e in _interactive_users(ctx):
        if not os.path.isdir(e.pw_dir):
            continue
        st = os.stat(e.pw_dir)
        if st.st_uid != e.pw_uid:
            bad.append("%s (%s owned by uid %d)" % (e.pw_name, e.pw_dir, st.st_uid))
    if bad:
        return "fail", "; ".join(bad[:6])
    return "pass", "all interactive users own their home directory"


def _ua_home_dirs(ctx):
    bad = []
    for e in _interactive_users(ctx):
        if not os.path.isdir(e.pw_dir):
            bad.append("%s: %s missing" % (e.pw_name, e.pw_dir))
            continue
        st = os.stat(e.pw_dir)
        if st.st_uid != e.pw_uid:
            bad.append("%s: %s not owned by the user" % (e.pw_name, e.pw_dir))
        if not mode_ok(st.st_mode, "750"):
            bad.append("%s: %s mode %s" % (e.pw_name, e.pw_dir, fmt_mode(st.st_mode)))
    if bad:
        return "fail", "; ".join(bad[:6])
    return "pass", "all interactive home directories exist, are owned by the user " \
                   "and are 0750 or more restrictive"


def _ua_dot_files(ctx):
    bad = []
    for e in _interactive_users(ctx):
        if not os.path.isdir(e.pw_dir):
            continue
        for f in globmod.glob(os.path.join(e.pw_dir, ".*")):
            if not os.path.isfile(f):
                continue
            base = os.path.basename(f)
            st = os.stat(f)
            if base in (".bash_history", ".netrc") and not mode_ok(st.st_mode, "600"):
                bad.append("%s mode %s" % (f, fmt_mode(st.st_mode)))
            elif st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                bad.append("%s is group/world writable (%s)" % (f, fmt_mode(st.st_mode)))
    if bad:
        return "fail", "; ".join(bad[:6])
    return "pass", "user dot files are not group or world writable"


def _dotfile_scan(ctx, names):
    hits = []
    for e in _interactive_users(ctx):
        for n in names:
            f = os.path.join(e.pw_dir, n)
            if os.path.exists(f):
                hits.append(f)
    return hits


def _ua_no_forward(ctx):
    h = _dotfile_scan(ctx, [".forward"])
    return ("fail", ".forward files present: " + ", ".join(h[:8])) if h else \
           ("pass", "no .forward files")


def _ua_no_netrc(ctx):
    h = _dotfile_scan(ctx, [".netrc"])
    return ("fail", ".netrc files present: " + ", ".join(h[:8])) if h else \
           ("pass", "no .netrc files")


def _ua_no_rhosts(ctx):
    h = _dotfile_scan(ctx, [".rhosts", ".shosts"])
    return ("fail", ".rhosts/.shosts files present: " + ", ".join(h[:8])) if h else \
           ("pass", "no .rhosts or .shosts files")


def _ua_netrc_perm(ctx):
    bad = []
    for f in _dotfile_scan(ctx, [".netrc"]):
        st = os.stat(f)
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            bad.append("%s (%s)" % (f, fmt_mode(st.st_mode)))
    if bad:
        return "fail", "group/world accessible .netrc: " + ", ".join(bad[:6])
    return "pass", "no group- or world-accessible .netrc files"


UA = {name[4:]: fn for name, fn in list(globals().items())
      if name.startswith("_ua_") and callable(fn)}


@check("user_audit")
def c_user_audit(ctx, p):
    fn = UA.get(p["kind"])
    if fn is None:
        return "error", "unknown user_audit kind %s" % p["kind"]
    return fn(ctx)


# A small set of user_audit findings can be fixed safely and deterministically.
@fix("user_audit")
def f_user_audit(ctx, p):
    kind = p["kind"]
    if kind == "sticky_bit":
        dirs = _fs_scan(ctx)["world_dirs"]
        if not dirs:
            return False, "no world-writable dirs without the sticky bit"
        for d in dirs:
            sh(["chmod", "a+t", d], 60)
        ctx.invalidate("fs_scan")
        return True, "added the sticky bit to %d world-writable dir(s)" % len(dirs)
    if kind == "world_writable":
        return f_world_writable(ctx, p)
    if kind == "nologin_locked":
        shadow = {f[0]: f[1] for f in _shadow_entries()}
        done = []
        for f in _passwd_entries():
            name, shell = f[0], f[6]
            if name == "root":
                continue
            if shell.rstrip("/").split("/")[-1] not in ("nologin", "false"):
                continue
            pw = shadow.get(name, "")
            if pw and not pw.startswith(("!", "*")):
                sh(["usermod", "-L", name], 30)
                done.append(name)
        if not done:
            return False, "nothing to change"
        return True, "locked: " + ", ".join(done)
    if kind == "system_shell":
        umin = uid_min()
        done = []
        for f in _passwd_entries():
            name, uid, shell = f[0], as_int(f[2], -1), f[6]
            if name == "root" or uid is None or uid >= umin or uid == 65534:
                continue
            if shell.rstrip("/").split("/")[-1] in ("nologin", "false", "sync",
                                                    "shutdown", "halt", ""):
                continue
            sh(["usermod", "-s", "/usr/sbin/nologin", name], 30)
            done.append(name)
        if not done:
            return False, "nothing to change"
        return True, "set /usr/sbin/nologin on: " + ", ".join(done)
    if kind == "home_dirs":
        done = []
        for e in _interactive_users(ctx):
            if not os.path.isdir(e.pw_dir):
                continue
            os.chmod(e.pw_dir, 0o750)
            sh(["chown", "%d:%d" % (e.pw_uid, e.pw_gid), e.pw_dir], 30)
            done.append(e.pw_name)
        if not done:
            return False, "nothing to change"
        return True, "set 0750 and correct ownership on %d home directory/ies" % len(done)
    if kind == "home_owner":
        done = []
        for e in _interactive_users(ctx):
            if os.path.isdir(e.pw_dir) and os.stat(e.pw_dir).st_uid != e.pw_uid:
                sh(["chown", "%d:%d" % (e.pw_uid, e.pw_gid), e.pw_dir], 30)
                done.append(e.pw_name)
        if not done:
            return False, "nothing to change"
        return True, "fixed ownership of: " + ", ".join(done)
    if kind == "netrc_perm":
        done = []
        for f in _dotfile_scan(ctx, [".netrc"]):
            os.chmod(f, 0o600)
            done.append(f)
        if not done:
            return False, "no .netrc files present"
        return True, "set 0600 on: " + ", ".join(done)
    if kind == "dot_files":
        done = []
        for e in _interactive_users(ctx):
            if not os.path.isdir(e.pw_dir):
                continue
            for f in globmod.glob(os.path.join(e.pw_dir, ".*")):
                if not os.path.isfile(f):
                    continue
                st = os.stat(f)
                if os.path.basename(f) in (".bash_history", ".netrc"):
                    if not mode_ok(st.st_mode, "600"):
                        os.chmod(f, 0o600)
                        done.append(f)
                elif st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    os.chmod(f, st.st_mode & ~(stat.S_IWGRP | stat.S_IWOTH))
                    done.append(f)
        if not done:
            return False, "nothing to change"
        return True, "tightened %d dot file(s)" % len(done)
    if kind == "su_wheel":
        try:
            grp.getgrnam("sugroup")
        except KeyError:
            sh(["groupadd", "sugroup"], 30)
        path = "/etc/pam.d/su"
        backup(ctx, path)
        lines = [l for l in readlines(path)
                 if not re.match(r"^\s*auth\s+required\s+pam_wheel\.so", l)]
        insert = "auth required pam_wheel.so use_uid group=sugroup"
        for i, l in enumerate(lines):
            if l.startswith("auth"):
                lines.insert(i, insert)
                break
        else:
            lines.insert(0, insert)
        write_file(ctx, path, "\n".join(lines).rstrip("\n") + "\n")
        return True, "restricted su to the empty group 'sugroup' in /etc/pam.d/su"
    if kind == "root_path":
        # Create missing directories in root's PATH (e.g. /root/bin)
        rc, o, _ = sh(
            "sudo -Hiu root env 2>/dev/null | grep '^PATH=' || echo \"PATH=$PATH\"",
            60)
        path_str = o.split("=", 1)[1] if "=" in o else ""
        created = []
        for d in path_str.split(":"):
            d = d.strip()
            if not d or d == ".":
                continue
            if not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
                os.chown(d, 0, 0)
                os.chmod(d, 0o755)
                created.append(d)
        if not created:
            return False, "nothing to change"
        return True, "created directories: " + ", ".join(created)
    if kind == "unowned":
        # Assign unowned files to root:root (reuse the shared fs scan)
        paths = _fs_scan(ctx)["unowned"]
        if not paths:
            return False, "no unowned files found"
        done = []
        for f in paths:
            if os.path.lexists(f):
                try:
                    os.chown(f, 0, 0)
                    done.append(os.path.basename(f))
                except OSError:
                    ctx.add_note("cannot chown %s" % f)
        if not done:
            return False, "could not chown any unowned path"
        ctx.invalidate("fs_scan")
        return True, "assigned root:root to %d path(s)" % len(done)
    return False, ("finding requires human judgement (accounts, ownership or data "
                   "loss risk); remediate manually")


# ==========================================================================
# Report-only families
# ==========================================================================

@check("info_only")
def c_info_only(ctx, p):
    if p.get("kind") == "ipv6":
        en = out("sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null", 30)
        state = "disabled" if en.strip() == "1" else "enabled"
        return "manual", "IPv6 is %s on this host; confirm it matches site policy" % state
    return "manual", p.get("note") or "informational only; verify against site policy"


@check("manual")
def c_manual(ctx, p):
    return "manual", "manual assessment required; see the Audit procedure in the benchmark"

# ==========================================================================
# cron / at access control
# ==========================================================================

CRON_ALLOW = [("/etc/cron.allow", "/etc/cron.deny"),
              ("/etc/at.allow", "/etc/at.deny")]


@check("cron_allow")
def c_cron_allow(ctx, p):
    bad = []
    for allow, deny in CRON_ALLOW:
        base = allow.split("/")[-1].split(".")[0]
        if base == "at" and not (pkg_installed("at") or exists("/usr/bin/at")):
            continue
        if exists(deny):
            bad.append("%s still exists" % deny)
        if not exists(allow):
            bad.append("%s does not exist" % allow)
            continue
        u, g, st = owner_of(allow)
        if not mode_ok(st.st_mode, "640"):
            bad.append("%s mode %s" % (allow, fmt_mode(st.st_mode)))
        if u != "root" or g not in ("root", "crontab"):
            bad.append("%s owned by %s:%s" % (allow, u, g))
    if bad:
        return "fail", "; ".join(bad)
    return "pass", "cron/at access is restricted via *.allow (0640 root:root), " \
                   "no *.deny files"


@fix("cron_allow")
def f_cron_allow(ctx, p):
    acts = []
    for allow, deny in CRON_ALLOW:
        base = allow.split("/")[-1].split(".")[0]
        if base == "at" and not (pkg_installed("at") or exists("/usr/bin/at")):
            continue
        if exists(deny):
            backup(ctx, deny)
            os.unlink(deny)
            acts.append("removed " + deny)
        if not exists(allow):
            write_file(ctx, allow, "", 0o640)
            acts.append("created " + allow)
        os.chmod(allow, 0o640)
        sh(["chown", "root:root", allow])
        ctx.add_changed_file(allow)
    return True, "; ".join(acts) or "normalised ownership and permissions"


# ==========================================================================
# PAM remediation via authselect custom profile
# ==========================================================================

CIS_AUTHSELECT_PROFILE = "cis"


def _authselect_current(ctx):
    if not have("authselect"):
        return None, []
    rc, o, _ = sh(["authselect", "current"], 30)
    if rc != 0:
        return None, []
    first = o.splitlines()[0] if o.splitlines() else ""
    m = re.search(r"Profile ID:\s*(\S+)", first) or re.search(r"(\S+/\S+|\S+)\s*$", first)
    prof = m.group(1) if m else None
    feats = re.findall(r"^-\s*(\S+)", o, re.M)
    return prof, feats


def _ensure_custom_profile(ctx):
    """Return the directory of a writable authselect custom profile, or None
    when authselect is not in use (then /etc/pam.d is edited directly)."""
    if not have("authselect"):
        return None
    prof, feats = _authselect_current(ctx)
    if prof and prof.startswith("custom/"):
        return "/etc/authselect/%s" % prof
    base = prof or "sssd"
    rc, o, e = sh(["authselect", "create-profile", CIS_AUTHSELECT_PROFILE,
                   "-b", base, "--symlink-meta"], 60)
    if rc != 0 and "already exists" not in (o + e):
        ctx.add_note("authselect create-profile: %s" % (e or o)[:160])
        return None
    d = "/etc/authselect/custom/%s" % CIS_AUTHSELECT_PROFILE
    if not os.path.isdir(d):
        return None
    rc, o, e = sh(["authselect", "select", "custom/%s" % CIS_AUTHSELECT_PROFILE]
                  + feats + ["--force"], 120)
    if rc != 0:
        ctx.add_note("authselect select: %s" % (e or o)[:160])
    return d


def _pam_edit_targets(ctx):
    targets = []
    d = _ensure_custom_profile(ctx)
    if d:
        for n in ("system-auth", "password-auth"):
            fp = os.path.join(d, n)
            if exists(fp):
                targets.append(fp)
    # Always include PAM_FILES as well — authselect-managed symlinks may
    # have args that the custom profile source does not (e.g. nullok injected
    # by the authselect template compiler).
    for f in PAM_FILES:
        fp = os.path.realpath(f) if exists(f) else f
        if exists(fp) and fp not in targets:
            targets.append(fp)
    if not targets:
        targets = [f for f in PAM_FILES if exists(f)]
    return targets


PAM_APPLY_BACKUP = None  # populated on first apply-changes failure


def _pam_snapshot():
    """Copy the live PAM stack so a failed apply-changes can be rolled back.

    authselect refuses to overwrite files it considers 'unexpectedly
    changed' (TencentOS 3 ships a modified sssd profile) — in that case the
    custom-profile sources we edit and /etc/pam.d can diverge, and a reboot
    would leave sshd unable to authenticate anyone.  Snapshot before editing,
    restore on failure.
    """
    snap = {}
    for f in PAM_FILES:
        rp = os.path.realpath(f) if exists(f) else f
        if exists(rp):
            snap[rp] = read(rp)
    return snap


def _pam_verify():
    """Cheap sanity check that the live PAM stack still has the core modules."""
    txt = ""
    for f in PAM_FILES:
        rp = os.path.realpath(f) if exists(f) else f
        if exists(rp):
            txt += read(rp) or ""
    # pam_unix must survive — without it no password/SSH auth works at all.
    if "pam_unix.so" not in txt:
        return False, "pam_unix.so missing from the live PAM stack"
    if not txt.strip():
        return False, "PAM stack is empty"
    return True, ""


def _pam_apply(ctx):
    if have("authselect"):
        rc, o, e = sh(["authselect", "apply-changes"], 120)
        if rc != 0:
            ctx.add_note("authselect apply-changes: %s" % (e or o)[:200])
            # Roll the live stack back to the pre-edit snapshot so sshd
            # authentication cannot break on reboot.
            global PAM_APPLY_BACKUP
            if PAM_APPLY_BACKUP:
                for path, content in PAM_APPLY_BACKUP.items():
                    try:
                        with open(path, "w", encoding="utf-8") as fh:
                            fh.write(content)
                    except OSError as exc:
                        ctx.add_note("PAM rollback %s: %s" % (path, exc))
                ctx.add_note("PAM rollback applied after apply-changes failure")
            else:
                ctx.add_note("no PAM snapshot to roll back to")
    ok, why = _pam_verify()
    if not ok:
        ctx.add_note("PAM verification failed: %s" % why)
    ctx.invalidate("pam_paths")


PAM_INSERT_HINT = {
    "pam_faillock.so": ("auth", "required", "preauth silent"),
    "pam_pwquality.so": ("password", "requisite", "local_users_only"),
    "pam_pwhistory.so": ("password", "requisite", "use_authtok remember=24"),
    "pam_unix.so": ("password", "sufficient", "sha512 shadow use_authtok"),
    "pam_wheel.so": ("auth", "required", "use_uid"),
}


@fix("pam_module")
def f_pam_module(ctx, p):
    mod = p["module"]
    if have("authselect"):
        featmap = {"pam_faillock.so": "with-faillock",
                   "pam_pwquality.so": "with-pwquality",
                   "pam_pwhistory.so": "with-pwhistory"}
        feat = featmap.get(mod)
        if feat:
            _ensure_custom_profile(ctx)
            rc, o, e = sh(["authselect", "enable-feature", feat], 60)
            if rc == 0:
                _pam_apply(ctx)
                return True, "enabled authselect feature %s" % feat
            ctx.add_note("enable-feature %s: %s" % (feat, (e or o)[:120]))
    global PAM_APPLY_BACKUP
    PAM_APPLY_BACKUP = _pam_snapshot()
    targets = _pam_edit_targets(ctx)
    if not targets:
        return False, "no writable PAM stack found"
    typ, ctrl, args = PAM_INSERT_HINT.get(mod, ("auth", "required", ""))
    n = 0
    for f in targets:
        lines = readlines(f)
        if any(mod in l and not l.lstrip().startswith("#") for l in lines):
            continue
        backup(ctx, f)
        newline = "%-8s %-12s %s %s" % (typ, ctrl, mod, args)
        for i, l in enumerate(lines):
            if l.startswith(typ):
                lines.insert(i, newline.rstrip())
                break
        else:
            lines.append(newline.rstrip())
        write_file(ctx, f, "\n".join(lines).rstrip("\n") + "\n")
        n += 1
    if not n:
        return False, "already present"
    _pam_apply(ctx)
    return True, "added %s to %d PAM file(s)" % (mod, n)


@fix("pam_arg")
def f_pam_arg(ctx, p):
    mod, arg, mode = p["module"], p["arg"], p.get("mode", "present")
    global PAM_APPLY_BACKUP
    PAM_APPLY_BACKUP = _pam_snapshot()
    targets = _pam_edit_targets(ctx)
    if not targets:
        return False, "no writable PAM stack found"
    if mode.startswith("ge:"):
        newarg = "%s=%s" % (arg, mode[3:])
    elif mode in ("present", "flag", "present_any"):
        newarg = arg
    elif mode == "absent":
        newarg = None
    else:
        return False, "unsupported mode %s" % mode
    changed = 0
    for f in targets:
        lines = readlines(f)
        res, hit = [], False
        for l in lines:
            if mod in l and not l.lstrip().startswith("#"):
                base = re.sub(r"\s+%s(=\S+)?" % re.escape(arg), "", l).rstrip()
                if newarg:
                    base = base + " " + newarg
                if base != l:
                    hit = True
                res.append(base)
            else:
                res.append(l)
        if hit:
            backup(ctx, f)
            write_file(ctx, f, "\n".join(res).rstrip("\n") + "\n")
            changed += 1
    if not changed:
        return False, "nothing to change (module line missing?)"
    _pam_apply(ctx)
    # authselect apply-changes regenerates /etc/pam.d from the selected
    # profile.  TencentOS 3 ships a modified sssd profile that authselect
    # refuses to clone, so apply-changes can re-inject the removed arg
    # (nullok) from the stock profile.  Re-apply the edit once more so the
    # final on-disk state is correct regardless.
    if newarg is None:
        for f in PAM_FILES:
            if not exists(f):
                continue
            lines = readlines(f)
            res = []
            for l in lines:
                if mod in l and not l.lstrip().startswith("#"):
                    l = re.sub(r"\s+%s(=\S+)?" % re.escape(arg), "", l).rstrip()
                res.append(l)
            write_file(ctx, f, "\n".join(res).rstrip("\n") + "\n")
    verb = "removed" if newarg is None else "set"
    return True, "%s %s on %s in %d file(s)" % (verb, arg, mod, changed)


@fix("authselect_profile")
def f_authselect_profile(ctx, p):
    if not have("authselect"):
        return False, "authselect is not installed"
    d = _ensure_custom_profile(ctx)
    if not d:
        return False, "unable to create a custom authselect profile"
    return True, "created and selected custom/%s" % CIS_AUTHSELECT_PROFILE

# ==========================================================================
# Host facts (fallback when the engine is run outside Ansible)
# ==========================================================================

def host_facts():
    f = {"hostname": None, "fqdn": None, "ipv4": [], "ipv6": [], "mac": [],
         "default_ipv4": None, "default_mac": None, "os": None, "kernel": None,
         "uptime_seconds": None, "virtualization": None}
    f["hostname"] = out("hostname -s 2>/dev/null || hostname", 20) or os.uname()[1]
    f["fqdn"] = out("hostname -f 2>/dev/null", 20) or f["hostname"]
    f["kernel"] = os.uname().release
    rel = read("/etc/os-release") or ""
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', rel, re.M)
    f["os"] = m.group(1) if m else out("uname -sr", 20)
    try:
        f["uptime_seconds"] = int(float((read("/proc/uptime") or "0").split()[0]))
    except Exception:
        pass
    f["virtualization"] = out("systemd-detect-virt 2>/dev/null || echo unknown", 20)

    ifaces = {}
    txt = out("ip -o addr show 2>/dev/null", 30)
    for ln in txt.splitlines():
        p = ln.split()
        if len(p) < 4:
            continue
        dev, fam, addr = p[1], p[2], p[3].split("/")[0]
        if dev == "lo":
            continue
        d = ifaces.setdefault(dev, {"ipv4": [], "ipv6": [], "mac": None})
        if fam == "inet":
            d["ipv4"].append(addr)
        elif fam == "inet6" and not addr.startswith("fe80"):
            d["ipv6"].append(addr)
    for ln in out("ip -o link show 2>/dev/null", 30).splitlines():
        m = re.match(r"\d+:\s+(\S+?):.*link/ether\s+([0-9a-f:]{17})", ln)
        if m and m.group(1) != "lo":
            ifaces.setdefault(m.group(1), {"ipv4": [], "ipv6": [], "mac": None})
            ifaces[m.group(1)]["mac"] = m.group(2)
    for dev, d in ifaces.items():
        f["ipv4"] += d["ipv4"]
        f["ipv6"] += d["ipv6"]
        if d["mac"]:
            f["mac"].append({"interface": dev, "address": d["mac"]})
    defdev = None
    m = re.search(r"dev\s+(\S+)", out("ip route get 1.1.1.1 2>/dev/null", 20))
    if m:
        defdev = m.group(1)
    if defdev and defdev in ifaces:
        f["default_ipv4"] = (ifaces[defdev]["ipv4"] or [None])[0]
        f["default_mac"] = ifaces[defdev]["mac"]
        f["default_interface"] = defdev
    elif f["ipv4"]:
        f["default_ipv4"] = f["ipv4"][0]
        f["default_mac"] = f["mac"][0]["address"] if f["mac"] else None
    f["interfaces"] = ifaces
    return f


# ==========================================================================
# Selection
# ==========================================================================

def primary_level(rule):
    lv = rule.get("levels") or []
    return min(lv) if lv else 1


def select(rules, profile, platform, include, exclude, sections, families):
    want = {1} if profile == "L1" else {1, 2}
    out_rules, skipped = [], []
    for r in rules:
        lv = set(r.get("levels") or [1])
        rid = r["id"]
        reason = None
        if not (lv & want):
            reason = "level %s not in profile %s" % (sorted(lv), profile)
        elif platform != "all" and r.get("platforms"):
            plats = [p.lower() for p in r["platforms"]]
            if plats and platform.lower() not in plats:
                reason = "applies to %s only" % "/".join(r["platforms"])
        if include and rid not in include and not any(
                rid == i or rid.startswith(i + ".") for i in include):
            reason = "not in the include list"
        if exclude and (rid in exclude or any(
                rid == e or rid.startswith(e + ".") for e in exclude)):
            reason = "explicitly excluded"
        if sections and not any(rid == s or rid.startswith(s + ".") for s in sections):
            reason = "outside the requested sections"
        if families and r["family"] not in families:
            reason = "family not requested"
        if reason:
            skipped.append((r, reason))
        else:
            out_rules.append(r)
    return out_rules, skipped


# ==========================================================================
# Execution
# ==========================================================================

def run_rule(ctx, rule):
    fam = rule["family"]
    params = rule.get("params") or {}
    res = {
        "id": rule["id"],
        "title": rule["title"],
        "section": rule.get("section") or "",
        "levels": rule.get("levels") or [],
        "level": primary_level(rule),
        "assessment": rule.get("assessment") or "Automated",
        "family": fam,
        "risk": rule.get("risk") or "none",
        "page": rule.get("page"),
        "status": "error",
        "detail": "",
        "apply_status": "n/a",
        "apply_detail": "",
        "status_before": None,
        "duration_ms": 0,
    }
    t0 = time.time()
    fn = CHECKS.get(fam)
    if fn is None:
        res["status"] = "manual"
        res["detail"] = "no automated check implemented for family '%s'" % fam
        res["duration_ms"] = int((time.time() - t0) * 1000)
        return res
    try:
        st, detail = fn(ctx, params)
    except Exception as exc:
        st, detail = "error", "%s: %s" % (type(exc).__name__, exc)
    res["status"], res["detail"] = st, detail

    if ctx.opts.mode == "apply" and st == "fail":
        res["status_before"] = "fail"
        ffn = FIXES.get(fam)
        if ffn is None:
            res["apply_status"] = "unsupported"
            res["apply_detail"] = "no automated remediation is available for this rule"
        elif rule.get("risk") == "disruptive" and not ctx.allow_disruptive:
            res["apply_status"] = "skipped_disruptive"
            res["apply_detail"] = ("remediation may interrupt services or require a "
                                   "reboot; re-run with cis_allow_disruptive=true")
        else:
            try:
                ok, adetail = ffn(ctx, params)
            except Exception as exc:
                ok, adetail = False, "%s: %s" % (type(exc).__name__, exc)
            res["apply_detail"] = adetail
            if ok:
                if rule.get("reboot_required"):
                    # Fix wrote config; runtime state only changes after
                    # reboot.  Skip the wasted re-check — the post-reboot
                    # audit will verify everything in one pass.
                    res["apply_status"] = "applied_pending"
                else:
                    try:
                        st2, d2 = fn(ctx, params)
                    except Exception as exc:
                        st2, d2 = "error", str(exc)
                    res["status"], res["detail"] = st2, d2
                    res["apply_status"] = "applied" if st2 == "pass" else "applied_pending"
            else:
                res["apply_status"] = "failed"
    elif ctx.opts.mode == "apply" and st == "pass":
        res["apply_status"] = "already"
    res["duration_ms"] = int((time.time() - t0) * 1000)
    return res


def summarize(results, skipped_count):
    def blank():
        return {"total": 0, "pass": 0, "fail": 0, "manual": 0, "error": 0,
                "notapplicable": 0, "applied": 0, "applied_pending": 0,
                "apply_failed": 0, "skipped_disruptive": 0, "unsupported": 0,
                "already": 0}
    s = {"all": blank(), "L1": blank(), "L2": blank()}
    for r in results:
        buckets = [s["all"], s["L1" if r["level"] == 1 else "L2"]]
        for b in buckets:
            b["total"] += 1
            b[r["status"]] = b.get(r["status"], 0) + 1
            a = r["apply_status"]
            if a in b:
                b[a] += 1
    for b in s.values():
        scored = b["pass"] + b["fail"]
        b["score"] = round(100.0 * b["pass"] / scored, 1) if scored else 0.0
        b["assessed"] = scored
    s["all"]["skipped_by_selection"] = skipped_count
    return s


def main():
    ap = argparse.ArgumentParser(description="CIS benchmark engine")
    ap.add_argument("--catalog", required=True)
    ap.add_argument("--mode", choices=["scan", "apply"], default="scan")
    ap.add_argument("--profile", choices=["L1", "L2"], default="L1")
    ap.add_argument("--platform", choices=["server", "workstation", "all"],
                    default="server")
    ap.add_argument("--include", default="")
    ap.add_argument("--exclude", default="")
    ap.add_argument("--sections", default="")
    ap.add_argument("--families", default="")
    ap.add_argument("--allow-disruptive", action="store_true")
    ap.add_argument("--backup-dir", default="")
    ap.add_argument("--out", default="-")
    ap.add_argument("--benchmark", default="")
    opts = ap.parse_args()

    def csv(x):
        return [i.strip() for i in x.split(",") if i.strip()]

    with open(opts.catalog, "r", encoding="utf-8") as _catalog_fh:
        rules = json.load(_catalog_fh)
    sel, skipped = select(rules, opts.profile, opts.platform,
                          csv(opts.include), csv(opts.exclude),
                          csv(opts.sections), csv(opts.families))

    if opts.mode == "apply" and os.geteuid() != 0:
        sys.stderr.write("apply mode requires root privileges\n")
        sys.exit(2)
    if opts.backup_dir:
        os.makedirs(opts.backup_dir, exist_ok=True)

    ctx = Ctx(opts)
    started = time.time()
    ordered = sorted(sel, key=lambda x: [int(n) for n in x["id"].split(".")])

    try:
        from concurrent.futures import ThreadPoolExecutor
        workers = min(8, max(1, os.cpu_count() or 1))
    except ImportError:                              # pragma: no cover
        workers = 1

    def _in_pool(fn, items):
        if workers > 1:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                return list(pool.map(fn, items))
        return [fn(r) for r in items]

    if opts.mode == "apply":
        # ── Phase 0: Pre-scan (parallel, package-discovery only) ──
        # Only run rules whose family can reveal a missing package.
        # Heavy rules (user_audit/world_writable/file_perm/crypto_policy
        # etc.) can never contribute to Phase 1 batch install — their
        # _fs_scan / authselect / modprobe calls waste 20+ seconds for
        # zero value.  Skipping them cuts Phase 0 from ~30s to ~5s.
        _PKG_FAMILIES = frozenset([
            "pkg_present", "pkg_absent", "pkg_any_present",
            "pkg_not_present", "pkg_not_installed", "pkg_installed",
            "pkg_removed", "pkg_audit", "pkg_firewall", "pkg_password",
            "svc_enabled", "svc_disabled", "svc_masked",
        ])
        pre_rules = [r for r in ordered if r.get("family", "") in _PKG_FAMILIES]
        sys.stderr.write("cis-engine: phase 0 pre-scan (%d rules, %d workers)\n"
                         % (len(pre_rules), workers))
        from argparse import Namespace as _NS
        scan_opts = _NS(**{k: v for k, v in vars(opts).items()})
        scan_opts.mode = "scan"
        ctx_scan = Ctx(scan_opts)
        pre_results = _in_pool(lambda r: run_rule(ctx_scan, r), pre_rules)

        # ── Phase 1: Batch-install missing packages ──
        missing_pkgs = set()
        for r in pre_results:
            if r["status"] == "fail":
                d = r.get("detail", "")
                m = re.search(r"missing:\s*(.+)$", d)
                if m:
                    # detail is "missing: aide, chrony" — split into
                    # individual names; passing the whole string to dnf as
                    # ONE argv element silently matches nothing.
                    for name in m.group(1).split(","):
                        name = name.strip()
                        if name:
                            missing_pkgs.add(name)
                elif ("not installed" in d or "none of" in d
                      or "required package" in d.lower()):
                    # Try to extract package names from comma-separated list
                    for seg in re.findall(r"([\w.-]+)", d):
                        if len(seg) > 2 and seg not in ("not", "installed",
                            "missing", "required", "package", "packages",
                            "none", "of", "s"):
                            missing_pkgs.add(seg)

        if missing_pkgs:
            pkg_list = sorted(missing_pkgs)
            sys.stderr.write("cis-engine: phase 1 installing %d packages: %s\n"
                             % (len(pkg_list), " ".join(pkg_list)))
            rc, o, e = sh(["dnf", "-y", "install"] + pkg_list, 900)
            if rc != 0:
                sys.stderr.write("batch install warning: %s\n" % ((e or o)[:200]))
            _pkg_cache_invalidate()
            _unit_db_invalidate()  # new packages may ship new systemd units

        # ── Phase 2: Parallel apply ──
        # Rules that touch the package manager are serialised via ctx._pkg_lock;
        # all others (config writes, file perms, kernel params, etc.) run in
        # parallel.  Service restarts are deferred to Phase 3.
        sys.stderr.write("cis-engine: phase 2 parallel apply (%d rules, %d workers)\n"
                         % (len(ordered), workers))

        def _apply_one(ctx, rule):
            fam = rule.get("family", "")
            # Only pkg_* families are serialised now (single RPM database /
            # dnf lock).  Shared-file writes (sysctl.conf drop-in, sshd
            # drop-in, fstab, audit rules, ...) are protected by per-path
            # ctx.file_lock() inside the write helpers, so they can run in
            # parallel safely — last-writer-wins races are gone.
            if fam in ("pkg_present", "pkg_not_present", "pkg_any_present",
                       "pkg_not_installed", "pkg_installed", "pkg_removed",
                       "pkg_audit", "pkg_firewall", "pkg_password"):
                with ctx._pkg_lock:
                    return run_rule(ctx, rule)
            return run_rule(ctx, rule)

        results = _in_pool(lambda r: _apply_one(ctx, r), ordered)

        # ── Phase 3: Batch restart queued services ──
        sys.stderr.write("cis-engine: phase 3 flushing %d service restart(s)\n"
                         % len(ctx._svc_queue))
        ctx.flush_restarts()

        # ── Phase 4: Re-check fixed rules (parallel, using original ctx) ──
        # Services have been restarted in Phase 3; rules whose re-check
        # previously failed because the daemon hadn't reloaded should now
        # pass.  We use the original ctx (not a fresh copy) so caches
        # populated during apply are reused — a new Ctx would have empty
        # caches and could mask the fixes.
        to_recheck = [r for r in results
                      if r.get("apply_status") in ("applied", "applied_pending")]
        if to_recheck:
            sys.stderr.write("cis-engine: phase 4 re-checking %d rule(s)\n"
                             % len(to_recheck))
            # Invalidate caches that may be stale after service restarts.
            ctx.invalidate("modprobe_showconfig", "lsmod")

            def _recheck(r):
                fn = CHECKS.get(r["family"])
                if fn:
                    try:
                        st, detail = fn(ctx, r.get("params") or {})
                        r["status"], r["detail"] = st, detail
                    except Exception as exc:                    # pragma: no cover
                        ctx.add_note("re-check %s: %s" % (r["id"], exc))
                return r

            results = _in_pool(_recheck, to_recheck) + \
                      [r for r in results if r.get("apply_status") not in ("applied", "applied_pending")]

    else:
        # scan/audit mode: already parallel
        results = _in_pool(lambda r: run_rule(ctx, r), ordered)
    elapsed = time.time() - started

    doc = {
        "schema": 1,
        "engine_version": VERSION,
        "benchmark": opts.benchmark or os.path.basename(opts.catalog),
        "mode": opts.mode,
        "profile": opts.profile,
        "platform": opts.platform,
        "allow_disruptive": bool(opts.allow_disruptive),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(started)),
        "duration_seconds": round(elapsed, 2),
        "host": host_facts(),
        "summary": summarize(results, len(skipped)),
        "results": results,
        "excluded": [{"id": r["id"], "title": r["title"], "reason": why}
                     for r, why in skipped],
        "changed_files": sorted(set(ctx.changed_files)),
        "engine_notes": ctx.notes,
    }
    payload = json.dumps(doc, indent=1, ensure_ascii=False)
    if opts.out == "-":
        sys.stdout.write(payload)
    else:
        out_dir = os.path.dirname(opts.out)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(opts.out, "w", encoding="utf-8") as fh:
            fh.write(payload)
        sys.stderr.write("wrote %s (%d rules, %.1fs)\n"
                         % (opts.out, len(results), elapsed))


if __name__ == "__main__":
    try:
        main()
    except Exception as _exc:
        import traceback as _tb, json as _json, sys as _sys
        _sys.stderr.write("cis-engine: FATAL — %s: %s\n"
                         % (type(_exc).__name__, _exc))
        _tb.print_exc(file=_sys.stderr)
        _sys.stdout.write(_json.dumps({
            "schema": 1, "engine_version": "1.0.0",
            "mode": "error", "error": str(_exc),
            "results": [{"id": "_fatal_", "title": "engine crash",
                         "status": "error", "detail": str(_exc),
                         "level": 1, "levels": [1], "family": "none",
                         "section": "", "risk": "none",
                         "apply_status": "failed",
                         "apply_detail": "engine crashed before completion",
                         "duration_ms": 0}]
        }, indent=1))
        _sys.exit(1)
