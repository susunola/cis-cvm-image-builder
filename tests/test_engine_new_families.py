"""Unit tests for the second wave of manual-rule automation families.

Covers the families added to automate rules the catalogs historically
carried as `manual` (see the per-OS rules.json wiring and CHANGELOG):
kmod_list, gpg_keys, pkg_repos, updates_applied, listening_ports,
nft_rules, iptables_rules, firewalld_rules, ufw_rules, exclusive_stack,
exclusive_logging, timesync_cfg, apparmor, perm_glob, apt_signed_by,
suid_baseline, pkg_verify, rsyslog_actions, audit_rules_valid, plus the
chrony_user (params.user) and user_audit (shadow_group_empty) extensions.

Mocking follows tests/test_engine_tencentos4_fixes.py: engine module
primitives (eng.sh, eng._unit_db, eng._fs_scan, eng.globmod, ...) are
monkeypatched; files live in FakeFs (basename-keyed) with a separate
full-path globber for glob-driven families.
"""

import fnmatch
import types

import pytest

from tests.engine_fixtures import (
    FakeFs,
    apply_fs_mocks,
    load_engine,
    make_ctx,
)


@pytest.fixture(scope="module")
def eng():
    return load_engine("cis-tencentos4")


def _mock_units(monkeypatch, eng, db):
    """Patch the engine's unit snapshot: {unit: (enabled_state, active_state)}."""
    monkeypatch.setattr(eng, "_UNIT_DB", None)
    monkeypatch.setattr(eng, "_unit_db", lambda: dict(db))


def _mock_glob(monkeypatch, eng, paths):
    """Patch eng.globmod.glob to match against the given full paths."""
    paths = sorted(paths)

    def fake_glob(pat):
        return [p for p in paths if fnmatch.fnmatchcase(p, pat)]

    monkeypatch.setattr(eng, "globmod", types.SimpleNamespace(glob=fake_glob))


def _set_files(monkeypatch, eng, fakefs, files):
    """Seed FakeFs with {full_path: content} and wire the globber to match."""
    for path, content in files.items():
        fakefs.set(path, content)
    _mock_glob(monkeypatch, eng, list(files))


def _sh_router(mapping, calls=None):
    """Build a fake sh() from {(cmd-as-tuple-or-str): (rc, out, err)}.

    A None key is the default reply.  List cmds are looked up as tuples."""
    def fake_sh(cmd, timeout=60):
        if calls is not None:
            calls.append(cmd)
        key = cmd if isinstance(cmd, str) else tuple(cmd)
        return mapping.get(key, mapping.get(None, (0, "", "")))
    return fake_sh


# -- kmod_list ---------------------------------------------------------------

_KMOD_SH = None  # set per-test


def _kmod_sh(cmd, timeout=60):
    if cmd == ["modprobe", "--showconfig"]:
        return 0, _KMOD_SH, ""
    if isinstance(cmd, str) and cmd.startswith("lsmod"):
        return 0, "", ""
    if isinstance(cmd, list) and cmd[:3] == ["modprobe", "-n", "-v"]:
        # module exists on the running kernel
        return 0, f"insmod /lib/modules/k/{cmd[3]}.ko", ""
    return 0, "", ""


def test_kmod_list_pass(eng, monkeypatch):
    global _KMOD_SH
    _KMOD_SH = "install cramfs /bin/false\ninstall udf /bin/false\n"
    monkeypatch.setattr(eng, "sh", _kmod_sh)
    monkeypatch.setattr(eng, "have", lambda b: True)
    _mock_glob(monkeypatch, eng, [])
    ctx = make_ctx(eng)
    st, detail = eng.c_kmod_list(ctx, {"modules": ["cramfs", "udf"]})
    assert st == "pass", detail


def test_kmod_list_fail_names_module(eng, monkeypatch):
    global _KMOD_SH
    _KMOD_SH = "install cramfs /bin/false\n"  # udf unblocked
    monkeypatch.setattr(eng, "sh", _kmod_sh)
    monkeypatch.setattr(eng, "have", lambda b: True)
    _mock_glob(monkeypatch, eng, [])
    ctx = make_ctx(eng)
    st, detail = eng.c_kmod_list(ctx, {"modules": ["cramfs", "udf"]})
    assert st == "fail"
    assert "udf" in detail and "cramfs (" not in detail


def test_kmod_list_fix_writes_conf_per_module(eng, monkeypatch):
    global _KMOD_SH
    _KMOD_SH = ""
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    monkeypatch.setattr(eng, "sh", _kmod_sh)
    monkeypatch.setattr(eng, "have", lambda b: True)
    _mock_glob(monkeypatch, eng, [])
    ctx = make_ctx(eng)
    ok, msg = eng.f_kmod_list(ctx, {"modules": ["cramfs", "udf"]})
    assert ok, msg
    assert "install cramfs /bin/false" in fakefs.read("/etc/modprobe.d/cis-cramfs.conf")
    assert "install udf /bin/false" in fakefs.read("/etc/modprobe.d/cis-udf.conf")


def test_kmod_list_errors_without_modules(eng):
    st, _ = eng.c_kmod_list(make_ctx(eng), {})
    assert st == "error"


# -- gpg_keys ------------------------------------------------------------------

def test_gpg_keys_rpm_pass_and_fail(eng, monkeypatch):
    monkeypatch.setattr(eng, "have", lambda b: b == "rpm")
    monkeypatch.setattr(eng, "sh", _sh_router(
        {("rpm", "-q", "gpg-pubkey"): (0, "gpg-pubkey-abcde-12345", "")}))
    st, _ = eng.c_gpg_keys(make_ctx(eng), {})
    assert st == "pass"
    monkeypatch.setattr(eng, "sh", _sh_router(
        {("rpm", "-q", "gpg-pubkey"): (1, "", "package gpg-pubkey is not installed")}))
    st, _ = eng.c_gpg_keys(make_ctx(eng), {})
    assert st == "fail"


def test_gpg_keys_apt(eng, monkeypatch):
    monkeypatch.setattr(eng, "have", lambda b: b == "apt-get")
    _mock_glob(monkeypatch, eng, ["/etc/apt/trusted.gpg.d/vendor.gpg"])
    st, detail = eng.c_gpg_keys(make_ctx(eng), {})
    assert st == "pass", detail
    _mock_glob(monkeypatch, eng, [])
    st, _ = eng.c_gpg_keys(make_ctx(eng), {})
    assert st == "fail"


# -- pkg_repos -----------------------------------------------------------------

def test_pkg_repos_dnf(eng, monkeypatch):
    monkeypatch.setattr(eng, "have", lambda b: b == "dnf")
    monkeypatch.setattr(eng, "sh", _sh_router(
        {("dnf", "repolist", "enabled"):
         (0, "repo id            repo name\ntce-base           TencentOS Base", "")}))
    st, _ = eng.c_pkg_repos(make_ctx(eng), {})
    assert st == "pass"
    monkeypatch.setattr(eng, "sh", _sh_router(
        {("dnf", "repolist", "enabled"): (0, "repo id            repo name", "")}))
    st, _ = eng.c_pkg_repos(make_ctx(eng), {})
    assert st == "fail"


def test_pkg_repos_apt(eng, monkeypatch):
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    monkeypatch.setattr(eng, "have", lambda b: b == "apt-get")
    _set_files(monkeypatch, eng, fakefs,
               {"/etc/apt/sources.list": "deb http://mirrors.tencentyun.com/ubuntu noble main\n"})
    st, _ = eng.c_pkg_repos(make_ctx(eng), {})
    assert st == "pass"
    _set_files(monkeypatch, eng, fakefs,
               {"/etc/apt/sources.list": "# deb http://x noble main\n"})
    st, _ = eng.c_pkg_repos(make_ctx(eng), {})
    assert st == "fail"


def test_pkg_repos_apt_deb822(eng, monkeypatch):
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    monkeypatch.setattr(eng, "have", lambda b: b == "apt-get")
    _set_files(monkeypatch, eng, fakefs,
               {"/etc/apt/sources.list.d/ubuntu.sources":
                "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu\nSuites: noble\n"})
    st, _ = eng.c_pkg_repos(make_ctx(eng), {})
    assert st == "pass"


# -- updates_applied -----------------------------------------------------------

def test_updates_applied_dnf(eng, monkeypatch):
    monkeypatch.setattr(eng, "have", lambda b: b == "dnf")
    monkeypatch.setattr(eng, "sh", _sh_router({("dnf", "check-update"): (0, "", "")}))
    st, _ = eng.c_updates_applied(make_ctx(eng), {})
    assert st == "pass"
    monkeypatch.setattr(eng, "sh", _sh_router(
        {("dnf", "check-update"): (100, "bash.x86_64  5.1.8-9  tce-base", "")}))
    st, detail = eng.c_updates_applied(make_ctx(eng), {})
    assert st == "fail" and "1 update" in detail
    monkeypatch.setattr(eng, "sh", _sh_router(
        {("dnf", "check-update"): (1, "", "repo error")}))
    st, _ = eng.c_updates_applied(make_ctx(eng), {})
    assert st == "error"


def test_updates_applied_apt(eng, monkeypatch):
    monkeypatch.setattr(eng, "have", lambda b: b == "apt-get")
    monkeypatch.setattr(eng, "sh", _sh_router(
        {("apt", "list", "--upgradable"): (0, "Listing...", "")}))
    st, _ = eng.c_updates_applied(make_ctx(eng), {})
    assert st == "pass"
    monkeypatch.setattr(eng, "sh", _sh_router(
        {("apt", "list", "--upgradable"):
         (0, "Listing...\nbash/noble 5.2 amd64 [upgradable from: 5.1]", "")}))
    st, detail = eng.c_updates_applied(make_ctx(eng), {})
    assert st == "fail" and "bash" in detail


def test_updates_applied_fix_runs_full_upgrade(eng, monkeypatch):
    seen = {}

    def fake_sh(cmd, timeout=60):
        seen["cmd"] = cmd
        seen["timeout"] = timeout
        return 0, "", ""

    monkeypatch.setattr(eng, "have", lambda b: b == "dnf")
    monkeypatch.setattr(eng, "sh", fake_sh)
    monkeypatch.setattr(eng, "_pkg_cache_invalidate", lambda: None)
    ok, msg = eng.f_updates_applied(make_ctx(eng), {})
    assert ok, msg
    assert seen["cmd"] == ["dnf", "-y", "update"]
    # generous timeout: a full image update takes far longer than 60s
    assert seen["timeout"] >= 900


def test_updates_applied_fix_apt(eng, monkeypatch):
    seen = {}

    def fake_sh(cmd, timeout=60):
        seen["cmd"] = cmd
        seen["timeout"] = timeout
        return 0, "", ""

    monkeypatch.setattr(eng, "have", lambda b: b == "apt-get")
    monkeypatch.setattr(eng, "sh", fake_sh)
    monkeypatch.setattr(eng, "_pkg_cache_invalidate", lambda: None)
    ok, _ = eng.f_updates_applied(make_ctx(eng), {})
    assert ok
    assert seen["cmd"][:4] == ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y"]
    assert "upgrade" in seen["cmd"]
    assert seen["timeout"] >= 900


# -- listening_ports ------------------------------------------------------------

_SS_CLEAN = (
    "tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    "
    'users:(("sshd",pid=1,fd=3))\n'
    "tcp   LISTEN 0      100        127.0.0.1:3306      0.0.0.0:*    \n"
    "udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*    \n"
)


def _ss_sh(output):
    return _sh_router({("ss", "-H", "-lntup"): (0, output, "")})


def test_listening_ports_pass_ssh_and_loopback(eng, monkeypatch):
    monkeypatch.setattr(eng, "sh", _ss_sh(_SS_CLEAN))
    st, detail = eng.c_listening_ports(make_ctx(eng), {})
    assert st == "pass", detail


def test_listening_ports_fail_lists_offender(eng, monkeypatch):
    out = _SS_CLEAN + ("tcp   LISTEN 0      128          0.0.0.0:9100      "
                       '0.0.0.0:*    users:(("node_exporter",pid=2,fd=3))\n')
    monkeypatch.setattr(eng, "sh", _ss_sh(out))
    st, detail = eng.c_listening_ports(make_ctx(eng), {})
    assert st == "fail"
    assert "9100" in detail and "node_exporter" in detail
    assert "3306" not in detail  # loopback-only listener is fine


def test_listening_ports_allow_ports_param(eng, monkeypatch):
    out = _SS_CLEAN + "tcp   LISTEN 0      128          [::]:9100      [::]:*\n"
    monkeypatch.setattr(eng, "sh", _ss_sh(out))
    st, _ = eng.c_listening_ports(make_ctx(eng), {"allow_ports": [22, 9100]})
    assert st == "pass"


def test_listening_ports_has_no_fixer(eng):
    assert "listening_ports" not in eng.FIXES


# -- nft_rules -------------------------------------------------------------------

_NFT_IN_USE = {"nftables.service": ("enabled", "active")}

_NFT_BASELINE_RULESET = """table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop
        ct state established,related accept
        tcp dport 22 accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        ct state new,established,related accept
    }
}
"""


def _nft_sh(ruleset):
    return _sh_router({("nft", "list", "ruleset"): (0, ruleset, "")})


def test_nft_rules_notapplicable_when_stack_unused(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"firewalld.service": ("enabled", "active")})
    monkeypatch.setattr(eng, "sh", _nft_sh(""))
    st, detail = eng.c_nft_rules(make_ctx(eng), {"kind": "table"})
    assert st == "notapplicable"
    assert "nftables" in detail


@pytest.mark.parametrize("kind", ["table", "base_chains", "loopback",
                                  "established", "default_deny"])
def test_nft_rules_pass_on_baseline(eng, monkeypatch, kind):
    _mock_units(monkeypatch, eng, _NFT_IN_USE)
    monkeypatch.setattr(eng, "sh", _nft_sh(_NFT_BASELINE_RULESET))
    st, detail = eng.c_nft_rules(make_ctx(eng), {"kind": kind})
    assert st == "pass", detail


@pytest.mark.parametrize("kind,breaker,misses", [
    ("table", lambda rs: "", "no nftables table"),
    ("base_chains", lambda rs: rs.replace("hook forward", "hook fwd"), "forward"),
    ("loopback", lambda rs: rs.replace('iifname "lo" accept\n', ""), "lo"),
    ("established", lambda rs: rs.replace("ct state established,related accept\n", ""),
     "established"),
    ("default_deny", lambda rs: rs.replace("policy drop;", "policy accept;"),
     "policy is not drop"),
])
def test_nft_rules_fail_variants(eng, monkeypatch, kind, breaker, misses):
    _mock_units(monkeypatch, eng, _NFT_IN_USE)
    monkeypatch.setattr(eng, "sh", _nft_sh(breaker(_NFT_BASELINE_RULESET)))
    st, detail = eng.c_nft_rules(make_ctx(eng), {"kind": kind})
    assert st == "fail"
    assert misses in detail


def test_nft_rules_flushed(eng, monkeypatch):
    _mock_units(monkeypatch, eng, _NFT_IN_USE)

    def fake_sh(cmd, timeout=60):
        if cmd == ["nft", "list", "ruleset"]:
            return 0, _NFT_BASELINE_RULESET, ""
        if cmd == ["iptables", "-S"]:
            return 0, "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n", ""
        if cmd == ["ip6tables", "-S"]:
            return 0, "-P INPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n", ""
        return 0, "", ""

    monkeypatch.setattr(eng, "have", lambda b: True)
    monkeypatch.setattr(eng, "sh", fake_sh)
    st, detail = eng.c_nft_rules(make_ctx(eng), {"kind": "flushed"})
    assert st == "fail"
    assert "ip6tables" in detail and "iptables:" not in detail


def test_nft_rules_permanent(eng, monkeypatch):
    _mock_units(monkeypatch, eng, _NFT_IN_USE)
    monkeypatch.setattr(eng, "sh", _nft_sh(_NFT_BASELINE_RULESET))
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    _set_files(monkeypatch, eng, fakefs, {
        "/etc/nftables.conf": 'include "/etc/sysconfig/nftables.conf"\n',
        "/etc/sysconfig/nftables.conf": "table inet filter {\n}\n",
    })
    st, _ = eng.c_nft_rules(make_ctx(eng), {"kind": "permanent"})
    assert st == "pass"
    # rules gone from the persisted config -> fail
    fakefs.set("/etc/sysconfig/nftables.conf", "# empty\n")
    st, _ = eng.c_nft_rules(make_ctx(eng), {"kind": "permanent"})
    assert st == "fail"


def test_nft_rules_fix_writes_baseline(eng, monkeypatch):
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    calls = []
    monkeypatch.setattr(eng, "sh", _sh_router({}, calls))
    monkeypatch.setattr(eng, "_detect_ssh_port", lambda: "2222")
    monkeypatch.setattr("os.path.isdir", lambda p: p == "/etc/sysconfig")
    ctx = make_ctx(eng)
    ok, msg = eng.f_nft_rules(ctx, {"kind": "default_deny"})
    assert ok, msg
    written = dict(fakefs.written)  # full paths; FakeFs keys reads by basename
    conf = written["/etc/sysconfig/nftables.conf"]
    assert "policy drop;" in conf
    assert 'iifname "lo" accept' in conf
    assert "tcp dport 2222 accept" in conf
    main = written["/etc/nftables.conf"]
    assert 'include "/etc/sysconfig/nftables.conf"' in main
    assert ["nft", "-f", "/etc/sysconfig/nftables.conf"] in calls
    assert ["systemctl", "enable", "--now", "nftables.service"] in calls


def test_nft_rules_unknown_kind_errors(eng, monkeypatch):
    _mock_units(monkeypatch, eng, _NFT_IN_USE)
    monkeypatch.setattr(eng, "sh", _nft_sh(""))
    st, _ = eng.c_nft_rules(make_ctx(eng), {"kind": "bogus"})
    assert st == "error"


# -- iptables_rules ---------------------------------------------------------------

_IPT_BASELINE = [
    "-P INPUT DROP", "-P FORWARD DROP", "-P OUTPUT DROP",
    "-A INPUT -i lo -j ACCEPT",
    "-A INPUT -s 127.0.0.0/8 -j DROP",
    "-A OUTPUT -o lo -j ACCEPT",
    "-A INPUT -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    "-A OUTPUT -p tcp -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT",
    "-A INPUT -p tcp -m conntrack --ctstate NEW --dport 22 -j ACCEPT",
]


def _ipt_sh(lines, ss_out=""):
    def fake_sh(cmd, timeout=60):
        if cmd == ["iptables", "-S"]:
            return 0, "\n".join(lines), ""
        if cmd == ["ip6tables", "-S"]:
            return 0, "\n".join(ln for ln in lines if "-s 127" not in ln), ""
        if cmd == ["ss", "-H", "-lntup"]:
            return 0, ss_out, ""
        return 0, "", ""
    return fake_sh


def test_iptables_rules_guard_notapplicable(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"nftables.service": ("enabled", "active")})
    monkeypatch.setattr(eng, "sh", _ipt_sh(_IPT_BASELINE))
    st, _ = eng.c_iptables_rules(make_ctx(eng), {"kind": "default_deny"})
    assert st == "notapplicable"


def test_iptables_rules_default_deny(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"iptables.service": ("enabled", "active")})
    monkeypatch.setattr(eng, "sh", _ipt_sh(_IPT_BASELINE))
    st, _ = eng.c_iptables_rules(make_ctx(eng), {"kind": "default_deny"})
    assert st == "pass"
    broken = [ln for ln in _IPT_BASELINE if ln != "-P FORWARD DROP"]
    monkeypatch.setattr(eng, "sh", _ipt_sh(broken))
    st, detail = eng.c_iptables_rules(make_ctx(eng), {"kind": "default_deny"})
    assert st == "fail" and "FORWARD" in detail


def test_iptables_rules_loopback_and_established(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"iptables.service": ("enabled", "active")})
    monkeypatch.setattr(eng, "sh", _ipt_sh(_IPT_BASELINE))
    for kind in ("loopback", "established"):
        st, detail = eng.c_iptables_rules(make_ctx(eng), {"kind": kind})
        assert st == "pass", (kind, detail)
    broken = [ln for ln in _IPT_BASELINE if "-s 127.0.0.0/8" not in ln]
    monkeypatch.setattr(eng, "sh", _ipt_sh(broken))
    st, detail = eng.c_iptables_rules(make_ctx(eng), {"kind": "loopback"})
    assert st == "fail" and "loopback-network" in detail


def test_iptables_rules_open_ports(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"iptables.service": ("enabled", "active")})
    monkeypatch.setattr(eng, "sh", _ipt_sh(_IPT_BASELINE, ss_out=_SS_CLEAN))
    st, detail = eng.c_iptables_rules(make_ctx(eng), {"kind": "open_ports"})
    assert st == "pass", detail
    extra = _SS_CLEAN + "tcp   LISTEN 0      128          0.0.0.0:9100      0.0.0.0:*\n"
    monkeypatch.setattr(eng, "sh", _ipt_sh(_IPT_BASELINE, ss_out=extra))
    st, detail = eng.c_iptables_rules(make_ctx(eng), {"kind": "open_ports"})
    assert st == "fail" and "9100" in detail


def test_iptables_rules_ipv6_uses_ip6tables(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"ip6tables.service": ("enabled", "inactive")})
    monkeypatch.setattr(eng, "sh", _ipt_sh(_IPT_BASELINE))
    st, _ = eng.c_iptables_rules(make_ctx(eng),
                                 {"kind": "default_deny", "ipv6": True})
    assert st == "pass"


def test_iptables_rules_permanent(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"iptables.service": ("enabled", "active")})
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    monkeypatch.setattr(eng, "sh", _ipt_sh(_IPT_BASELINE))
    _set_files(monkeypatch, eng, fakefs,
               {"/etc/sysconfig/iptables": "*filter\n-A INPUT -i lo -j ACCEPT\nCOMMIT\n"})
    st, _ = eng.c_iptables_rules(make_ctx(eng), {"kind": "permanent"})
    assert st == "pass"


def test_iptables_rules_fix_restores_baseline(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"iptables.service": ("disabled", "inactive")})
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    calls = []
    monkeypatch.setattr(eng, "sh", _sh_router({}, calls))
    monkeypatch.setattr(eng, "_detect_ssh_port", lambda: "22")
    monkeypatch.setattr("os.path.isdir", lambda p: p == "/etc/sysconfig")
    ok, msg = eng.f_iptables_rules(make_ctx(eng), {"kind": "default_deny"})
    assert ok, msg
    conf = fakefs.read("/etc/sysconfig/iptables")
    assert conf and ":INPUT DROP" in conf and "COMMIT" in conf
    assert "-A INPUT -s 127.0.0.0/8 -j DROP" in conf
    assert "iptables-restore < /etc/sysconfig/iptables" in calls


# -- firewalld_rules ---------------------------------------------------------------

def _fwd_sh(zones_svcs=None, trusted_ifs=(), rich=None, active_zones=None):
    zones_svcs = zones_svcs or {}
    rich = rich or {}
    active_zones = active_zones if active_zones is not None else list(zones_svcs)

    def fake_sh(cmd, timeout=60):
        if cmd == ["firewall-cmd", "--get-zones"]:
            return 0, "public trusted", ""
        if cmd[:2] == ["firewall-cmd", "--permanent"] and "--list-rich-rules" in cmd:
            zone = next(a.split("=", 1)[1] for a in cmd if a.startswith("--zone="))
            return 0, "\n".join(rich.get(zone, [])), ""
        if cmd == ["firewall-cmd", "--permanent", "--zone=trusted", "--list-interfaces"]:
            return 0, " ".join(trusted_ifs), ""
        if cmd == ["firewall-cmd", "--get-active-zones"]:
            return 0, "".join(z + "\n  interfaces: eth0\n" for z in active_zones), ""
        if "--list-services" in cmd:
            zone = next(a.split("=", 1)[1] for a in cmd if a.startswith("--zone="))
            return 0, " ".join(zones_svcs.get(zone, ([], []))[0]), ""
        if "--list-ports" in cmd:
            zone = next(a.split("=", 1)[1] for a in cmd if a.startswith("--zone="))
            return 0, " ".join(zones_svcs.get(zone, ([], []))[1]), ""
        return 0, "", ""
    return fake_sh


def test_firewalld_rules_guard(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"nftables.service": ("enabled", "active")})
    monkeypatch.setattr(eng, "sh", _fwd_sh())
    st, _ = eng.c_firewalld_rules(make_ctx(eng), {"kind": "loopback"})
    assert st == "notapplicable"


def test_firewalld_rules_inactive_unit_fails_and_fixer_starts_stack(eng, monkeypatch):
    """firewalld installed but not running: fail (not notapplicable) so the
    fixer fires even when parallel apply reaches this rule before
    svc_enabled starts firewalld; the fixer brings the stack up itself."""
    _mock_units(monkeypatch, eng, {"firewalld.service": ("disabled", "inactive")})
    monkeypatch.setattr(eng, "sh", _fwd_sh())
    st, detail = eng.c_firewalld_rules(make_ctx(eng), {"kind": "services"})
    assert st == "fail" and "not active" in detail
    calls = []

    def fake_sh(cmd, timeout=60):
        calls.append(cmd)
        return _fwd_sh(zones_svcs={"public": (["ssh", "mdns"], [])})(cmd, timeout)

    monkeypatch.setattr(eng, "sh", fake_sh)
    ok, msg = eng.f_firewalld_rules(make_ctx(eng), {"kind": "services"})
    assert ok, msg
    assert ["systemctl", "enable", "--now", "firewalld.service"] in calls


def test_firewalld_rules_loopback(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"firewalld.service": ("enabled", "active")})
    monkeypatch.setattr(eng, "sh", _fwd_sh(trusted_ifs=("lo",)))
    st, _ = eng.c_firewalld_rules(make_ctx(eng), {"kind": "loopback"})
    assert st == "pass"
    monkeypatch.setattr(eng, "sh", _fwd_sh(trusted_ifs=()))
    st, _ = eng.c_firewalld_rules(make_ctx(eng), {"kind": "loopback"})
    assert st == "fail"


def test_firewalld_rules_loopback_src(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"firewalld.service": ("enabled", "active")})
    rule = ('rule family=ipv4 source address="127.0.0.1" '
            'destination not address="127.0.0.1" drop')
    monkeypatch.setattr(eng, "sh", _fwd_sh(rich={"trusted": [rule]}))
    st, _ = eng.c_firewalld_rules(make_ctx(eng), {"kind": "loopback_src"})
    assert st == "pass"
    monkeypatch.setattr(eng, "sh", _fwd_sh())
    st, _ = eng.c_firewalld_rules(make_ctx(eng), {"kind": "loopback_src"})
    assert st == "fail"


def test_firewalld_rules_services(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"firewalld.service": ("enabled", "active")})
    monkeypatch.setattr(eng, "sh", _fwd_sh(zones_svcs={"public": (["ssh"], [])}))
    monkeypatch.setattr(eng, "_detect_ssh_port", lambda: "22")
    st, detail = eng.c_firewalld_rules(make_ctx(eng), {"kind": "services"})
    assert st == "pass", detail
    monkeypatch.setattr(eng, "sh",
                        _fwd_sh(zones_svcs={"public": (["ssh", "cockpit"], ["9090/tcp"])}))
    st, detail = eng.c_firewalld_rules(make_ctx(eng), {"kind": "services"})
    assert st == "fail"
    assert "cockpit" in detail and "9090/tcp" in detail


def test_firewalld_rules_fix_loopback(eng, monkeypatch):
    calls = []
    monkeypatch.setattr(eng, "sh", _sh_router({}, calls))
    ok, msg = eng.f_firewalld_rules(make_ctx(eng), {"kind": "loopback"})
    assert ok, msg
    assert ["firewall-cmd", "--permanent", "--zone=trusted",
            "--add-interface=lo"] in calls
    assert ["firewall-cmd", "--reload"] in calls


def test_firewalld_rules_fix_services_removes_extras(eng, monkeypatch):
    calls = []

    def fake_sh(cmd, timeout=60):
        calls.append(cmd)
        if cmd == ["firewall-cmd", "--get-active-zones"]:
            return 0, "public\n  interfaces: eth0\n", ""
        if "--list-services" in cmd:
            return 0, "ssh dhcpv6-client cockpit", ""
        if "--list-ports" in cmd:
            return 0, "9090/tcp", ""
        return 0, "", ""

    monkeypatch.setattr(eng, "sh", fake_sh)
    monkeypatch.setattr(eng, "_detect_ssh_port", lambda: "22")
    ok, msg = eng.f_firewalld_rules(make_ctx(eng), {"kind": "services"})
    assert ok, msg
    assert ["firewall-cmd", "--zone=public", "--remove-service=cockpit",
            "--permanent"] in calls
    assert ["firewall-cmd", "--zone=public", "--remove-port=9090/tcp",
            "--permanent"] in calls
    assert not any("--remove-service=ssh" in " ".join(c) for c in calls)


# -- ufw_rules ---------------------------------------------------------------------

_UFW_STATUS = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
Anywhere on lo             ALLOW IN    Anywhere
Anywhere                   ALLOW OUT   Anywhere on lo (out)
Anywhere                   DENY IN     127.0.0.0/8
22/tcp                     ALLOW IN    Anywhere
"""


def _ufw_sh(status):
    def fake_sh(cmd, timeout=60):
        if cmd == ["ufw", "status"]:
            return 0, "Status: active\n" if status else "Status: inactive\n", ""
        if cmd == ["ufw", "status", "verbose"]:
            return 0, status or "Status: inactive\n", ""
        if cmd == ["ss", "-H", "-lntup"]:
            return 0, _SS_CLEAN, ""
        return 0, "", ""
    return fake_sh


def test_ufw_rules_guard_notapplicable(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {})
    monkeypatch.setattr(eng, "sh", _ufw_sh(None))
    st, _ = eng.c_ufw_rules(make_ctx(eng), {"kind": "default_deny"})
    assert st == "notapplicable"


@pytest.mark.parametrize("kind", ["loopback", "default_deny", "outbound",
                                  "open_ports"])
def test_ufw_rules_pass(eng, monkeypatch, kind):
    _mock_units(monkeypatch, eng, {"ufw.service": ("disabled", "inactive")})
    monkeypatch.setattr(eng, "sh", _ufw_sh(_UFW_STATUS))
    st, detail = eng.c_ufw_rules(make_ctx(eng), {"kind": kind})
    assert st == "pass", detail


def test_ufw_rules_fail_variants(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {})
    no_loop = _UFW_STATUS.replace("Anywhere                   DENY IN     127.0.0.0/8\n", "")
    monkeypatch.setattr(eng, "sh", _ufw_sh(no_loop))
    st, detail = eng.c_ufw_rules(make_ctx(eng), {"kind": "loopback"})
    assert st == "fail" and "127.0.0.0/8" in detail
    monkeypatch.setattr(
        eng, "sh",
        _ufw_sh(_UFW_STATUS.replace("deny (incoming)", "allow (incoming)")))
    st, _ = eng.c_ufw_rules(make_ctx(eng), {"kind": "default_deny"})
    assert st == "fail"


def test_ufw_rules_fix_loopback_enables(eng, monkeypatch):
    calls = []

    def fake_sh(cmd, timeout=60):
        calls.append(cmd)
        if cmd == ["ufw", "status"]:
            return 0, "Status: active\n", ""
        return 0, "", ""

    _mock_units(monkeypatch, eng, {})
    monkeypatch.setattr(eng, "sh", fake_sh)
    monkeypatch.setattr(eng, "_detect_ssh_port", lambda: "22")
    ok, msg = eng.f_ufw_rules(make_ctx(eng), {"kind": "loopback"})
    assert ok, msg
    # SSH management port is whitelisted BEFORE any enable
    assert calls.index(["ufw", "allow", "22/tcp"]) < \
        calls.index(["ufw", "--force", "enable"])
    assert ["ufw", "allow", "in", "on", "lo"] in calls
    assert ["ufw", "deny", "in", "from", "127.0.0.0/8"] in calls


# -- exclusive_stack / exclusive_logging --------------------------------------------

_FW_GROUP = ["firewalld.service", "nftables.service", "iptables.service",
             "ufw.service"]


def test_exclusive_stack(eng, monkeypatch):
    none_in_use = dict.fromkeys(_FW_GROUP, ("disabled", "inactive"))
    _mock_units(monkeypatch, eng, none_in_use)
    ctx = make_ctx(eng)
    st, _ = eng.c_exclusive_stack(ctx, {"group": _FW_GROUP})
    assert st == "fail"  # none in use
    one = dict(none_in_use)
    one["nftables.service"] = ("enabled", "active")
    _mock_units(monkeypatch, eng, one)
    st, detail = eng.c_exclusive_stack(make_ctx(eng), {"group": _FW_GROUP})
    assert st == "pass", detail
    two = dict(one)
    two["firewalld.service"] = ("disabled", "active")
    _mock_units(monkeypatch, eng, two)
    st, detail = eng.c_exclusive_stack(make_ctx(eng), {"group": _FW_GROUP})
    assert st == "fail" and "more than one" in detail
    st, _ = eng.c_exclusive_stack(make_ctx(eng), {})
    assert st == "error"


def test_exclusive_logging(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {
        "rsyslog.service": ("enabled", "active"),
        "syslog-ng.service": ("disabled", "inactive"),
        "systemd-journald.service": ("static", "active"),
    })
    st, detail = eng.c_exclusive_logging(make_ctx(eng), {})
    assert st == "pass", detail
    _mock_units(monkeypatch, eng, {
        "rsyslog.service": ("enabled", "active"),
        "syslog-ng.service": ("enabled", "active"),
    })
    st, detail = eng.c_exclusive_logging(make_ctx(eng), {})
    assert st == "fail" and "syslog-ng" in detail


# -- timesync_cfg ----------------------------------------------------------------------

def test_timesync_cfg_timesyncd(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {})
    st, _ = eng.c_timesync_cfg(make_ctx(eng), {"kind": "timesyncd"})
    assert st == "notapplicable"
    _mock_units(monkeypatch, eng,
                {"systemd-timesyncd.service": ("enabled", "active")})
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    monkeypatch.setattr("os.path.isfile", lambda p: True)  # conf_values gate
    _set_files(monkeypatch, eng, fakefs,
               {"/etc/systemd/timesyncd.conf": "[Time]\nNTP=ntp.example.com\n"})
    st, _ = eng.c_timesync_cfg(make_ctx(eng), {"kind": "timesyncd"})
    assert st == "pass"
    st, _ = eng.c_timesync_cfg(make_ctx(eng),
                               {"kind": "timesyncd", "server": "other.ntp"})
    assert st == "fail"
    fakefs.set("/etc/systemd/timesyncd.conf", "[Time]\n#NTP=\n")
    st, _ = eng.c_timesync_cfg(make_ctx(eng), {"kind": "timesyncd"})
    assert st == "fail"


def test_timesync_cfg_chrony(eng, monkeypatch):
    monkeypatch.setattr(eng, "pkg_installed", lambda p: False)
    st, _ = eng.c_timesync_cfg(make_ctx(eng), {"kind": "chrony"})
    assert st == "notapplicable"
    monkeypatch.setattr(eng, "pkg_installed", lambda p: p == "chrony")
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    _set_files(monkeypatch, eng, fakefs,
               {"/etc/chrony/chrony.conf": "pool ntp.ubuntu.com iburst\n"})
    st, detail = eng.c_timesync_cfg(make_ctx(eng), {"kind": "chrony"})
    assert st == "pass", detail
    st, _ = eng.c_timesync_cfg(make_ctx(eng),
                               {"kind": "chrony", "server": "time.internal"})
    assert st == "fail"


def test_timesync_cfg_fix_chrony_replaces_sources(eng, monkeypatch):
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    _set_files(monkeypatch, eng, fakefs,
               {"/etc/chrony/chrony.conf":
                "pool old.example iburst\nserver 1.2.3.4\n"})
    written = {}

    def fake_atomic(path, content, mode=None, preserve_owner=True):
        written[path] = content
        fakefs.set(path, content)

    monkeypatch.setattr(eng, "atomic_write", fake_atomic)
    ctx = make_ctx(eng)
    ok, msg = eng.f_timesync_cfg(ctx, {"kind": "chrony"})
    assert ok, msg
    final = fakefs.read("/etc/chrony/chrony.conf")
    assert "pool time.cloud.tencent.com iburst" in final
    # set_kv_in_file drops commented variants of the key it manages; other
    # directives (server ...) stay commented out
    assert "old.example" not in final and "# server 1.2.3.4" in final
    assert "chronyd" in ctx.restarts


# -- apparmor ---------------------------------------------------------------------------

def test_apparmor_notapplicable_when_absent(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {})
    monkeypatch.setattr(eng, "pkg_installed", lambda p: False)
    monkeypatch.setattr(eng, "have", lambda b: False)
    st, _ = eng.c_apparmor(make_ctx(eng), {"kind": "enforcing"})
    assert st == "notapplicable"


def test_apparmor_not_disabled(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"apparmor.service": ("enabled", "active")})
    _mock_glob(monkeypatch, eng, ["/etc/apparmor.d/disable/usr.sbin.cupsd"])
    st, detail = eng.c_apparmor(make_ctx(eng), {"kind": "not_disabled"})
    assert st == "fail" and "usr.sbin.cupsd" in detail
    _mock_glob(monkeypatch, eng, [])
    st, _ = eng.c_apparmor(make_ctx(eng), {"kind": "not_disabled"})
    assert st == "pass"


def test_apparmor_enforcing(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"apparmor.service": ("enabled", "active")})
    monkeypatch.setattr(eng, "sh", _sh_router(
        {("aa-status",): (0, "apparmor module is loaded.\n"
                          "14 profiles are in enforce mode.\n"
                          "0 profiles are in complain mode.\n", "")}))
    st, _ = eng.c_apparmor(make_ctx(eng), {"kind": "enforcing"})
    assert st == "pass"
    monkeypatch.setattr(eng, "sh", _sh_router(
        {("aa-status",): (0, "2 profiles are in complain mode.\n", "")}))
    st, detail = eng.c_apparmor(make_ctx(eng), {"kind": "enforcing"})
    assert st == "fail" and "2 profile" in detail


def test_apparmor_fix_removes_disable_links(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"apparmor.service": ("enabled", "active")})
    _mock_glob(monkeypatch, eng, ["/etc/apparmor.d/disable/usr.sbin.cupsd"])
    unlinked = []
    monkeypatch.setattr("os.unlink", unlinked.append)
    ctx = make_ctx(eng)
    ok, msg = eng.f_apparmor(ctx, {"kind": "not_disabled"})
    assert ok, msg
    assert "/etc/apparmor.d/disable/usr.sbin.cupsd" in unlinked
    assert "apparmor" in ctx.restarts


def test_apparmor_fix_enforcing_calls_aa_enforce(eng, monkeypatch):
    _mock_units(monkeypatch, eng, {"apparmor.service": ("enabled", "active")})
    profiles = ["/etc/apparmor.d/usr.sbin.cupsd", "/etc/apparmor.d/usr.bin.man"]
    _mock_glob(monkeypatch, eng, profiles)
    calls = []
    monkeypatch.setattr(eng, "sh", _sh_router({}, calls))
    monkeypatch.setattr("os.path.isfile", lambda p: p in profiles)
    ctx = make_ctx(eng)
    ok, msg = eng.f_apparmor(ctx, {"kind": "enforcing"})
    assert ok, msg
    assert any(c[0] == "aa-enforce" for c in calls)


# -- perm_glob ----------------------------------------------------------------------------

def _fake_owner(mode):
    st = types.SimpleNamespace(st_mode=mode)
    return lambda path: ("root", "root", st)


def test_perm_glob_empty_is_notapplicable(eng, monkeypatch):
    _mock_glob(monkeypatch, eng, [])
    st, _ = eng.c_perm_glob(make_ctx(eng), {"globs": ["/etc/apt/auth.conf.d/*"]})
    assert st == "notapplicable"


def test_perm_glob_mode_owner(eng, monkeypatch):
    paths = ["/etc/apt/auth.conf.d/90netrc", "/etc/apt/auth.conf.d/95other"]
    _mock_glob(monkeypatch, eng, paths)
    monkeypatch.setattr(eng, "owner_of", _fake_owner(0o100600))
    p = {"globs": ["/etc/apt/auth.conf.d/*"], "mode": "600",
         "owner": "root", "group": "root"}
    st, _ = eng.c_perm_glob(make_ctx(eng), p)
    assert st == "pass"
    monkeypatch.setattr(eng, "owner_of", _fake_owner(0o100640))
    st, detail = eng.c_perm_glob(make_ctx(eng), p)
    assert st == "fail" and "0640" in detail


def test_perm_glob_fix(eng, monkeypatch):
    paths = ["/etc/apt/auth.conf.d/90netrc"]
    _mock_glob(monkeypatch, eng, paths)
    chmods = []
    monkeypatch.setattr("os.chmod", lambda p, m: chmods.append((p, m)))
    monkeypatch.setattr(eng, "sh", _sh_router({}))
    ok, msg = eng.f_perm_glob(make_ctx(eng), {"globs": ["/etc/apt/auth.conf.d/*"],
                                              "mode": "600"})
    assert ok, msg
    assert chmods == [("/etc/apt/auth.conf.d/90netrc", 0o600)]


def test_perm_glob_errors_without_globs(eng):
    st, _ = eng.c_perm_glob(make_ctx(eng), {})
    assert st == "error"


# -- apt_signed_by -------------------------------------------------------------------------

def test_apt_signed_by_notapplicable_without_apt(eng, monkeypatch):
    monkeypatch.setattr(eng, "have", lambda b: False)
    st, _ = eng.c_apt_signed_by(make_ctx(eng), {})
    assert st == "notapplicable"


def test_apt_signed_by_list_and_deb822(eng, monkeypatch):
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    monkeypatch.setattr(eng, "have", lambda b: b == "apt-get")
    _set_files(monkeypatch, eng, fakefs, {
        "/etc/apt/sources.list":
            "deb [signed-by=/usr/share/keyrings/a.gpg] http://x noble main\n",
        "/etc/apt/sources.list.d/b.sources":
            "Types: deb\nURIs: http://y\nSuites: noble\n"
            "Signed-By: /usr/share/keyrings/b.gpg\n",
    })
    st, detail = eng.c_apt_signed_by(make_ctx(eng), {})
    assert st == "pass", detail
    fakefs.set("/etc/apt/sources.list", "deb http://x noble main\n")
    st, detail = eng.c_apt_signed_by(make_ctx(eng), {})
    assert st == "fail" and "sources.list" in detail


def test_apt_signed_by_no_sources_fails(eng, monkeypatch):
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    monkeypatch.setattr(eng, "have", lambda b: b == "apt-get")
    _mock_glob(monkeypatch, eng, [])
    st, _ = eng.c_apt_signed_by(make_ctx(eng), {})
    assert st == "fail"


# -- suid_baseline --------------------------------------------------------------------------

def test_suid_baseline(eng, monkeypatch):
    monkeypatch.setattr(eng, "_fs_scan",
                        lambda ctx: {"privileged": ["/usr/bin/su", "/opt/evil"]})
    st, _ = eng.c_suid_baseline(make_ctx(eng),
                                {"allow": ["/usr/bin/su", "/opt/evil"]})
    assert st == "pass"
    st, detail = eng.c_suid_baseline(make_ctx(eng), {"allow": ["/usr/bin/su"]})
    assert st == "fail" and "/opt/evil" in detail


def test_suid_baseline_recorded_mode(eng, monkeypatch):
    """Golden-image mode: no params.allow -> the fixer records the current
    set at params.baseline (default /etc/ohbs-image/suid-baseline.list);
    checks fail on anything not in the recording.  Missing recording:
    fail in apply mode (so the fixer fires), manual in scan mode."""
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    monkeypatch.setattr("os.makedirs", lambda *a, **k: None)
    monkeypatch.setattr(eng, "_fs_scan",
                        lambda ctx: {"privileged": ["/usr/bin/su", "/usr/bin/sudo"]})
    # scan mode, no recording -> manual (honest no-data)
    st, detail = eng.c_suid_baseline(make_ctx(eng, mode="scan"), {})
    assert st == "manual" and "suid-baseline.list" in detail
    # apply mode, no recording -> fail, then the fixer records the set
    st, _ = eng.c_suid_baseline(make_ctx(eng), {})
    assert st == "fail"
    ok, msg = eng.f_suid_baseline(make_ctx(eng), {})
    assert ok, msg
    recorded = fakefs.read("/etc/ohbs-image/suid-baseline.list")
    assert recorded == "/usr/bin/su\n/usr/bin/sudo\n"
    # afterwards the recorded set passes, an extra SUID file fails
    st, _ = eng.c_suid_baseline(make_ctx(eng, mode="scan"), {})
    assert st == "pass"
    monkeypatch.setattr(eng, "_fs_scan",
                        lambda ctx: {"privileged": ["/usr/bin/su", "/opt/evil"]})
    st, detail = eng.c_suid_baseline(make_ctx(eng, mode="scan"), {})
    assert st == "fail" and "/opt/evil" in detail
    # a custom baseline path is honoured
    ok, _ = eng.f_suid_baseline(make_ctx(eng), {"baseline": "/x/base.list"})
    assert ok
    assert fakefs.read("/x/base.list") is not None


def test_suid_baseline_fix_strips_bits(eng, monkeypatch):
    monkeypatch.setattr(eng, "_fs_scan",
                        lambda ctx: {"privileged": ["/usr/bin/su", "/opt/evil"]})
    chmods = []
    monkeypatch.setattr("os.chmod", lambda p, m: chmods.append((p, m)))
    monkeypatch.setattr("os.path.lexists", lambda p: True)
    monkeypatch.setattr("os.stat",
                        lambda p: types.SimpleNamespace(st_mode=0o104755))
    ok, msg = eng.f_suid_baseline(make_ctx(eng), {"allow": ["/usr/bin/su"]})
    assert ok, msg
    assert chmods == [("/opt/evil", 0o100755)]


# -- pkg_verify --------------------------------------------------------------------------------

def test_pkg_verify_rpm(eng, monkeypatch):
    monkeypatch.setattr(eng, "have", lambda b: b == "rpm")
    monkeypatch.setattr(eng, "sh", _sh_router({("rpm", "-Va"): (0, "", "")}))
    st, _ = eng.c_pkg_verify(make_ctx(eng), {})
    assert st == "pass"
    # content drift on config files (S/5/T flags) is fine; M/U/G is not
    monkeypatch.setattr(eng, "sh", _sh_router({("rpm", "-Va"): (
        0, "S.5....T.  c /etc/sysconfig/sshd\n.M.......    /usr/bin/su\n", "")}))
    st, detail = eng.c_pkg_verify(make_ctx(eng), {})
    assert st == "fail" and "/usr/bin/su" in detail and "sshd" not in detail


def test_pkg_verify_dpkg_and_no_tool(eng, monkeypatch):
    monkeypatch.setattr(eng, "have", lambda b: b == "dpkg")
    monkeypatch.setattr(eng, "sh", _sh_router(
        {("dpkg", "--verify"): (0, "??5?????? c /etc/foo\n", "")}))
    st, _ = eng.c_pkg_verify(make_ctx(eng), {})
    assert st == "pass"
    monkeypatch.setattr(eng, "have", lambda b: False)
    st, _ = eng.c_pkg_verify(make_ctx(eng), {})
    assert st == "error"


# -- rsyslog_actions -----------------------------------------------------------------------------

_RSYSLOG_DEFAULT = """\
# comment
module(load="imuxsock")
$FileCreateMode 0640
*.info;mail.none;authpriv.none;cron.none                /var/log/messages
authpriv.*                                              /var/log/secure
"""


def _rsyslog(monkeypatch, eng, fakefs, files):
    apply_fs_mocks(monkeypatch, eng, fakefs)
    monkeypatch.setattr(eng, "pkg_installed", lambda p: p == "rsyslog")
    _set_files(monkeypatch, eng, fakefs, files)


def test_rsyslog_actions_pass_on_distro_default(eng, monkeypatch):
    fakefs = FakeFs()
    _rsyslog(monkeypatch, eng, fakefs, {"/etc/rsyslog.conf": _RSYSLOG_DEFAULT})
    st, detail = eng.c_rsyslog_actions(make_ctx(eng), {})
    assert st == "pass", detail


def test_rsyslog_actions_forwarding_and_action_block(eng, monkeypatch):
    fakefs = FakeFs()
    _rsyslog(monkeypatch, eng, fakefs,
             {"/etc/rsyslog.d/99-remote.conf": "*.* @@loghost.example:514\n"})
    st, _ = eng.c_rsyslog_actions(make_ctx(eng), {})
    assert st == "pass"
    fakefs = FakeFs()
    _rsyslog(monkeypatch, eng, fakefs,
             {"/etc/rsyslog.d/50-default.conf":
              'auth,authpriv.* action(type="omfile" file="/var/log/auth.log")\n'})
    st, _ = eng.c_rsyslog_actions(make_ctx(eng), {})
    assert st == "pass"


def test_rsyslog_actions_fail_when_only_directives(eng, monkeypatch):
    fakefs = FakeFs()
    _rsyslog(monkeypatch, eng, fakefs, {
        "/etc/rsyslog.conf":
            "# *.info /var/log/messages\nmodule(load=\"imuxsock\")\n"
            "$FileCreateMode 0640\ntemplate(name=\"t\" type=\"list\")\n",
    })
    st, _ = eng.c_rsyslog_actions(make_ctx(eng), {})
    assert st == "fail"


def test_rsyslog_actions_notapplicable_without_rsyslog(eng, monkeypatch):
    monkeypatch.setattr(eng, "pkg_installed", lambda p: False)
    st, _ = eng.c_rsyslog_actions(make_ctx(eng), {})
    assert st == "notapplicable"


# -- audit_rules_valid ----------------------------------------------------------------------------

def test_audit_rules_valid(eng, monkeypatch):
    monkeypatch.setattr(eng, "pkg_installed", lambda p: p == "audit")
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    _set_files(monkeypatch, eng, fakefs, {
        "/etc/audit/rules.d/60-cis.rules":
            "-a always,exit -F arch=b64 -S execve -k x\n"
            "-w /etc/passwd -p wa -k identity\n-e 2\n# comment\n",
    })
    st, detail = eng.c_audit_rules_valid(make_ctx(eng), {})
    assert st == "pass", detail
    _set_files(monkeypatch, eng, fakefs, {
        "/etc/audit/rules.d/60-cis.rules":
            "-a always,exit -F arch=b64 -S execve -k x\n-e 2\n",
        "/etc/audit/rules.d/99-bad.rules": "nonsense line here\n",
    })
    st, detail = eng.c_audit_rules_valid(make_ctx(eng), {})
    assert st == "fail" and "99-bad.rules:1" in detail


def test_audit_rules_valid_notapplicable_without_audit(eng, monkeypatch):
    monkeypatch.setattr(eng, "pkg_installed", lambda p: False)
    st, _ = eng.c_audit_rules_valid(make_ctx(eng), {})
    assert st == "notapplicable"


def test_audit_rules_valid_fix_loads(eng, monkeypatch):
    calls = []
    monkeypatch.setattr(eng, "pkg_installed", lambda p: p == "audit")
    monkeypatch.setattr(eng, "sh", _sh_router({}, calls))
    ok, msg = eng.f_audit_rules_valid(make_ctx(eng), {})
    assert ok, msg
    assert ["augenrules", "--load"] in calls


# -- chrony_user params.user extension --------------------------------------------------------------

def test_chrony_user_ubuntu_running_as_chrony_user(eng, monkeypatch):
    monkeypatch.setattr(eng, "pkg_installed", lambda p: p == "chrony")
    monkeypatch.setattr(eng, "sh", _sh_router(
        {"ps -eo user:32,comm 2>/dev/null | awk '$2==\"chronyd\"{print $1}' | sort -u":
         (0, "_chrony", "")}))
    st, detail = eng.c_chrony_user(make_ctx(eng), {"user": "_chrony"})
    assert st == "pass", detail


def test_chrony_user_ubuntu_wrong_user_fails(eng, monkeypatch):
    monkeypatch.setattr(eng, "pkg_installed", lambda p: p == "chrony")
    monkeypatch.setattr(eng, "sh", _sh_router(
        {"ps -eo user:32,comm 2>/dev/null | awk '$2==\"chronyd\"{print $1}' | sort -u":
         (0, "root", "")}))
    st, detail = eng.c_chrony_user(make_ctx(eng), {"user": "_chrony"})
    assert st == "fail" and "root" in detail


def test_chrony_user_ubuntu_not_running_falls_back_to_unit(eng, monkeypatch):
    monkeypatch.setattr(eng, "pkg_installed", lambda p: p == "chrony")
    monkeypatch.setattr(eng, "sh", _sh_router({
        "ps -eo user:32,comm 2>/dev/null | awk '$2==\"chronyd\"{print $1}' | sort -u":
            (0, "", ""),
        "systemctl cat chrony.service chronyd.service 2>/dev/null":
            (0, "[Service]\nUser=_chrony\n", ""),
    }))
    st, _ = eng.c_chrony_user(make_ctx(eng), {"user": "_chrony"})
    assert st == "pass"
    monkeypatch.setattr(eng, "sh", _sh_router({
        "ps -eo user:32,comm 2>/dev/null | awk '$2==\"chronyd\"{print $1}' | sort -u":
            (0, "", ""),
    }))
    st, _ = eng.c_chrony_user(make_ctx(eng), {"user": "_chrony"})
    assert st == "fail"


def test_chrony_user_default_rhel_path_unchanged(eng, monkeypatch):
    monkeypatch.setattr(eng, "pkg_installed", lambda p: p == "chrony")
    fakefs = FakeFs()
    apply_fs_mocks(monkeypatch, eng, fakefs)
    monkeypatch.setattr("os.path.isfile", lambda p: True)  # conf_values gate
    fakefs.set("/etc/sysconfig/chronyd", 'OPTIONS="-F 2 -u chrony"\n')
    monkeypatch.setattr(eng, "sh", _sh_router(
        {"ps -eo user:32,comm 2>/dev/null | awk '$2==\"chronyd\"{print $1}' | sort -u":
         (0, "", "")}))
    st, detail = eng.c_chrony_user(make_ctx(eng), {})
    assert st == "pass", detail


def test_chrony_user_fix_refuses_non_chrony_user(eng, monkeypatch):
    monkeypatch.setattr(eng, "pkg_installed", lambda p: p == "chrony")
    ok, msg = eng.f_chrony_user(make_ctx(eng), {"user": "_chrony"})
    assert not ok and "_chrony" in msg


# -- user_audit shadow_group_empty -------------------------------------------------------------------

def _account_files(monkeypatch, eng, fakefs, group, passwd):
    apply_fs_mocks(monkeypatch, eng, fakefs)
    fakefs.set("/etc/group", group)
    fakefs.set("/etc/passwd", passwd)
    monkeypatch.setattr(eng, "_GROUP_CACHE", None)
    monkeypatch.setattr(eng, "_PASSWD_CACHE", None)


_PASSWD = "root:x:0:0:r:/root:/bin/bash\nalice:x:1000:1000:a:/home/a:/bin/bash\n"


def test_shadow_group_empty(eng, monkeypatch):
    fakefs = FakeFs()
    _account_files(monkeypatch, eng, fakefs,
                   "root:x:0:\nshadow:x:42:\n", _PASSWD)
    st, detail = eng.c_user_audit(make_ctx(eng), {"kind": "shadow_group_empty"})
    assert st == "pass", detail
    fakefs.set("/etc/group", "root:x:0:\nshadow:x:42:alice\n")
    monkeypatch.setattr(eng, "_GROUP_CACHE", None)
    st, detail = eng.c_user_audit(make_ctx(eng), {"kind": "shadow_group_empty"})
    assert st == "fail" and "alice" in detail
    # shadow as a PRIMARY group is just as bad (grants /etc/shadow reads)
    fakefs.set("/etc/group", "root:x:0:\nshadow:x:42:\n")
    fakefs.set("/etc/passwd", _PASSWD + "bob:x:1001:42:b:/home/b:/bin/bash\n")
    monkeypatch.setattr(eng, "_GROUP_CACHE", None)
    monkeypatch.setattr(eng, "_PASSWD_CACHE", None)
    st, detail = eng.c_user_audit(make_ctx(eng), {"kind": "shadow_group_empty"})
    assert st == "fail" and "bob" in detail


def test_shadow_group_empty_no_shadow_group_passes(eng, monkeypatch):
    fakefs = FakeFs()
    _account_files(monkeypatch, eng, fakefs, "root:x:0:\n", _PASSWD)
    st, _ = eng.c_user_audit(make_ctx(eng), {"kind": "shadow_group_empty"})
    assert st == "pass"


def test_shadow_group_empty_fix_gpasswd(eng, monkeypatch):
    fakefs = FakeFs()
    _account_files(monkeypatch, eng, fakefs,
                   "root:x:0:\nshadow:x:42:alice,bob\n", _PASSWD)
    calls = []
    monkeypatch.setattr(eng, "sh", _sh_router({}, calls))
    ok, msg = eng.f_user_audit(make_ctx(eng), {"kind": "shadow_group_empty"})
    assert ok, msg
    assert ["gpasswd", "-d", "alice", "shadow"] in calls
    assert ["gpasswd", "-d", "bob", "shadow"] in calls


def test_shadow_group_empty_fix_refuses_primary_group_move(eng, monkeypatch):
    fakefs = FakeFs()
    _account_files(monkeypatch, eng, fakefs,
                   "root:x:0:\nshadow:x:42:\n",
                   _PASSWD + "bob:x:1001:42:b:/home/b:/bin/bash\n")
    monkeypatch.setattr(eng, "sh", _sh_router({}))
    ok, msg = eng.f_user_audit(make_ctx(eng), {"kind": "shadow_group_empty"})
    assert not ok and "primary group" in msg
