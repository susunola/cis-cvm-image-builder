from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from ._config import PackerResult, ResolvedConfig, _validate_value_present
from ._logging import banner, fail, info, ok, warn
from ._render import _check_ansible_windows_collection, _check_bundled_role, _check_pywinrm
from ._tc_cloud import _check_security_group_ingress

PACKER_TIMEOUT_MINUTES = 120

def run_packer(
    workdir: Path,
    subcmd: str,
    quiet: bool = False,
    capture: bool = False,
    timeout: int | None = None,
    debug: bool = False,
    log_file: str | None = None,
) -> PackerResult:
    """Run `packer init` then `packer <subcmd>` inside *workdir*.

    When *log_file* is given, packer output is also written there (UTF-8,
    line-buffered).  cis-image log messages (ok/fail/info/banner) are handled
    separately via the logger's FileHandler attached in cmd_build.
    """
    if timeout is None:
        timeout = PACKER_TIMEOUT_MINUTES * 60

    env = os.environ.copy()
    if debug:
        env["PACKER_LOG"] = "1"

    hcl_path = "packer/main.pkr.hcl"
    varfile_path = "packer/auto.pkrvars.hcl"

    # Use an ABSOLUTE cwd for every packer subprocess.  A relative cwd is
    # resolved against the parent process's cwd at spawn time; if that cwd is
    # ever removed/recreated mid-build (e.g. rebuild.sh rm -rf + clone), packer
    # inherits a stale cwd and its ansible-local prepare fails with
    # 'stat ansible/site-audit.yml: no such file or directory' even though the
    # file exists in the rendered workdir.
    workdir = Path(workdir).resolve()

    # 1. packer init
    # Plugin downloads can be tens of MB on a slow/proxied link; 60s was
    # too aggressive and produced a misleading "check network" error.
    try:
        init_res = subprocess.run(
            ["packer", "init", hcl_path],
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
    except FileNotFoundError:
        fail("packer not found in PATH. Install from https://developer.hashicorp.com/packer/install")
        return PackerResult(exit_code=1)
    except subprocess.TimeoutExpired:
        fail("packer init timed out (300s). Check network / plugin registry access.")
        return PackerResult(exit_code=1)

    if init_res.returncode != 0:
        combined = (init_res.stdout or "") + (init_res.stderr or "")
        # init output is captured (not streamed) — surface it before failing.
        if combined.strip():
            print(combined.rstrip("\n"), file=sys.stderr)
        fail("packer init failed (see output above).")
        return PackerResult(
            exit_code=init_res.returncode,
            stdout_lines=combined.splitlines(),
        )

    # 2. packer <subcmd>
    cmd = ["packer", subcmd, f"-var-file={varfile_path}", hcl_path]
    try:
        if capture or quiet or log_file:
            # Capture output line-by-line with real-time streaming.  The
            # reader runs on a daemon thread: `for line in proc.stdout`
            # blocks until EOF, so a timeout enforced only via wait()
            # afterwards would never fire while the child keeps the pipe
            # open.  On timeout we kill() explicitly — Popen.__exit__ would
            # otherwise wait() with no timeout and hang forever.
            lines: list[str] = []
            proc = subprocess.Popen(
                cmd, cwd=str(workdir),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, env=env,
            )

            def _reader() -> None:
                assert proc.stdout is not None
                if log_file:
                    with open(log_file, "a", encoding="utf-8") as log_fh:
                        for line in proc.stdout:
                            if not quiet:
                                print(line, end="", file=sys.stderr)
                            log_fh.write(line)
                            lines.append(line.rstrip("\n"))
                else:
                    for line in proc.stdout:
                        if not quiet:
                            print(line, end="", file=sys.stderr)
                        lines.append(line.rstrip("\n"))

            reader = threading.Thread(target=_reader, daemon=True)
            reader.start()
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                reader.join(timeout=10)
                fail(f"packer {subcmd} timed out after {timeout // 60} minutes; "
                     "process killed.")
                return PackerResult(exit_code=1, stdout_lines=lines)
            reader.join(timeout=30)
            return PackerResult(exit_code=proc.returncode, stdout_lines=lines)
        else:
            # Inherit stdout/stderr from parent (live output, no capture).
            # subprocess.run kills the child itself on TimeoutExpired.
            cp = subprocess.run(cmd, cwd=workdir, timeout=timeout, env=env)
            return PackerResult(exit_code=cp.returncode)
    except subprocess.TimeoutExpired:
        fail(f"packer {subcmd} timed out after {timeout // 60} minutes.")
        return PackerResult(exit_code=1)
    except FileNotFoundError:
        fail("packer not found in PATH.")
        return PackerResult(exit_code=1)

def run_preflight(r: ResolvedConfig) -> bool:
    """Run all pre-flight checks. Returns True if everything passes."""
    banner("preflight")
    all_ok = True
    family: str = r.family

    # Credentials
    for env_name in (r.secret_id_env, r.secret_key_env):
        if os.environ.get(env_name):
            ok(f"Credential env var {env_name} is set")
        else:
            fail(f"Credential env var {env_name} is not set (export before running)")
            all_ok = False

    if family == "windows":
        winrm_pass = os.environ.get(r.winrm_password_env)
        if winrm_pass:
            ok(f"WinRM password env var {r.winrm_password_env} is set")
        else:
            fail(f"WinRM password env var {r.winrm_password_env} is not set")
            all_ok = False
        # The password lands in the packer user_data as `net user
        # Administrator '${var.winrm_password}'` — a single quote breaks
        # the PowerShell command and WinRM never comes up ("Timeout waiting
        # for WinRM" with no diagnosable cause).  Enforce the template's
        # documented constraint here instead of at build time.
        if winrm_pass and "'" in winrm_pass:
            fail(f"WinRM password (from {r.winrm_password_env}) contains a "
                 "single quote — it is injected into a PowerShell userdata "
                 "string and would break the build. Remove all ' characters.")
            all_ok = False
        if _check_ansible_windows_collection():
            ok("ansible.windows collection installed")
        else:
            fail("ansible.windows collection not found — install with: "
                 "ansible-galaxy collection install ansible.windows")
            all_ok = False
        if _check_pywinrm():
            ok("pywinrm importable (WinRM transport)")
        else:
            fail("pywinrm not installed for the ansible python — install with: "
                 "pip install pywinrm")
            all_ok = False

    # packer binary
    if shutil.which("packer"):
        ok("packer found in PATH")
    else:
        fail("packer not found in PATH — install from https://developer.hashicorp.com/packer/install")
        all_ok = False

    # Bundled role
    if _check_bundled_role(r.role_dir):
        ok(f"Bundled role '{r.role_dir}' ready ({Path(__file__).parent / 'roles' / r.role_dir})")
    else:
        fail(f"Bundled role directory missing: {r.role_dir}. "
             f"The package may be corrupted — reinstall cis_image.")
        all_ok = False

    # Key parameters
    checks: list[tuple[str, Any]] = [
        ("region", r.region),
        ("zone", r.zone),
        ("instance_type", r.instance_type),
        ("source_image_id", r.source_image_id),
        ("vpc_id", r.vpc_id),
        ("subnet_id", r.subnet_id),
        ("security_group_id", r.security_group_id),
    ]
    for label, val in checks:
        err = _validate_value_present(label, val)
        if err is None:
            ok(f"{label} = {val}")
        else:
            fail(err)
            all_ok = False

    ok(f"profile={r.profile_name} (CIS Level {r.level}, {'winrm' if family == 'windows' else 'ssh'})")

    # P1#4 — benchmark pinning: warn when [meta].benchmark diverges from the
    # profile's default.  The value is embedded in image tags, the report,
    # lineage and provenance — a mismatch silently mislabels the audit.
    profile_bm = str(r.profile.get("benchmark", ""))
    if r.image_benchmark and profile_bm and r.image_benchmark != profile_bm:
        warn(f"[meta].benchmark '{r.image_benchmark}' differs from profile "
             f"default '{profile_bm}' — image tags will carry the override")
    elif not r.image_benchmark:
        warn("[meta].benchmark is empty — image tags/report will not name "
             "the CIS benchmark edition")

    if r.verify_boot and family == "windows":
        warn("[meta].verify_boot is Linux-only — it will be ignored for "
             "Windows builds")

    # Best-effort: catch the #1 support-ticket cause (SG blocks the build
    # port) before Packer burns ~10 minutes on an SSH/WinRM connect timeout.
    _check_security_group_ingress(r)

    if all_ok:
        info("All pre-flight checks passed.")
    else:
        warn("Some pre-flight checks failed — fix before continuing.")
    return all_ok

def _is_interactive(stream: Any = sys.stdin) -> bool:
    """Check if the terminal is interactive (TTY)."""
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False

def _extract_image_ids(stdout_lines: list[str]) -> list[str]:
    """Extract created image IDs from captured packer build output.

    Packer's artifact line looks like:
      Tencentcloud images(ap-guangzhou: img-abc123
      ap-hongkong: img-def456) were created.
    (older builds printed "Created image ID: img-..." — keep that too).

    A single build can create several images (cross-region copies).  The
    old "Created image ID:" lines are collected (not early-returned) so a
    build that mixes both formats still records every image in lineage —
    an early return here silently orphaned the copies (they never age out
    of cleanup-images and bill forever).
    """
    image_ids: list[str] = []
    collecting = False
    for line in stdout_lines:
        if m := re.search(r"Created image ID:\s*(\S+)", line):
            image_ids.append(m.group(1))
        if "Tencentcloud images(" in line:
            collecting = True
        if collecting:
            image_ids += re.findall(r"img-[A-Za-z0-9]+", line)
            if ") were created" in line:
                break
    return list(dict.fromkeys(image_ids))

def _extract_score(stdout_lines: list[str]) -> float | None:
    """Extract the re-audit score (e.g. 'Score: 91.5%') from packer output."""
    for line in stdout_lines:
        if m := re.search(r"Score:\s*(\d+(?:\.\d+)?)\s*%", line):
            return float(m.group(1))
    return None

def _extract_sbom_sha(stdout_lines: list[str]) -> str | None:
    """Extract the SBOM sha256 echoed by the SBOM provisioner (P2#10)."""
    for line in stdout_lines:
        if m := re.search(r"SBOM_SHA256=([0-9a-f]{64})", line):
            return m.group(1)
    return None

def _extract_sbom_count(stdout_lines: list[str]) -> int | None:
    """Extract the SBOM package count echoed by the SBOM provisioner."""
    for line in stdout_lines:
        if m := re.search(r"sbom:\s*(\d+)\s+package", line):
            return int(m.group(1))
    return None

def _last_num(lines: list[str], pattern: str) -> int | None:
    """Return the last integer matching *pattern* across *lines*."""
    val: int | None = None
    for line in lines:
        if m := re.search(pattern, line):
            val = int(m.group(1))
    return val
