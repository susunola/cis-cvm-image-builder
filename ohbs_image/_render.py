from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import sys
from datetime import UTC
from pathlib import Path
from typing import Any

from ._config import ResolvedConfig
from ._logging import VERSION, ConfigError, info, warn
from ._templates import (
    _BANNER_ART,
    CVE_SCAN_LINUX_BLOCK,
    FINALIZE_SH_TEMPLATE,
    HCL_LINUX_TEMPLATE,
    HCL_WIN_TEMPLATE,
    HOSTS_FIX_SNIPPET,
    IDEMPOTENCY_LINUX_BLOCK,
    INSTALL_SH_TEMPLATE,
    SBOM_LINUX_BLOCK,
    SITE_AUDIT_TEMPLATE,
    SITE_YML_TEMPLATE,
    SITE_YML_WIN_TEMPLATE,
    SMOKE_LINUX_BLOCK,
    SMOKE_WIN_BLOCK,
    TEST_COMPONENTS_LINUX_BLOCK,
    TEST_COMPONENTS_WIN_BLOCK,
)


def _bundle_role(workdir: Path, role_dir: str) -> None:
    """Copy bundled role from roles/<role_dir>/ to workdir/ansible/roles/<role_dir>/."""
    project_root = Path(__file__).parent.resolve()
    src = (project_root / "roles" / role_dir).resolve()

    # Defence-in-depth: ensure the resolved path is within our project roles/ dir.
    # This prevents directory traversal via malformed or unexpected role_dir values.
    roles_root = (project_root / "roles").resolve()
    try:
        src.relative_to(roles_root)
    except ValueError as exc:
        raise ConfigError(
            f"Role directory resolves outside of {roles_root}: {src}. "
            "Refusing to bundle — check the profile's role_dir.") from exc

    if not src.is_dir():
        raise ConfigError(
            f"Bundled role directory not found: {src}. "
            f"The package may be corrupted — reinstall ohbs_image."
        )
    dst = workdir / "ansible" / "roles" / role_dir
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))

def _check_bundled_role(role_dir: str) -> bool:
    """Return True if the bundled role directory exists and is under our project root."""
    project_root = Path(__file__).parent.resolve()
    src = (project_root / "roles" / role_dir).resolve()
    try:
        src.relative_to((project_root / "roles").resolve())
    except ValueError:
        return False
    return src.is_dir()


def _select_workspace_catalog(workdir: Path, role_dir: str, catalog_basename: str) -> None:
    """Promote a benchmark-specific catalog to the workspace rules.json.

    The engine always runs against the workspace ``rules.json``.  For CIS and
    the legacy empty benchmark *catalog_basename* is already ``rules.json`` so
    this is a no-op.  For any other benchmark the active catalog is a
    ``rules_<slug>.json`` file copied by ``_bundle_role``; we copy it over
    ``rules.json`` (overwriting the CIS default) so the engine, overrides and
    the finalize re-scan all resolve the correct benchmark transparently.
    """
    if catalog_basename in ("", "rules.json"):
        return
    files_dir = workdir / "ansible" / "roles" / role_dir / "files"
    src = files_dir / catalog_basename
    if not src.is_file():
        # Catalog not bundled yet — caller (resolve) still validated
        # benchmark; build will surface a missing-catalog error at engine time.
        return
    shutil.copyfile(src, files_dir / "rules.json")


def _check_ansible_windows_collection() -> bool:
    """Return True when the ansible.windows collection is visible to ansible.

    Windows roles run controller-side with win_command/win_copy/win_file —
    without this collection the playbook dies at Gathering Facts with the
    opaque "ansible.legacy.setup was redirected ... could not be loaded".
    """
    try:
        out = subprocess.run(
            ["ansible-galaxy", "collection", "list", "ansible.windows"],
            capture_output=True, text=True, timeout=30,
        )
        return out.returncode == 0 and "ansible.windows" in out.stdout
    except (OSError, subprocess.SubprocessError):
        return False

def _check_pywinrm() -> bool:
    """Return True when pywinrm is importable (WinRM transport for ansible)."""
    try:
        out = subprocess.run(
            [sys.executable, "-c", "import winrm"],
            capture_output=True, timeout=15,
        )
        return out.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False

def _apply_rule_overrides(workdir: Path, role_dir: str,
                          overrides: dict[str, dict[str, Any]]) -> None:
    """Deep-merge [cis].overrides into the WORKSPACE copy of rules.json.

    *overrides* maps CIS rule IDs (e.g. "5.2.2") to a dict of parameter
    values.  Each rule's `params` dict is updated in place — the bundled
    catalog file under ohbs_image/roles/ is never modified.  Rule IDs that
    don't exist in the catalog are rejected loudly (typo = fail fast).
    """
    rules_path = workdir / "ansible" / "roles" / role_dir / "files" / "rules.json"
    try:
        rules = json.loads(rules_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(
            f"[cis].overrides: cannot read bundled rules.json for {role_dir}: "
            f"{exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"[cis].overrides: bundled rules.json for {role_dir} is invalid: "
            f"{exc}") from exc

    by_id: dict[str, dict[str, Any]] = {str(r.get("id", "")): r for r in rules}
    missing = [rid for rid in overrides if rid not in by_id]
    if missing:
        raise ConfigError(
            f"[cis].overrides references unknown rule ID(s): {missing}. "
            f"Valid IDs start with e.g. '1.1.1.1' — run 'ohbs-image list' and "
            f"check the catalog for the exact ID.")

    changed: list[str] = []
    for rid, params in overrides.items():
        rule = by_id[rid]
        cur = rule.get("params")
        if not isinstance(cur, dict):
            rule["params"] = {}
            cur = rule["params"]
        cur.update(params)
        changed.append(rid)
    rules_path.write_text(json.dumps(rules, ensure_ascii=False, indent=1) + "\n",
                          encoding="utf-8")
    info(f"Applied [cis].overrides to {len(changed)} rule(s): "
         f"{', '.join(sorted(changed))}")

def render_finalize(r: ResolvedConfig, p: dict[str, Any],
                    image_name: str | None = None) -> str:
    """Generate ohbs-image-finalize.sh for Linux profiles.

    Substitutes the build's actual metadata into the finalize script.
    image_name comes from _image_name() — the same value Packer uses.
    """
    if image_name is None:
        image_name = _image_name(r)
    return (
        FINALIZE_SH_TEMPLATE
        .replace("__BANNER_ART__", _BANNER_ART)
        .replace("__HOSTS_FIX__", HOSTS_FIX_SNIPPET)
        .replace("__SOURCE_IMAGE__", r.source_image_id)
        .replace("__IMAGE_NAME__", image_name)
        .replace("__IMAGE_OS__", r.image_os_tag)
        .replace("__CIS_LEVEL__", r.cis_level_tag)
        .replace("__IMAGE_BENCHMARK__", r.image_benchmark)
        .replace("__CIS_IMAGE_VERSION__", VERSION)
    )

def _format_hcl_value(value: Any) -> str:
    """Format a Python value as valid HCL."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        # json.dumps escapes quotes/backslashes; valid for HCL string lists.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, dict):
        # HCL object literals are JSON-compatible; used for nested map args
        # (e.g. a data_disks block, image_tags-like maps).
        return json.dumps(value, ensure_ascii=False)
    # Escape backslashes and double quotes so arbitrary strings can't break
    # out of the HCL string literal (or inject HCL).
    text = str(value)
    if "\n" in text:
        raise ConfigError("HCL string values cannot contain newlines")
    if "${" in text or "%%{" in text:
        raise ConfigError("HCL string values cannot contain interpolation sequences (${ or %%{)")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _render_extra_args_block(extra: dict[str, Any]) -> str:
    """Serialize a [build.packer] passthrough dict into HCL source-block lines
    (e.g. `  disk_type = "CLOUD_SSD"`). Empty dict yields "" (the
    __EXTRA_ARGS_BLOCK__ marker is replaced with nothing, matching the
    pre-passthrough behaviour exactly)."""
    lines = [f"  {k} = {_format_hcl_value(v)}" for k, v in extra.items()]
    return ("\n".join(lines) + "\n") if lines else ""

def _image_name(r: ResolvedConfig) -> str:
    """Single source of truth for the image name.

    [image].name, when set, is used verbatim; otherwise the name is
    computed once in Python (24-hour UTC clock) and passed to Packer as a
    plain variable, so the name baked into the in-image banner/motd/report
    always matches the actual image name.  (Packer's own
    `formatdate("YYYYMMDD-hhmmss", timestamp())` used a 12-hour clock and
    evaluated at a different moment, so the two never agreed.)
    """
    if r.image_name_override:
        return r.image_name_override
    from datetime import datetime
    snap_ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    level_short = r.cis_level_tag.replace("-server", "")
    return f"{r.image_name_prefix}-{level_short}-{snap_ts}"

def render_pkrvars(r: ResolvedConfig, image_name: str | None = None) -> str:
    """Generate auto.pkrvars.hcl content."""
    if image_name is None:
        image_name = _image_name(r)
    flat: dict[str, Any] = {
        "region": r.region,
        "zone": r.zone,
        "instance_type": r.instance_type,
        "source_image_id": r.source_image_id,
        "vpc_id": r.vpc_id,
        "subnet_id": r.subnet_id,
        "security_group_id": r.security_group_id,
        "associate_public_ip_address": r.associate_public_ip,
        "image_name_prefix": r.image_name_prefix,
        "image_name": image_name,
        "instance_name": r.instance_name,
        "image_copy_regions": r.image_copy_regions,
        "cis_level": r.cis_level_tag,
        "image_os_tag": r.image_os_tag,
        "image_benchmark": r.image_benchmark,
        "image_catalog": r.catalog_basename,
    }

    if r.family == "windows":
        flat["winrm_username"] = r.winrm_username
    else:
        flat["ssh_username"] = r.ssh_username
        flat["ssh_port"] = r.ssh_port
        flat["ssh_timeout"] = r.ssh_timeout

    return "\n".join(f"{k} = {_format_hcl_value(v)}" for k, v in flat.items()) + "\n"

def render_install(p: dict[str, Any]) -> str:
    """Generate install-ansible.sh for Linux profiles."""
    index_url = str(p.get("pip_index_url", ""))
    index_flag = f"-i {shlex.quote(index_url)}" if index_url else ""
    return (
        INSTALL_SH_TEMPLATE
        .replace("__HOSTS_FIX__", HOSTS_FIX_SNIPPET)
        .replace("__PKG_UPDATE__", str(p.get("pkg_update", "")))
        .replace("__PKG_INSTALL__", str(p.get("pkg_install", "")))
        .replace("__ANSIBLE_CORE_SPEC__", str(p.get("ansible_core_spec", "ansible-core>=2.15")))
        .replace("__CIS_PKG_BATCH_INSTALL__", str(p.get("cis_pkg_batch", "echo '(no CIS packages to pre-install)'")))
        .replace("__PIP_INDEX_FLAG__", index_flag)
    )

def render_site(p: dict[str, Any], level: int, mode: str = "apply",
                rules_include: list[str] | None = None,
                rules_exclude: list[str] | None = None,
                min_score: int = 85) -> str:
    """Generate ansible/site.yml.

    *mode* — "apply" (remediate) or "scan" (audit-only, no changes).
    *rules_include/rules_exclude* — optional rule-id filters forwarded to
    the engine's --include/--exclude (empty list = run all rules).
    *min_score* — gate threshold (Windows applies it in-role; Linux applies
    it in the post-reboot site-audit.yml via render_site_audit).
    """
    cis_level = f"L{level}"
    family = str(p.get("family", ""))

    if family == "windows":
        # Windows has no post-reboot re-audit — the gate lives in the single
        # apply/scan pass, so min_score/mode/include/exclude all land here.
        return (
            SITE_YML_WIN_TEMPLATE
            .replace("__OS_NAME__", str(p["os_tag"]))
            .replace("__CIS_LEVEL__", cis_level)
            .replace("__ROLE_DIR__", str(p["role_dir"]))
            .replace("__CIS_MODE__", mode)
            .replace("__MIN_SCORE__", str(min_score))
            .replace("__CIS_INCLUDE__", _yaml_list(rules_include or []))
            .replace("__CIS_EXCLUDE__", _yaml_list(rules_exclude or []))
        )
    else:
        inc = rules_include or []
        exc = rules_exclude or []
        return (
            SITE_YML_TEMPLATE
            .replace("__OS_NAME__", str(p["os_tag"]))
            .replace("__CIS_LEVEL__", cis_level)
            .replace("__ROLE_DIR__", str(p["role_dir"]))
            .replace("__CIS_MODE__", mode)
            .replace("__CIS_INCLUDE__", _yaml_list(inc))
            .replace("__CIS_EXCLUDE__", _yaml_list(exc))
        )

def _yaml_list(items: list[str]) -> str:
    """Render a Python list as an inline YAML list."""
    if not items:
        return "[]"
    return "[" + ", ".join(json.dumps(x, ensure_ascii=False) for x in items) + "]"

def render_site_audit(p: dict[str, Any], level: int, min_score: int = 85) -> str:
    """Generate ansible/site-audit.yml for post-reboot re-evaluation."""
    cis_level = f"L{level}"
    return (
        SITE_AUDIT_TEMPLATE
        .replace("__OS_NAME__", str(p["os_tag"]))
        .replace("__CIS_LEVEL__", cis_level)
        .replace("__ROLE_DIR__", str(p["role_dir"]))
        .replace("__MIN_SCORE__", str(min_score))
    )

def _assert_no_markers(content: str, filename: str) -> None:
    """Ensure no unreplaced __...__ template markers remain in rendered output."""
    markers = re.findall(r"__[A-Z_]+__", content)
    if markers:
        raise RuntimeError(
            f"Unreplaced markers in {filename}: {', '.join(sorted(set(markers)))}. "
            f"This is a bug — please report it."
        )

def _validate_env_var_name(name: str, field_label: str) -> None:
    """Env var names land inside HCL env("...") — reject anything that
    isn't a plain identifier so a malformed config can't break out of the
    string literal."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ConfigError(
            f"{field_label} must be a valid environment variable name, got {name!r}")

def _validate_shell_arg(value: str, field_label: str) -> None:
    """Values substituted into shell inline scripts must not contain shell
    metacharacters (they are embedded unquoted by design — the inline runs
    as root on the build VM)."""
    if re.search(r"['\"`$\\;|&<>(){}!\n]", value):
        raise ConfigError(
            f"{field_label} contains shell metacharacters: {value!r}. "
            "Use plain letters, digits, dot, dash, underscore only.")

def render_all(workdir: Path, r: ResolvedConfig, scan: bool = False,
               idempotency: bool = False) -> None:
    """Render the complete build directory.

    *scan* — audit-only mode: the engine runs with cis_mode=scan (no
    remediation) and the instance-level smoke test is skipped (the source
    image is not yet hardened, so hardening assertions would fail).
    *idempotency* — Linux only: re-run the apply playbook once more and
    fail the build if the second pass changes anything (Applied/Pending > 0).
    """
    p = r.profile
    family: str = r.family

    (workdir / "packer" / "scripts").mkdir(parents=True, exist_ok=True)
    (workdir / "ansible").mkdir(parents=True, exist_ok=True)

    # 1. Copy bundled role into workspace
    _bundle_role(workdir, r.role_dir)

    # Benchmark-aware catalog selection: for a non-CIS benchmark the active
    # catalog is rules_<slug>.json (copied alongside rules.json by _bundle_role).
    # Promote it to the workspace rules.json so the engine's fixed
    # `--catalog rules.json` path and [cis].overrides both keep working. Pure
    # no-op for CIS (where rules.json already IS the active catalog).
    _select_workspace_catalog(workdir, r.role_dir, r.catalog_basename)

    # P1#5 — [cis].overrides: deep-merge per-rule parameter overrides into
    # the WORKSPACE copy of rules.json (the bundled catalog is never
    # mutated).  Mirrors ansible-lockdown's per-control vars without
    # touching the engine or shipping a second catalog.
    if r.rules_overrides:
        _apply_rule_overrides(workdir, r.role_dir, r.rules_overrides)

    # Computed once — pkrvars, HCL finalize args and the finalize script
    # itself all share this exact image name.
    image_name = _image_name(r)

    # Credential env var names are user-configurable ([cloud].secret_id_env);
    # validate before they land inside HCL env("...") calls.
    _validate_env_var_name(r.secret_id_env, "[cloud].secret_id_env")
    _validate_env_var_name(r.secret_key_env, "[cloud].secret_key_env")
    _validate_env_var_name(r.security_token_env, "[cloud].security_token_env")

    # Values substituted into the finalize inline shell command must be
    # shell-safe (single-quoting happens in the template).
    _validate_shell_arg(r.source_image_id, "[build].source_image_id")
    _validate_shell_arg(image_name, "image name")
    _validate_shell_arg(r.image_os_tag, "[meta].os_tag")
    _validate_shell_arg(r.cis_level_tag, "cis level")
    _validate_shell_arg(r.image_benchmark, "[meta].benchmark")

    # 2. HCL (Linux or Windows template)
    # [cloud].assume_role_arn — group-account CAM role assumption.  Renders a
    # HCL assume_role block when set; empty string renders nothing at all.
    if r.assume_role_arn:
        assume_role_block = (
            '  assume_role {\n'
            f'    role_arn         = "{r.assume_role_arn}"\n'
            f'    session_name     = "{r.assume_role_session}"\n'
            f'    session_duration = {r.assume_role_duration}\n'
            '  }\n'
        )
    else:
        assume_role_block = ""

    # Instance-level smoke test (build → test → distribute): any failure
    # aborts the build before Packer snapshots the image.
    # Linux profiles carry family == "" (only Windows sets "windows").
    # In scan (audit-only) mode the smoke test is skipped — the source image
    # is not yet hardened, so hardening assertions would falsely fail.
    if r.smoke_test and not scan:
        smoke_block = SMOKE_LINUX_BLOCK if family != "windows" else SMOKE_WIN_BLOCK
    else:
        smoke_block = ""

    # Supply-chain gates (Linux only, build mode): CVE scan + SBOM.
    # Spliced right after the smoke test, before the snapshot.
    supply_block = ""
    if not scan and family != "windows":
        if r.cve_scan:
            supply_block += CVE_SCAN_LINUX_BLOCK + "\n"
        if r.sbom:
            supply_block += SBOM_LINUX_BLOCK + "\n"

    # User test components ([meta].test_components) — build mode only.
    # Copy each script into the workdir (packer/scripts/test-components/),
    # upload via file provisioners, then run them sequentially.  A non-zero
    # exit aborts the build before the snapshot (#13).
    test_block = ""
    if not scan and r.test_components:
        tc_dir = workdir / "packer" / "scripts" / "test-components"
        tc_dir.mkdir(parents=True, exist_ok=True)
        # Non-root profiles (ubuntu) cannot write to /root — upload to the
        # ssh user's home instead, mirroring __REMOTE_DIR__ (v0.14.33).
        ssh_user = str(p.get("ssh_username", "root") or "root")
        remote_home = "/root" if ssh_user == "root" else f"/home/{ssh_user}"
        uploads: list[str] = []
        for i, script in enumerate(r.test_components):
            src = Path(script)
            if not src.is_file():
                raise ConfigError(
                    f"[meta].test_components: script not found: {script}")
            # keep the basename; prefix with an index so ordering survives
            # the copy and the packer file-upload naming.
            dest_name = f"{i:02d}-{src.name}"
            shutil.copyfile(src, tc_dir / dest_name)
            if family == "windows":
                uploads.append(
                    f'  provisioner "file" {{\n'
                    f'    source      = "packer/scripts/test-components/{dest_name}"\n'
                    f'    destination = "C:/ohbs-image-test-components/{dest_name}"\n'
                    f'  }}\n')
            else:
                uploads.append(
                    f'  provisioner "file" {{\n'
                    f'    source      = "packer/scripts/test-components/{dest_name}"\n'
                    f'    destination = "{remote_home}/ohbs-image-test-components/{dest_name}"\n'
                    f'  }}\n')
        test_uploads = "".join(uploads)
        runner = TEST_COMPONENTS_WIN_BLOCK if family == "windows" else TEST_COMPONENTS_LINUX_BLOCK
        test_block = test_uploads + runner
        info(f"User test components: {len(r.test_components)} script(s) will "
             f"run before the snapshot")

    # Idempotency verification (Linux only): re-run apply, fail if it changes.
    idempotency_block = IDEMPOTENCY_LINUX_BLOCK if (idempotency and family != "windows") else ""

    # [build].spot — use a spot instance for the ephemeral build VM.  The
    # build machine is short-lived and disposable, so the repossess risk is
    # acceptable and the cost saving (up to ~90% vs on-demand) is real (#15).
    # Packer's tencentcloud plugin accepts instance_charge_type = "SPOTPAID".
    spot_block = '  instance_charge_type = "SPOTPAID"\n' if r.spot else ""

    # [build].packer — user passthrough of arbitrary packer builder args,
    # injected into the source block via the __EXTRA_ARGS_BLOCK__ marker.
    extra_block = _render_extra_args_block(r.packer_extra)

    if family == "windows":
        if r.ssh_debug_password:
            warn("[meta].ssh_debug_password is ignored for Windows profiles "
                 "(it only applies to Linux user_data).")
        _validate_env_var_name(r.winrm_password_env, "[cloud].winrm_password_env")
        hcl = (HCL_WIN_TEMPLATE
               .replace("__WINRM_PASSWORD_ENV__", r.winrm_password_env)
               .replace("__SECRET_ID_ENV__", r.secret_id_env)
               .replace("__SECRET_KEY_ENV__", r.secret_key_env)
               .replace("__SECURITY_TOKEN_ENV__", r.security_token_env)
               .replace("__SMOKE_TEST_BLOCK__", smoke_block)
               .replace("__TEST_COMPONENTS_BLOCK__", test_block)
               .replace("__SPOT_BLOCK__", spot_block)
               .replace("__ASSUME_ROLE_BLOCK__", assume_role_block)
               .replace("__EXTRA_ARGS_BLOCK__", extra_block))
    else:
        # Substitute the build's actual metadata into the finalize provisioner
        # so the in-image banner/report show the right source/level/OS.
        hcl = (HCL_LINUX_TEMPLATE
               .replace("__CLEAN_CMD__", str(p["clean_cmd"]))
               .replace("__VERSION__", VERSION)
               .replace("__SOURCE_IMAGE__", r.source_image_id)
               .replace("__IMAGE_NAME__", image_name)
               .replace("__IMAGE_OS__", r.image_os_tag)
               .replace("__CIS_LEVEL__", r.cis_level_tag)
               .replace("__IMAGE_BENCHMARK__", r.image_benchmark)
               .replace("__IMAGE_CATALOG__", r.catalog_basename)
               .replace("__CIS_IMAGE_VERSION__", VERSION)
               .replace("__CIS_PROFILE_SHORT__", f"L{r.level}")
               .replace("__HOSTS_FIX_HCL__", HOSTS_FIX_SNIPPET.replace('"', '\\"'))
               .replace("__SECRET_ID_ENV__", r.secret_id_env)
               .replace("__SECRET_KEY_ENV__", r.secret_key_env)
               .replace("__SECURITY_TOKEN_ENV__", r.security_token_env)
               .replace("__IDEMPOTENCY_BLOCK__", idempotency_block)
               .replace("__SMOKE_TEST_BLOCK__", smoke_block)
               .replace("__SUPPLY_CHAIN_BLOCK__", supply_block)
               .replace("__TEST_COMPONENTS_BLOCK__", test_block)
               .replace("__SPOT_BLOCK__", spot_block)
               .replace("__ASSUME_ROLE_BLOCK__", assume_role_block)
               .replace("__EXTRA_ARGS_BLOCK__", extra_block)
               # must run AFTER the smoke block is spliced in — the block
               # itself carries __REMOTE_DIR__ placeholders (v0.14.33)
               .replace("__REMOTE_DIR__",
                        "/root" if p.get("ssh_username", "root") == "root"
                        else f"/home/{p['ssh_username']}"))
        user_data = ""
        if r.ssh_debug_password:
            quoted = shlex.quote(f"root:{r.ssh_debug_password}")
            user_data = (
                '  user_data = <<EOF\n'
                '#!/bin/bash\n'
                f"echo {quoted} | chpasswd\n"
                'EOF\n'
            )
        hcl = hcl.replace("__USER_DATA_BLOCK__", user_data)
    _assert_no_markers(hcl, "main.pkr.hcl")
    hcl_path = workdir / "packer" / "main.pkr.hcl"
    hcl_path.write_text(hcl, encoding="utf-8")
    if r.ssh_debug_password:
        # The debug password is embedded in the HCL — restrict permissions.
        hcl_path.chmod(0o600)

    # 3. Vars
    (workdir / "packer" / "auto.pkrvars.hcl").write_text(
        render_pkrvars(r, image_name), encoding="utf-8")

    # 4. Ansible playbooks
    site = render_site(p, r.level, mode="scan" if scan else "apply",
                       rules_include=r.rules_include, rules_exclude=r.rules_exclude,
                       min_score=r.min_score)
    _assert_no_markers(site, "site.yml")
    (workdir / "ansible" / "site.yml").write_text(site, encoding="utf-8")

    if family != "windows":
        site_audit = render_site_audit(p, r.level, r.min_score)
        _assert_no_markers(site_audit, "site-audit.yml")
        (workdir / "ansible" / "site-audit.yml").write_text(site_audit, encoding="utf-8")

    # 5. Install script (Linux only)
    if family != "windows":
        install = render_install(p)
        _assert_no_markers(install, "install-ansible.sh")
        install_path = workdir / "packer" / "scripts" / "install-ansible.sh"
        install_path.write_text(install, encoding="utf-8")
        install_path.chmod(0o755)

    # 6. Finalize script — writes banner + /opt report (Linux only)
    if family != "windows":
        finalize = render_finalize(r, p, image_name)
        _assert_no_markers(finalize, "ohbs-image-finalize.sh")
        finalize_path = workdir / "packer" / "scripts" / "ohbs-image-finalize.sh"
        finalize_path.write_text(finalize, encoding="utf-8")
        finalize_path.chmod(0o755)
