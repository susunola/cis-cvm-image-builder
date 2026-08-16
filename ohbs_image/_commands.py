from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import ohbs_image

from ._audit import _drift_diff, _write_sarif, _write_xccdf
from ._config import ResolvedConfig, load_config, resolve
from ._logging import VERSION, ConfigError, banner, fail, info, logger, ok, warn
from ._packer import (
    _extract_image_ids,
    _extract_sbom_count,
    _extract_sbom_sha,
    _extract_score,
    _is_interactive,
    _last_num,
    run_preflight,
)
from ._profiles import DEFAULT_WORKDIR, PROFILE_NAMES_HELP, PROFILES, SAMPLE_CONFIG
from ._render import _image_name
from ._reports import (
    _find_provenance,
    _save_build_report,
    _send_notification,
)
from ._tc_cloud import (
    _fetch_baseline,
)


def cmd_init(args: argparse.Namespace) -> int:
    """Generate a sample ohbs-image.toml."""
    target = Path(args.target)
    target.mkdir(parents=True, exist_ok=True)
    cfg = target / "ohbs-image.toml"

    if cfg.exists() and not args.force:
        fail(f"{cfg} already exists. Use --force to overwrite.")
        return 1

    cfg.write_text(SAMPLE_CONFIG, encoding="utf-8")

    # Add .gitignore
    gi = target / ".gitignore"
    ignore_lines = [f"{DEFAULT_WORKDIR}/", "ohbs-image.toml", ""]
    if not gi.exists():
        gi.write_text("\n".join(ignore_lines), encoding="utf-8")
    else:
        existing = gi.read_text(encoding="utf-8")
        additions = [line for line in ignore_lines if line and line not in existing.splitlines()]
        if additions:
            gi.write_text(existing.rstrip() + "\n" + "\n".join(additions) + "\n", encoding="utf-8")

    banner("init")
    ok(f"Generated: {cfg}")
    info("Edit ohbs-image.toml: fill in VPC/subnet/SG/source image ID.")
    info("Credentials go in environment variables, never in the config file.")
    info(f"Supported profiles: {PROFILE_NAMES_HELP}")
    info("Then run: ohbs-image preflight / validate / build")
    return 0

def _load_resolve_preflight(config_path: str, workdir: str) -> tuple[ResolvedConfig, Path] | None:
    """Load config, resolve, run preflight. Returns (ResolvedConfig, workdir) or None on failure."""
    try:
        data = load_config(Path(config_path))
        r = resolve(data)
    except ConfigError as exc:
        fail(str(exc))
        return None

    if not run_preflight(r):
        return None

    # v0.16.5: resolve the render dir to an ABSOLUTE path BEFORE rendering.
    # render_all writes into it as given, and run_packer later re-resolves the
    # same Path — if the parent cwd changes between the two (rebuild.sh
    # rm -rf + clone churns the tree), a relative ".ohbs-image-build" resolves to
    # a different directory and packer's ansible-local prepare fails with
    # 'stat ansible/site.yml: no such file' even though the file exists.
    wd = Path(workdir).resolve()
    wd.mkdir(parents=True, exist_ok=True)
    return r, wd

def cmd_preflight(args: argparse.Namespace) -> int:
    """Run pre-flight checks."""
    result = ohbs_image._load_resolve_preflight(args.config, args.workdir)
    return 0 if result is not None else 1

def cmd_validate(args: argparse.Namespace) -> int:
    """Render templates and run packer validate."""
    prep = ohbs_image._load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, workdir = prep

    ohbs_image.render_all(workdir, r)

    banner("validate")
    info(f"Rendered working directory: {workdir}")
    info("Running packer init + packer validate ...")
    result = ohbs_image.run_packer(workdir, "validate", quiet=args.quiet, debug=args.debug)

    # Output is already streamed live by run_packer (or surfaced on init
    # failure); do not re-print result.stdout_lines here.
    if result.exit_code == 0:
        ok("packer validate passed")
    else:
        fail("packer validate failed (see output above)")
    return result.exit_code

def _open_build_log(args: argparse.Namespace) -> logging.FileHandler | None:
    """Attach a file handler to the root logger for --log-file (build only)."""
    if not args.log_file:
        return None
    fh = logging.FileHandler(args.log_file, mode="w", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"))
    logger.addHandler(fh)
    info(f"Build log → {args.log_file}")
    return fh


def _close_build_log(fh: logging.FileHandler | None) -> None:
    """Detach and close the build log handler without leaking it."""
    if fh is not None:
        logger.removeHandler(fh)
        fh.close()


def cmd_build(args: argparse.Namespace) -> int:
    """Render templates and run packer build."""
    prep = ohbs_image._load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, workdir = prep

    # P1#7 — change detection: identical inputs + previous image still
    # exists → skip the rebuild entirely (scheduled-rebuild cost saver).
    if args.skip_if_unchanged:
        prev_fp, prev_images = ohbs_image._last_successful_fingerprint(r)
        if prev_fp is not None and prev_fp == ohbs_image._build_fingerprint(r):
            if ohbs_image._image_ids_still_exist(r.region, prev_images):
                ok(f"inputs unchanged since last build — skipping rebuild "
                   f"(images {', '.join(prev_images) or 'n/a'} still exist)")
                return 0
            warn("inputs unchanged but no prior image still exists — rebuilding")

    ohbs_image.render_all(workdir, r)

    # Confirmation prompt (skip with -y or in non-interactive mode)
    if not args.yes:
        communicator = "winrm" if r.family == "windows" else "ssh"
        info(f"profile     = {r.profile_name}  |  CIS Level {r.level}  |  region {r.region}  |  {communicator}")
        info(f"source image = {r.source_image_id}")
        info(f"instance     = {r.instance_type}")
        if not _is_interactive():
            warn("stdin is not a TTY — assuming non-interactive, proceeding without prompt. "
                 "Use -y/--yes to suppress this message.")
        else:
            try:
                resp = input("  Confirm build? (y/N) ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return 1
            if resp not in ("y", "yes"):
                info("Cancelled.")
                return 0

    banner("build")
    info(f"Rendered working directory: {workdir}")
    info(f"Running packer build (CIS Level {r.level}, profile={r.profile_name}) ...")

    _fh: logging.FileHandler | None = _open_build_log(args)

    result = ohbs_image.run_packer(workdir, "build", quiet=args.quiet, capture=True, debug=args.debug,
                        log_file=args.log_file)

    # Sync file position: run_packer opened its own FD for appending,
    # so _fh's position is stale — seek to end before more logger writes.
    if _fh is not None and _fh.stream is not None:
        _fh.stream.seek(0, 2)

    # Output is already streamed live by run_packer; only scan the captured
    # lines to extract the resulting image ID (do not re-print them).
    image_ids = _extract_image_ids(result.stdout_lines)
    score = _extract_score(result.stdout_lines)
    sbom_sha = _extract_sbom_sha(result.stdout_lines)
    sbom_count = _extract_sbom_count(result.stdout_lines)
    image_name = _image_name(r)
    success = result.exit_code == 0

    if success:
        ok("packer build succeeded")
        if image_ids:
            ok(f"Output image ID(s): {', '.join(image_ids)}")
        else:
            info("Could not parse image ID from output — check the Tencent Cloud console.")
        if score is not None:
            ok(f"Re-audit score: {score:g}%")
        if sbom_sha:
            ok(f"SBOM: {sbom_count or '?'} packages, sha256 {sbom_sha[:16]}…")
        # Build → test → distribute: record lineage + signed provenance
        lin = ohbs_image._record_lineage(r, image_ids, image_name, score, ok=True,
                              sbom_sha=sbom_sha, sbom_count=sbom_count)
        if lin:
            info(f"Lineage recorded -> {lin}")
        prov = ohbs_image._write_provenance(r, image_ids, image_name, score,
                                 sbom_sha=sbom_sha, sbom_count=sbom_count)
        if prov:
            info(f"Provenance written -> {prov}")
        rep = _save_build_report(r, image_name, result.stdout_lines, workdir)
        if rep:
            info(f"Audit report archived -> {rep}")
        # P2#9 — cross-account image sharing (never fails the build).
        # [image].share_org_units (#17) merges into the same call — org
        # sharing uses the identical ModifyImageSharePermission API.
        share_targets = list(dict.fromkeys(
            r.image_share_accounts + r.image_share_org_units))
        if share_targets and image_ids:
            ohbs_image._share_images(r, image_ids, share_targets)
        # P0#3 — clean-boot verification (build → test → distribute).
        # Boot a probe from the produced image and re-audit on fresh boot.
        if r.verify_boot and image_ids:
            if r.family == "windows":
                warn("[meta].verify_boot is Linux-only — skipping "
                     "clean-boot verification for Windows")
            else:
                ok("Clean-boot verification: booting probe instance from "
                   f"{image_ids[0]} …")
                vrc = ohbs_image.cmd_verify_image(args, image_id=image_ids[0])
                if vrc != 0:
                    fail("clean-boot verification FAILED — image not approved")
                    ohbs_image._record_lineage(r, image_ids, image_name, score, ok=False,
                                    sbom_sha=sbom_sha, sbom_count=sbom_count)
                    _send_notification(r, False, image_ids, score, image_name)
                    _close_build_log(_fh)
                    return vrc
    else:
        fail("packer build failed (see output above)")
        ohbs_image._record_lineage(r, image_ids, image_name, score, ok=False,
                        sbom_sha=sbom_sha, sbom_count=sbom_count)

    # [notify] — WeCom webhook; never affects the exit code.
    _send_notification(r, success, image_ids, score, image_name)

    _close_build_log(_fh)
    return result.exit_code

def cmd_images(args: argparse.Namespace) -> int:
    """List recorded builds (lineage) — most recent first."""
    path = ohbs_image._lineage_path()
    if not path.exists():
        info(f"No lineage records yet at {path} — run a build first.")
        return 0
    records: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                records.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
    records.reverse()  # newest first
    limit = getattr(args, "limit", 10)
    if args.latest:
        records = records[:1]
    elif limit > 0:
        records = records[:limit]
    if not records:
        info("No records.")
        return 0
    for rec in records:
        imgs = ", ".join(rec.get("image_ids") or [])
        score = rec.get("score")
        score_s = f"{score:g}%" if score is not None else "-"
        status = rec.get("status", "?")
        print(f"{rec.get('ts', '?'):s}  {status:6s}  L{rec.get('cis_level', '?')}  "
              f"score={score_s:>6s}  {rec.get('image_name', ''):s}  "
              f"src={rec.get('source_image_id', ''):s}  ->  {imgs}")
    return 0

def cmd_check_source(args: argparse.Namespace) -> int:
    """ohbs-image check-source — vendor image refresh detection (#20).

    Queries the source image's CreatedTime and compares it with the last
    build's lineage record.  Exit 0 = source unchanged (no rebuild needed);
    exit 1 = source image has been refreshed → rebuild the golden image.
    Schedule it on a timer alongside 'build --skip-if-unchanged' so a
    vendor OS image update automatically triggers a rebuild.
    """
    prep = ohbs_image._load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, _workdir = prep
    now_created = ohbs_image._source_image_created(r)
    if not now_created:
        warn("Could not query the source image's CreatedTime — cannot "
             "detect a vendor refresh (check credentials/API access)")
        return 0  # fail open: don't force a rebuild on a transient API issue

    prev: str | None = None
    path = ohbs_image._lineage_path()
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rec = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                if (rec.get("status") == "ok"
                        and rec.get("profile") == r.profile_name
                        and rec.get("region") == r.region):
                    prev = rec.get("source_image_created") or None

    banner("check-source")
    info(f"source image : {r.source_image_id}")
    info(f"current      : created {now_created}")
    if prev is None:
        info("no previous build record — rebuild required")
        return 1
    info(f"last build   : created {prev}")
    if prev == now_created:
        ok("source image unchanged since last build — no rebuild needed")
        return 0
    warn("source image has been refreshed — rebuild the golden image "
         "(run 'ohbs-image build')")
    return 1

def cmd_verify_image(args: argparse.Namespace, image_id: str | None = None) -> int:
    """ohbs-image verify-image — clean-boot verification of a produced image.

    Boots a probe instance from *image_id*, runs the bundled engine in
    scan mode (fresh boot — NOT the build instance), gates on --min-score,
    and always terminates the probe instance (even on gate failure).
    When called from cmd_build, *image_id* is passed explicitly.
    """
    prep = ohbs_image._load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, _workdir = prep
    image_id = image_id or getattr(args, "image", "") or ""
    # When driven by 'build --verify-boot', args carries no --min-score —
    # fall back to the config's [cis].min_score, not a hardcoded 85, so the
    # auto-verification gate matches the configured audit gate.
    min_score = float(getattr(args, "min_score", r.min_score or 85))
    if not image_id:
        fail("--image <img-xxx> is required")
        return 1
    if r.family == "windows":
        fail("verify-image boots an SSH probe — Linux images only for now "
             "(Windows images are gated by the in-build re-audit)")
        return 1
    info(f"Launching verification instance from {image_id} "
         f"({r.profile_name} L{r.level}, {r.region}) …")
    instance_id = None
    try:
        try:
            instance_id = ohbs_image._probe_launch(r, image_id, f"ohbs-image-verify-{image_id}")
        except ConfigError as exc:
            fail(str(exc))
            return 1
        ok(f"Probe instance: {instance_id}")
        ip = ohbs_image._probe_public_ip(r, instance_id)
        if not ip:
            fail("Could not get a public IP for the probe instance (timeout)")
            return 1
        ok(f"Probe public IP: {ip}")
        ssh_user = r.ssh_username or "root"
        ssh_port = r.ssh_port or 22
        if not ohbs_image._probe_ssh_ready(ip, ssh_port, ssh_user):
            fail("SSH did not come up on the probe instance (timeout) — "
                 "clean-boot verification failed")
            return 1
        ok("SSH ready on fresh boot")
        doc = ohbs_image._probe_scan(r, ip, ssh_port, ssh_user, r.level)
        if "error" in doc and "summary" not in doc:
            fail(f"Fresh-boot scan failed: {doc.get('error', 'unknown error')}")
            return 1
        score = (doc.get("summary") or {}).get("all", {}).get("score")
        fails = (doc.get("summary") or {}).get("all", {}).get("fail", 0)
        banner("verify-image")
        if score is not None:
            info(f"Fresh-boot scan score: {score:g}% (gate >= {min_score:g}%)")
        info(f"Fresh-boot failing rules: {fails}")
        gate_ok = score is not None and score >= min_score
        if gate_ok:
            ok("clean-boot verification PASSED")
            return 0
        shown = f"{score:g}%" if score is not None else "unknown"
        fail(f"clean-boot verification FAILED: score {shown} < {min_score:g}%")
        return 1
    finally:
        if instance_id:
            ohbs_image._probe_terminate(r, instance_id)

def _drift_resolve_baseline(args: argparse.Namespace, r: ResolvedConfig,
                            host: str, ssh_port: int, ssh_user: str) -> dict[str, Any] | None:
    """Resolve the drift baseline: --image fetch, or --baseline <file>.

    Priority is --baseline <file> (explicit) > --image <id> (fetch from the
    producing image's shipped audit, falling back to a live SSH read).
    Returns None when no baseline could be obtained.
    """
    baseline: dict[str, Any] | None = None
    image_id = getattr(args, "image", "") or ""
    if image_id:
        baseline = _fetch_baseline(r, image_id)
        if baseline is None:
            info("Fetching baseline from the instance's shipped audit "
                 "(/opt/ohbs-image-AUDIT-RESULT.json, written at build time) …")
            remote = "sudo cat /opt/ohbs-image-AUDIT-RESULT.json 2>/dev/null"
            try:
                cp = subprocess.run(
                    ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
                     "-p", str(ssh_port), f"{ssh_user}@{host}", remote],
                    capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                baseline = None
            except FileNotFoundError:
                warn("ssh not found in PATH — cannot fetch the image baseline")
                baseline = None
            else:
                try:
                    baseline = cast("dict[str, Any]", json.loads(cp.stdout))
                except json.JSONDecodeError:
                    baseline = None
        if baseline is None:
            warn("No baseline found — try saving one with "
                 "'ohbs-image drift --save-baseline' or pass --baseline <file>")

    # --baseline <file> overrides everything.
    bl_path = getattr(args, "baseline", "") or ""
    if bl_path and Path(bl_path).exists():
        try:
            baseline = cast("dict[str, Any]",
                            json.loads(Path(bl_path).read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            warn(f"Could not parse baseline file {bl_path}")
            baseline = None
    return baseline


def cmd_drift(args: argparse.Namespace) -> int:
    """ohbs-image drift — detect configuration drift on a running instance.

    Scans a LIVE instance (--host) with the bundled engine and diffs the
    result against the baseline: the audit result shipped inside the
    producing image (--image), or a locally saved baseline.  Reports
    new failures / recovered rules / score delta.  Exit 0 = no drift.
    """
    if getattr(args, "save_baseline", False):
        return cmd_save_baseline(args)
    prep = ohbs_image._load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, _workdir = prep
    host = args.host
    if not host:
        fail("--host <ip> is required (the running instance to check for drift)")
        return 1
    ssh_user = getattr(args, "ssh_user", "") or r.ssh_username or "root"
    ssh_port = int(getattr(args, "ssh_port", 0) or r.ssh_port or 22)

    # 1. Run a live scan on the instance (reuse the same SSH scan as
    #    verify-image — the engine ships inside the image).
    banner("drift")
    info(f"Scanning live instance {host} (profile {r.profile_name} L{r.level}) …")
    current = ohbs_image._probe_scan(r, host, ssh_port, ssh_user, r.level)
    if "error" in current and "summary" not in current:
        fail(f"Live scan failed: {current.get('error', 'unknown error')}")
        return 1
    cs = (current.get("summary") or {}).get("all", {})
    info(f"Live score: {cs.get('score', '?')}%  "
         f"(fail {cs.get('fail', 0)}, pass {cs.get('pass', 0)})")

    # 2. Baseline: --baseline <file> overrides, else fetch from --image.
    baseline = _drift_resolve_baseline(args, r, host, ssh_port, ssh_user)
    if baseline is None:
        fail("No baseline to compare against — pass --image <id>, "
             "--baseline <file>, or run 'ohbs-image drift --save-baseline' first")
        return 1

    # 3. Diff + report.
    diff = _drift_diff(baseline, current)
    bs = (baseline.get("summary") or {}).get("all", {})
    # Explicit None checks: `or` would silently discard a legitimate 0 score
    # (an engine result where every rule fails).
    bscore = diff["baseline_score"] if diff["baseline_score"] is not None else bs.get("score")
    cscore = diff["current_score"] if diff["current_score"] is not None else cs.get("score")
    if bscore is not None:
        info(f"Baseline score: {bscore:g}%")
    delta = ""
    if bscore is not None and cscore is not None:
        d = round(float(cscore) - float(bscore), 1)
        delta = f"  ({'+' if d > 0 else ''}{d:g} pts)"
        info(f"Score delta: {delta}")
    if diff["new_failures"]:
        warn(f"DRIFT: {len(diff['new_failures'])} rule(s) now failing that "
             f"were not before:")
        for rid in diff["new_failures"]:
            fail(f"  ✗ {rid}")
    else:
        ok("No new failing rules")
    if diff["recovered"]:
        ok(f"Recovered: {len(diff['recovered'])} rule(s) now passing")
        for rid in diff["recovered"][:10]:
            ok(f"  ✓ {rid}")

    # 4. Gate: exit 1 when there is real drift (new failures).
    if diff["new_failures"]:
        fail(f"DRIFT DETECTED — {len(diff['new_failures'])} new failing "
             f"rule(s) on {host}")
        return 1
    ok(f"No drift detected on {host}")
    return 0

def cmd_save_baseline(args: argparse.Namespace) -> int:
    """ohbs-image drift --save-baseline — persist the current host scan as a baseline."""
    prep = ohbs_image._load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, _workdir = prep
    host = args.host
    if not host:
        fail("--host <ip> is required to save a baseline")
        return 1
    ssh_user = getattr(args, "ssh_user", "") or r.ssh_username or "root"
    ssh_port = int(getattr(args, "ssh_port", 0) or r.ssh_port or 22)
    doc = ohbs_image._probe_scan(r, host, ssh_port, ssh_user, r.level)
    if "error" in doc and "summary" not in doc:
        fail(f"Scan failed: {doc.get('error', 'unknown error')}")
        return 1
    image_id = getattr(args, "image", "") or "current"
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", image_id) or "current"
    out = ohbs_image._lineage_path().parent / "baselines" / f"{safe}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n",
                   encoding="utf-8")
    ok(f"Baseline saved -> {out}")
    return 0

def _retire_cleanup_images(path: Path, retired_ids: set[str]) -> None:
    """Rewrite the lineage file, removing *retired_ids* at per-image granularity.

    A lineage record can hold several image_ids (cross-region copies).
    Removing ONE of them must NOT retire the whole record — otherwise the
    surviving copies are dropped from the cleanup set forever (they never age
    out) and check-source/pending treat the record as gone.  Only mark a record
    retired when it has no images left.

    The rewrite is ATOMIC (temp file + os.replace) and preserves any line
    that fails to parse: lineage is the only durable record of what was
    built, so a single corrupt line must not be silently erased.
    """
    retired_ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rec = json.loads(ln)
            except json.JSONDecodeError:
                lines.append(ln)  # keep the corrupt line verbatim
                continue
            ids = list(rec.get("image_ids", []))
            if ids and not rec.get("retired"):
                remaining = [i for i in ids if i not in retired_ids]
                if len(remaining) != len(ids):
                    rec["image_ids"] = remaining
                    if not remaining:
                        rec["retired"] = True
                        rec["retired_ts"] = retired_ts
            lines.append(json.dumps(rec, ensure_ascii=False))
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def cmd_cleanup_images(args: argparse.Namespace) -> int:
    """Retire old golden images by lineage age. Dry-run by default.

    *--unused-since N* (#16): additionally require the image to be
    UNshared (cvm:DescribeImageSharePermission returns no shares) — an
    image shared with other accounts is presumed in use downstream and is
    skipped, so cleanup never breaks a running consumer.  Fails open
    (keeps the image) when the share query errors.
    """
    path = ohbs_image._lineage_path()
    if not path.exists():
        info(f"No lineage records at {path} — nothing to clean.")
        return 0

    records: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                records.append(json.loads(ln))
            except json.JSONDecodeError:
                continue

    ok_recs = [r for r in records if r.get("status") == "ok" and not r.get("retired")]
    ok_recs.sort(key=lambda r: r.get("ts", ""))  # oldest first

    keep = max(0, int(getattr(args, "keep_latest", 1)))
    older_than = max(1, int(getattr(args, "older_than", 30)))
    unused_since = max(0, int(getattr(args, "unused_since", 0)))
    cutoff = datetime.now(UTC).timestamp() - older_than * 86400

    candidates: list[tuple[dict[str, Any], str]] = []  # (record, image_id)
    for i, rec in enumerate(ok_recs):
        if len(ok_recs) - i <= keep:
            continue  # keep the newest N builds
        try:
            ts = datetime.strptime(rec.get("ts", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
        except ValueError:
            continue
        if ts > cutoff:
            continue
        for img in rec.get("image_ids", []):
            candidates.append((rec, img))

    # --unused-since: drop candidates whose image is still shared (in use).
    if unused_since:
        kept_shared = 0
        filtered: list[tuple[dict[str, Any], str]] = []
        for rec, img in candidates:
            if ohbs_image._image_is_shared(rec.get("region", ""), img):
                kept_shared += 1
                info(f"  {rec.get('region', '?')}: {img} is still shared "
                     "(in use downstream) — kept")
            else:
                filtered.append((rec, img))
        candidates = filtered
        if kept_shared:
            info(f"{kept_shared} shared image(s) kept (--unused-since)")

    if not candidates:
        ok(f"No images older than {older_than} days to retire (keeping {keep} latest).")
        return 0

    info(f"{len(candidates)} image(s) older than {older_than} days, keeping {keep} latest:")
    # group candidates by region for API calls
    by_region: dict[str, list[str]] = {}
    for rec, img in candidates:
        by_region.setdefault(rec.get("region", ""), []).append(img)

    # --apply: delete candidates; even if one delete fails, the images
    # already deleted must still be retired from lineage (otherwise they
    # stay recorded forever and re-cleanup keeps re-trying them).
    deleted_ids: set[str] = set()
    delete_error: str | None = None
    total_deleted = 0
    for region, imgs in sorted(by_region.items()):
        for img in sorted(set(imgs)):
            if args.apply:
                try:
                    existing = ohbs_image._images_exist(region, [img])
                    if not existing:
                        info(f"  {region}: {img} already gone — marking retired")
                    else:
                        ohbs_image._delete_images(region, [img])
                        ok(f"  {region}: deleted {img}")
                    deleted_ids.add(img)
                    total_deleted += 1
                except ConfigError as exc:
                    fail(str(exc))
                    delete_error = delete_error or str(exc)
            else:
                warn(f"  [dry-run] would delete {region}: {img}")

    # mark retired in lineage (both dry-run and apply update the audit trail)
    if args.apply:
        # Per-IMAGE granularity: a lineage record can hold several image_ids.
        # Removing one must not retire the whole record.  Only images that
        # were actually deleted (or already gone) are retired — a delete
        # that failed keeps its lineage record so it is retried next run.
        if deleted_ids:
            _retire_cleanup_images(path, deleted_ids)
        ok(f"Retired {total_deleted} image(s); lineage updated.")

    if not args.apply:
        info("Re-run with --apply to actually delete (and mark lineage retired).")
    if delete_error:
        return 1
    return 0

def cmd_test(args: argparse.Namespace) -> int:
    """ohbs-image test --idempotency: re-run apply and assert the second pass
    makes no changes (Applied: 0 / Pending: 0 in the role summary)."""
    prep = ohbs_image._load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, workdir = prep

    if args.idempotency and r.family == "windows":
        warn("Idempotency check is Linux-only — nothing to do for Windows.")
        return 0

    ohbs_image.render_all(workdir, r, idempotency=args.idempotency)
    banner("test")
    info(f"Idempotency — re-running apply must make 0 changes "
         f"({r.profile_name} L{r.level}, region {r.region})")

    result = ohbs_image.run_packer(workdir, "build", quiet=args.quiet, capture=True, debug=args.debug)
    if result.exit_code != 0:
        fail("build failed during idempotency test")
        return result.exit_code

    applied = _last_num(result.stdout_lines, r"Applied:\s+(\d+)")
    pending = _last_num(result.stdout_lines, r"Pending:\s+(\d+)")
    if applied is None:
        fail("Could not parse apply summary — idempotency test inconclusive")
        return 1
    total_changes = applied + (pending or 0)
    if total_changes > 0:
        fail(f"idempotency FAILED: second apply made {applied} change(s), "
             f"{pending or 0} pending — the image drifts on rebuild")
        return 1
    ok("idempotency OK — second apply made 0 changes (no drift)")
    return 0

def cmd_pending(args: argparse.Namespace) -> int:
    """Change detection: report whether a rebuild is needed (P1#7).

    Exit 0 = build inputs unchanged since the last successful build
    (no rebuild needed).  Exit 1 = something changed or no record exists.
    The check is input-only; 'build --skip-if-unchanged' additionally
    verifies the previous image still exists before skipping.
    """
    prep = ohbs_image._load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, _workdir = prep
    fp = ohbs_image._build_fingerprint(r)
    prev_fp, prev_images = ohbs_image._last_successful_fingerprint(r)
    info(f"profile={r.profile_name} L{r.level} region={r.region}")
    info(f"current fingerprint  = {fp}")
    if prev_fp is None:
        fail("no previous successful build for this profile/level/region "
             "— rebuild required")
        return 1
    info(f"last build fingerprint = {prev_fp}")
    if prev_fp == fp:
        ok("inputs unchanged since last successful build — rebuild not required")
        if prev_images:
            ok(f"last images: {', '.join(prev_images)}")
        return 0
    warn("inputs changed — rebuild required")
    return 1

def cmd_list(args: argparse.Namespace) -> int:
    """Enumerate available profiles with metadata (P1#4: benchmark shown).

    *--versions* (#19): additionally show the bundled rule-catalog sha256
    and the ohbs-image version, so an audit can pin "this image was hardened
    with exactly this rule set".
    """
    show_versions = bool(getattr(args, "versions", False))
    if show_versions:
        print(f"{'profile':<12} {'benchmark':<14} {'catalog':<22} {'rules_sha256':<18} engine")
        for name, meta in sorted(PROFILES.items()):
            role = str(meta.get("role_dir", ""))
            bm = str(meta.get("benchmark", ""))
            cat = ohbs_image._catalog_basename(role, bm) if role else "-"
            rh = ohbs_image._bundled_rules_hash(role, cat)[:16] if role else "-"
            print(f"{name:<12} {bm:<14} {cat:<22} {rh:<18} {VERSION}")
        return 0
    print(f"{'profile':<12} {'family':<8} {'os':<12} {'comm':<6} {'benchmark':<14} user")
    for name, meta in sorted(PROFILES.items()):
        family = "windows" if meta.get("family") == "windows" else "linux"
        comm = "winrm" if family == "windows" else "ssh"
        user = meta.get("ssh_username", "") or meta.get("winrm_username", "") or "-"
        bm = str(meta.get("benchmark", ""))
        print(f"{name:<12} {family:<8} {str(meta.get('os_tag', '')):<12} "
              f"{comm:<6} {bm:<14} {user}")
    return 0

def cmd_scan(args: argparse.Namespace) -> int:
    """Audit-only build: engine runs in scan mode (no remediation), gate on score.

    Runs the full ephemeral-CVM pipeline but the bundled engine only
    *evaluates* the rules — nothing is modified.  The final re-audit score
    is gated against --min-score (default 85%); below it the command fails
    (non-zero exit) so CI can block on compliance.
    """
    prep = ohbs_image._load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, workdir = prep

    ohbs_image.render_all(workdir, r, scan=True)
    banner("scan")
    info(f"Audit-only (no remediation) — {r.profile_name} L{r.level}, region {r.region}")
    info(f"Gate: score >= {args.min_score:g}%")

    result = ohbs_image.run_packer(workdir, "build", quiet=args.quiet, capture=True, debug=args.debug)
    image_ids = _extract_image_ids(result.stdout_lines)
    score = _extract_score(result.stdout_lines)
    image_name = _image_name(r)

    # SARIF report (if requested) — written regardless of gate outcome so CI
    # can archive failures.  P0#2: carry the benchmark reference so rule IDs
    # cross-reference the official CIS/SCAP numbering.
    _write_sarif(args, result.stdout_lines, benchmark=r.image_benchmark)
    # XCCDF 1.2 export (if requested) — P2#8, for enterprise GRC ingestion.
    _write_xccdf(args, result.stdout_lines, benchmark=r.image_benchmark)

    if result.exit_code != 0:
        # A parsed score below the gate means the in-role score check
        # deliberately failed the build — report it as a gate failure,
        # not as an infrastructure/packer error.
        if score is not None and score < args.min_score:
            fail(f"scan gate FAILED: score {score:g}% < {args.min_score:g}% "
                 f"(audit-only, nothing remediated)")
            ohbs_image._record_lineage(r, image_ids, image_name, score, ok=False)
            _send_notification(r, False, image_ids, score, image_name)
            return 1
        fail("packer build failed during scan")
        ohbs_image._record_lineage(r, image_ids, image_name, score, ok=False)
        _send_notification(r, False, image_ids, score, image_name)
        return result.exit_code

    ok("scan build succeeded")
    if score is not None:
        ok(f"Scan score: {score:g}%")

    gate_ok = score is not None and score >= args.min_score
    if not gate_ok:
        shown = f"{score:g}%" if score is not None else "unknown"
        fail(f"scan gate FAILED: score {shown} < {args.min_score:g}%")
        ohbs_image._record_lineage(r, image_ids, image_name, score, ok=False)
        _send_notification(r, False, image_ids, score, image_name)
        return 1

    if image_ids:
        ok(f"Output image ID(s): {', '.join(image_ids)}")
    ohbs_image._record_lineage(r, image_ids, image_name, score, ok=True)
    ohbs_image._write_provenance(r, image_ids, image_name, score)
    rep = _save_build_report(r, image_name, result.stdout_lines, workdir)
    if rep:
        info(f"Audit report archived -> {rep}")
    _send_notification(r, True, image_ids, score, image_name)
    return 0

def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a signed provenance statement (SLSA signing verification)."""
    paths: list[Path] = []
    if args.provenance:
        p = Path(args.provenance)
        if not p.exists():
            fail(f"Provenance file not found: {p}")
            return 1
        paths = [p]
    elif args.image:
        paths = _find_provenance(args.image)
        if not paths:
            fail(f"No provenance found for image {args.image} in "
                 f"{ohbs_image._lineage_path().parent / 'provenance'}")
            return 1
    else:
        fail("Specify --provenance <file> or --image <id>")
        return 1

    rc_all = 0
    for prov_path in paths:
        try:
            prov = json.loads(prov_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(f"Could not read provenance {prov_path}: {exc}")
            rc_all = 1
            continue
        banner("verify")
        ok(f"provenance : {prov_path}")
        subjects = ", ".join(s.get("name", "?") for s in prov.get("subject", []))
        info(f"subject    : {subjects}")
        ext = prov.get("predicate", {}).get("buildDefinition", {}).get("externalParameters", {})
        info(f"profile    : {ext.get('profile', '?')}  |  CIS level {ext.get('cis_level', '?')}  |  region {ext.get('region', '?')}")
        info(f"source     : {ext.get('source_image_id', '?')}")
        info(f"builder    : {prov.get('predicate', {}).get('runDetails', {}).get('builder', {}).get('id', '?')}")
        score = prov.get("predicate", {}).get("runDetails", {}).get("metadata", {}).get("reAuditScore")
        if score is not None:
            info(f"re-audit   : {score:g}%")
        # signature check
        sig = prov_path.with_suffix(prov_path.suffix + ".sig")
        if sig.exists():
            try:
                rc = subprocess.run(["gpg", "--verify", str(sig), str(prov_path)],
                                    capture_output=True, text=True, timeout=30)
                if rc.returncode == 0:
                    ok(f"signature  : VALID ({prov_path.name}.sig)")
                else:
                    fail(f"signature  : INVALID — {(rc.stderr or rc.stdout).strip()[:200]}")
                    rc_all = 1
            except FileNotFoundError:
                warn("gpg not found — cannot verify signature")
            except subprocess.TimeoutExpired:
                warn("gpg verify timed out")
        else:
            warn("signature  : NONE (provenance was not signed)")
            rc_all = 1
    return rc_all

_FORBIDDEN_CLEAN_PREFIXES: tuple[Path, ...] = (
    Path("/"),
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path.home() / "Downloads",
    Path.home() / "Library",
    Path.home() / "Pictures",
    Path.home() / "Music",
    Path.home() / "Movies",
)

def _clean_is_safe(workdir: Path) -> str | None:
    """Return an error message if *workdir* is unsafe to delete, else None."""
    wd = workdir.resolve()

    # 1. Require at least one ohbs-image marker file (guard against accidental path).
    #    Access to the marker path can raise (e.g. a permission-denied parent
    #    directory such as another user's home). Treat any such failure as "no
    #    marker" → unsafe to delete: we must never delete a path we can't verify.
    markers = [
        wd / "packer" / "main.pkr.hcl",
        wd / "ansible" / "site.yml",
    ]
    marker_found = False
    for m in markers:
        try:
            marker_found = m.exists()
        except OSError:
            marker_found = False
        if marker_found:
            break
    if not marker_found:
        return f"Not a ohbs-image working directory (no packer/main.pkr.hcl or ansible/site.yml): {wd}"

    # 2. Reject known system / home root directories
    for forbidden in _FORBIDDEN_CLEAN_PREFIXES:
        try:
            fr = forbidden.resolve()
        except OSError:
            continue
        if wd == fr or str(wd).startswith(str(fr) + os.sep):
            return f"Refusing to clean system/home path: {wd}"

    return None

def cmd_clean(args: argparse.Namespace) -> int:
    """Remove the rendered working directory."""
    workdir = Path(args.workdir)
    if not workdir.exists():
        info(f"Working directory does not exist: {workdir}")
        return 0

    err = _clean_is_safe(workdir)
    if err:
        fail(err)
        return 1

    shutil.rmtree(workdir)
    ok(f"Removed: {workdir}")
    return 0
