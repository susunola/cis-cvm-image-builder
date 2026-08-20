from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from datetime import UTC
from pathlib import Path
from typing import Any

import ohbs_image

from ._config import ResolvedConfig
from ._logging import VERSION, info, ok, warn


def _save_build_report(r: ResolvedConfig, image_name: str,
                       stdout_lines: list[str], workdir: Path) -> Path | None:
    """Archive the per-rule audit JSON on the BUILD machine (P-next).

    The in-image copy (/opt/ohbs-image-AUDIT-RESULT.json /
    C:\\ProgramData\\ohbs-image\\AUDIT-RESULT.json) travels with the image for
    drift/verify-image, but the operator's durable record belongs next to
    the lineage + provenance: ~/.ohbs-image/reports/<image-name>.json.

    Linux emits the file as a gzipped+base64 marker line in the packer log
    (the finalize provisioner); Windows fetches result.json back to
    <workdir>/ansible/reports/<host>/raw/ via the role's cis_report_json.
    Returns the saved path, or None when no report was found.
    """
    raw: bytes | None = None
    for line in stdout_lines:
        m = re.search(r"__CIS_IMAGE_AUDIT_B64__([A-Za-z0-9+/=]+)", line)
        if m:
            import base64 as _b64
            import gzip as _gz
            try:
                raw = _gz.decompress(_b64.b64decode(m.group(1)))
            except Exception:
                raw = None
            break
    if raw is None:
        # Windows path: result.json fetched to the controller by the role.
        cands = sorted(workdir.glob("ansible/reports/*/raw/result.json"))
        if cands:
            try:
                raw = cands[-1].read_bytes()
            except OSError:
                raw = None
    if not raw:
        return None
    try:
        json.loads(raw)  # don't archive garbage
    except ValueError:
        return None
    try:
        out = ohbs_image._reports_dir() / f"{image_name}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(raw)
        return out
    except OSError:
        return None

def _record_lineage(r: ResolvedConfig, image_ids: list[str], image_name: str,
                    score: float | None, ok: bool,
                    sbom_sha: str | None = None,
                    sbom_count: int | None = None,
                    mode: str = "build") -> Path | None:
    """Append one lineage record. Returns the file path, or None on failure.

    *mode* — "build" (real hardening build), "scan" (audit-only) or "test"
    (idempotency run).  Readers that must only see real builds filter on it;
    records written before this field existed are treated as "build".
    """
    if not isinstance(r, ResolvedConfig):
        return None  # defensive: only real resolved configs are recorded
    try:
        path = ohbs_image._lineage_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        from datetime import datetime
        rec = {
            "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "ok" if ok else "failed",
            "mode": mode,
            "ohbs_image_version": VERSION,
            "profile": r.profile_name,
            "cis_level": r.level,
            "region": r.region,
            "zone": r.zone,
            "source_image_id": r.source_image_id,
            "image_name": image_name,
            "image_ids": image_ids,
            "score": score,
            # P1#4/#7 — benchmark pinning + change detection: the fingerprint
            # lets 'build --skip-if-unchanged' skip rebuilds when nothing
            # changed, and the benchmark name/version anchors the audit.
            "benchmark": r.image_benchmark,
            "fingerprint": ohbs_image._build_fingerprint(r),
            # #20 — the source image's CreatedTime at build time, so
            # 'ohbs-image check-source' can detect a vendor image refresh.
            "source_image_created": ohbs_image._source_image_created(r),
        }
        # P2#10 — SBOM pinning: hash + package count of the emitted SBOM.
        if sbom_sha:
            rec["sbom_sha256"] = sbom_sha
        if sbom_count is not None:
            rec["sbom_packages"] = sbom_count
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return path
    except OSError:
        return None

def _bundled_rules_hash(role_dir: str, catalog: str = "rules.json") -> str:
    """SHA-256 of the bundled catalog for *role_dir* ("" if unavailable).

    *catalog* is the catalog basename (``rules.json`` for CIS, or
    ``rules_<slug>.json`` for a non-CIS benchmark).  Defaults to the CIS
    catalog to preserve prior callers.
    """
    import hashlib
    project_root = Path(__file__).parent.resolve()
    p = (project_root / "roles" / role_dir / "files" / catalog).resolve()
    try:
        p.relative_to((project_root / "roles").resolve())
    except ValueError:
        return ""
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return ""

def _build_fingerprint(r: ResolvedConfig) -> str:
    """Deterministic fingerprint of every build input that affects the image.

    Includes the source image ID (rebuilds after a vendor image refresh are
    NOT skipped), the rule catalog hash, benchmark, level, rule filters and
    the builder version.  Stable across runs of the same inputs.
    """
    import hashlib
    if not isinstance(r, ResolvedConfig):
        return ""
    parts = [
        "ohbs-image", VERSION,
        "profile", r.profile_name,
        "level", str(r.level),
        "region", r.region,
        "zone", r.zone,
        "source", r.source_image_id,
        "instance", r.instance_type,
        "benchmark", r.image_benchmark,
        "os", r.image_os_tag,
        "rules", ohbs_image._bundled_rules_hash(r.role_dir, r.catalog_basename),
        "include", ",".join(r.rules_include),
        "exclude", ",".join(r.rules_exclude),
        "overrides", json.dumps(r.rules_overrides, sort_keys=True, ensure_ascii=False),
    ]
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()

def _last_successful_fingerprint(r: ResolvedConfig) -> tuple[str | None, list[str]]:
    """Most recent 'ok' BUILD lineage record matching profile/level/region.

    Returns (fingerprint, image_ids) — None fingerprint when no match.
    Used by change detection to skip rebuilds with identical inputs.
    Only real builds count: audit-only scans and idempotency-test runs
    (mode "scan"/"test") produce images that are NOT hardened, so they must
    never satisfy 'build --skip-if-unchanged'.  Records written before the
    mode field existed (no "mode" key) are treated as builds.
    """
    path = ohbs_image._lineage_path()
    if not path.exists():
        return None, []
    match: dict[str, Any] | None = None
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
                    and rec.get("mode", "build") == "build"
                    and rec.get("profile") == r.profile_name
                    and rec.get("cis_level") == r.level
                    and rec.get("region") == r.region
                    and not rec.get("retired")):
                match = rec  # last matching record wins (file is append-only)
    if not match:
        return None, []
    return match.get("fingerprint"), list(match.get("image_ids") or [])

def _send_notification(r: ResolvedConfig, ok: bool, image_ids: list[str],
                       score: float | None, image_name: str) -> None:
    if not isinstance(r, ResolvedConfig):
        return
    # [notify].deploy_webhook — EventBridge-style downstream trigger (#14).
    # On SUCCESS, POST the image metadata to the customer's CI/CD so the
    # "new image is ready" event drives the deployment, not a human reading
    # the WeCom message.  Independent of the WeCom notification (fires even
    # when [notify].webhook is unset); never fails the build.
    if ok and r.deploy_webhook:
        ohbs_image._trigger_deploy_webhook(r, image_ids, score, image_name)
    if not r.notify_webhook:
        return
    if r.notify_on == "success" and not ok:
        return
    if r.notify_on == "failure" and ok:
        return
    if ok:
        head = "✅ ohbs-image build OK"
        body = (f"profile {r.profile_name} L{r.level} | image {image_name} | "
                f"score {score:g}%" if score is not None else
                f"profile {r.profile_name} L{r.level} | image {image_name}")
        if image_ids:
            body += f"\nimage-id: {', '.join(image_ids)}"
        body += f"\nregion {r.region}"
    else:
        head = "❌ ohbs-image build FAILED"
        body = f"profile {r.profile_name} L{r.level} | region {r.region} — check the build log"
    payload = json.dumps({"msgtype": "text", "text": {"content": f"{head}\n{body}"}},
                         ensure_ascii=False).encode("utf-8")
    try:
        req = urllib.request.Request(
            r.notify_webhook, data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                info("Notification sent to WeCom webhook")
            else:
                warn(f"Notification webhook returned HTTP {resp.status}")
    except Exception as exc:  # notifications must never fail the build
        warn(f"Notification webhook failed: {exc}")

def _trigger_deploy_webhook(r: ResolvedConfig, image_ids: list[str],
                            score: float | None, image_name: str) -> None:
    """POST image metadata to [notify].deploy_webhook on build success."""
    payload = json.dumps({
        "event": "image.ready",
        "image_id": (image_ids[0] if image_ids else ""),
        "image_ids": image_ids,
        "image_name": image_name,
        "profile": r.profile_name,
        "cis_level": r.level,
        "region": r.region,
        "benchmark": r.image_benchmark,
        "score": score,
        "ohbs_image_version": VERSION,
    }, ensure_ascii=False).encode("utf-8")
    try:
        req = urllib.request.Request(
            r.deploy_webhook, data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status < 300:
                ok(f"Deploy webhook triggered ({resp.status})")
            else:
                warn(f"Deploy webhook returned HTTP {resp.status}")
    except Exception as exc:  # must never fail the build
        warn(f"Deploy webhook failed: {exc}")

def _write_provenance(r: ResolvedConfig, image_ids: list[str], image_name: str,
                      score: float | None,
                      sbom_sha: str | None = None,
                      sbom_count: int | None = None) -> Path | None:
    if not isinstance(r, ResolvedConfig):
        return None
    try:
        from datetime import datetime
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        dirp = ohbs_image._lineage_path().parent / "provenance"
        dirp.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", image_name) or "image"
        prov_path = dirp / f"{safe_name}.{ts.replace(':', '').replace('-', '').replace('T', '-')}.provenance.json"
        prov: dict[str, Any] = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": i, "digest": {"sha256": "n/a"}} for i in image_ids],
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://ohbs_image.dev/build/v1",
                    "externalParameters": {
                        "profile": r.profile_name,
                        "cis_level": r.level,
                        "region": r.region,
                        "zone": r.zone,
                        "source_image_id": r.source_image_id,
                        "instance_type": r.instance_type,
                        "benchmark": r.image_benchmark,
                        # P1#4 — pin the exact rule catalog version that was
                        # applied, so the provenance is auditable against the
                        # benchmark edition (ansible-lockdown pins per-benchmark).
                        "rules_sha256": ohbs_image._bundled_rules_hash(r.role_dir, r.catalog_basename),
                        "fingerprint": ohbs_image._build_fingerprint(r),
                    },
                    "internalParameters": {"ohbs_image_version": VERSION},
                },
                "runDetails": {
                    "builder": {"id": f"ohbsimage@{VERSION}"},
                    "metadata": {
                        "invocationId": ts,
                        "startedOn": ts,
                        "finishedOn": ts,
                    },
                },
            },
        }
        if score is not None:
            prov["predicate"]["runDetails"]["metadata"]["reAuditScore"] = score
        # P2#10 — SBOM pinning: the provenance now references the emitted
        # SBOM (hash + package count), closing the SLSA L2-style gap of
        # "what exactly shipped inside the image".
        if sbom_sha:
            prov["predicate"]["runDetails"]["metadata"]["sbomSha256"] = sbom_sha
        if sbom_count is not None:
            prov["predicate"]["runDetails"]["metadata"]["sbomPackageCount"] = sbom_count
        prov_path.write_text(json.dumps(prov, ensure_ascii=False, indent=1) + "\n",
                             encoding="utf-8")
        if r.sign_key:
            sig = prov_path.with_suffix(prov_path.suffix + ".sig")
            try:
                rc = subprocess.run(
                    ["gpg", "--batch", "--yes", "--detach-sign", "--armor",
                     "--local-user", r.sign_key, "-o", str(sig), str(prov_path)],
                    capture_output=True, text=True, timeout=60)
                if rc.returncode == 0:
                    ok(f"Provenance signed with GPG key {r.sign_key} -> {sig.name}")
                else:
                    warn(f"GPG signing failed (key {r.sign_key}?): "
                         f"{(rc.stderr or rc.stdout).strip()[:200]}")
            except FileNotFoundError:
                warn("gpg not found — provenance written unsigned")
            except subprocess.TimeoutExpired:
                warn("gpg signing timed out — provenance written unsigned")
        return prov_path
    except OSError as exc:
        warn(f"Could not write provenance: {exc}")
        return None

def _find_provenance(image_id: str) -> list[Path]:
    """Locate provenance files whose subject references *image_id*."""
    dirp = ohbs_image._lineage_path().parent / "provenance"
    if not dirp.is_dir():
        return []
    hits: list[Path] = []
    for p in sorted(dirp.glob("*.provenance.json")):
        try:
            prov = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        subjects = [s.get("name", "") for s in prov.get("subject", [])]
        if image_id in subjects:
            hits.append(p)
    return hits
