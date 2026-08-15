from __future__ import annotations

import argparse
import contextlib
import json
import re
import subprocess
from datetime import UTC
from pathlib import Path
from typing import Any, cast

from ._logging import VERSION, banner, fail, info, ok, warn
from ._packer import _extract_score


def _extract_rule_statuses(doc: dict[str, Any]) -> dict[str, str]:
    """Flatten an engine result doc into {rule_id: status}."""
    out: dict[str, str] = {}
    for r in doc.get("results") or []:
        rid = r.get("id")
        if rid:
            out[str(rid)] = str(r.get("status", "?"))
    return out

def _drift_diff(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare two engine result docs; return the drift summary.

    *new_failures* — rules passing (or absent) in the baseline that now fail.
    *recovered*    — rules failing in the baseline that now pass.
    *status_changed* — any other pass/fail flip.
    """
    b = _extract_rule_statuses(baseline)
    c = _extract_rule_statuses(current)
    all_ids = sorted(set(b) | set(c))
    new_failures: list[str] = []
    recovered: list[str] = []
    status_changed: list[str] = []
    for rid in all_ids:
        bst, cst = b.get(rid, "absent"), c.get(rid, "absent")
        if cst == "fail" and bst in ("pass", "absent", "manual", "notapplicable"):
            new_failures.append(rid)
        elif cst in ("pass", "manual", "notapplicable") and bst == "fail":
            recovered.append(rid)
        elif cst != bst and cst not in ("fail",) and bst not in ("fail",):
            status_changed.append(rid)
    bs = (baseline.get("summary") or {}).get("all", {})
    cs = (current.get("summary") or {}).get("all", {})
    return {
        "baseline_score": bs.get("score"),
        "current_score": cs.get("score"),
        "new_failures": new_failures,
        "recovered": recovered,
        "status_changed": status_changed,
    }

_RULE_FAIL_RE = re.compile(r"✗\s+([0-9][0-9.]+)\s*\|\s*([^\n✗]*)")

def _parse_failed_rules(stdout_lines: list[str]) -> list[dict[str, str]]:
    """Extract {id, title, detail} for each failed rule in engine output.

    The engine emits the failed-rule list as ONE Ansible ``msg`` string
    with literal ``\\n`` escapes (each rule's detail glued directly to the
    next ``✗`` marker), so a line-anchored regex over raw packer stdout
    never matches.  Decode any ``"msg": "..."`` JSON payloads first, then
    split the blob on rule markers — plain and msg-wrapped output parse
    identically.
    """
    texts: list[str] = []
    for line in stdout_lines:
        for m in re.findall(r'"msg":\s*"((?:[^"\\]|\\.)*)"', line):
            try:
                texts.append(json.loads(f'"{m}"'))
            except ValueError:
                texts.append(m)
        texts.append(line)
    blob = "\n".join(texts)
    matches = list(_RULE_FAIL_RE.finditer(blob))
    rules: list[dict[str, str]] = []
    seen: set[str] = set()
    for i, m in enumerate(matches):
        rid, title = m.group(1), m.group(2).strip()
        if rid in seen:
            continue
        seen.add(rid)
        # Detail = text between this rule's title and the next rule marker
        # (the engine prints it as indented line(s) right after the title).
        end = matches[i + 1].start() if i + 1 < len(matches) else len(blob)
        detail = re.sub(r"\s*\n\s*", " ", blob[m.end():end]).strip()
        rules.append({"id": rid, "title": title, "detail": detail})
    return rules

def _build_sarif(stdout_lines: list[str], benchmark: str = "") -> str:
    """Build a SARIF 2.1.0 document from the engine's 'List failed rules' output.

    *benchmark* (P0#2) — official benchmark reference (e.g. "CIS TencentOS
    Linux 4 Benchmark v1.0.0") carried in the driver so GRC tooling can
    cross-reference the rule IDs against CIS-CAT / SCAP content.
    """
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for parsed in _parse_failed_rules(stdout_lines):
        rid, title, detail = parsed["id"], parsed["title"], parsed["detail"]
        rule_obj: dict[str, Any] = {"id": rid, "shortDescription": {"text": title}}
        if benchmark:
            rule_obj["properties"] = {"benchmark": benchmark}
        rules.append(rule_obj)
        results.append({
            "ruleId": rid,
            "level": "error",
            "message": {"text": detail or title},
        })
    driver: dict[str, Any] = {
        "name": "cis-image",
        "version": VERSION,
        "informationUri": "https://github.com/susunola/cis-image",
        "rules": rules,
    }
    if benchmark:
        driver["properties"] = {"benchmark": benchmark}
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": driver},
            "results": results,
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=1)

def _write_sarif(args: argparse.Namespace, stdout_lines: list[str], benchmark: str = "") -> None:
    if not getattr(args, "sarif", None):
        return
    try:
        Path(args.sarif).write_text(
            _build_sarif(stdout_lines, benchmark), encoding="utf-8")
        ok(f"SARIF report written -> {args.sarif}")
    except OSError as exc:
        warn(f"Could not write SARIF report: {exc}")

def _build_xccdf(stdout_lines: list[str], benchmark: str = "") -> str:
    """Build a minimal XCCDF 1.2 TestResult document from the engine output.

    Each failing rule becomes a <rule-result>; the benchmark reference is
    carried in the TestResult so the export ties back to the CIS edition.
    """
    from datetime import datetime
    from xml.sax.saxutils import escape
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = []
    for parsed in _parse_failed_rules(stdout_lines):
        rid = parsed["id"]
        rows.append(
            f'  <rule-result idref="xccdf_org.cis_image.content_rule_{rid}">\n'
            f'    <result>fail</result>\n'
            f'    <message>{escape((parsed["detail"] or parsed["title"])[:200])}</message>\n'
            f'  </rule-result>')
    # Real audit score when the engine printed one; 0 when the build never
    # reached the audit (a hard-coded 100 here made failed builds look
    # compliant to GRC ingestion).
    score = _extract_score(stdout_lines)
    bm = escape(benchmark) if benchmark else "cis-image"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" '
        f'id="cis-image-{escape(benchmark) if benchmark else "benchmark"}">\n'
        f'  <TestResult id="cis-image-scan" start-time="{now}" end-time="{now}" '
        f'benchmark-reference="{bm}">\n'
        f'    <score max="100">{score if score is not None else 0.0:.6f}</score>\n'
        + "\n".join(rows) + "\n"
        '  </TestResult>\n</Benchmark>\n')

def _write_xccdf(args: argparse.Namespace, stdout_lines: list[str], benchmark: str = "") -> None:
    if not getattr(args, "xccdf", None):
        return
    try:
        Path(args.xccdf).write_text(
            _build_xccdf(stdout_lines, benchmark), encoding="utf-8")
        ok(f"XCCDF report written -> {args.xccdf}")
    except OSError as exc:
        warn(f"Could not write XCCDF report: {exc}")

def _audit_ssh_args(host: str, ssh_user: str, ssh_port: int,
                    ssh_key: str | None = None) -> list[str]:
    args = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15"]
    if ssh_port:
        args += ["-p", str(ssh_port)]
    if ssh_key:
        args += ["-i", ssh_key]
    args += [f"{ssh_user}@{host}"]
    return args

def _audit_oscap(host: str, ssh_user: str, ssh_port: int, ssh_key: str | None,
                 profile: str, datastream: str, timeout: int = 900) -> str:
    """Run oscap over SSH, return the ARF XML document ("" on failure)."""
    remote = (f"oscap xccdf eval --profile {profile} --results-arf - {datastream} 2>/dev/null"
              )
    try:
        cp = subprocess.run(_audit_ssh_args(host, ssh_user, ssh_port, ssh_key) + [remote],
                            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        warn(f"oscap audit timed out after {timeout}s on {host}")
        return ""
    except FileNotFoundError:
        warn("ssh not found in PATH — cannot run the oscap audit")
        return ""
    return cp.stdout

def _audit_inspec(host: str, ssh_user: str, ssh_port: int, ssh_key: str | None,
                  baseline: str, timeout: int = 900) -> dict[str, Any] | None:
    """Run InSpec over SSH, return the parsed JSON report (None on failure)."""
    target = f"ssh://{ssh_user}@{host}"
    if ssh_port:
        target += f":{ssh_port}"
    cmd = ["inspec", "exec", baseline, "-t", target, "--reporter", "json"]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        warn("inspec not found in PATH — install from https://chef.io/products/chef-inspec")
        return None
    except subprocess.TimeoutExpired:
        warn(f"inspec timed out after {timeout}s")
        return None
    try:
        return cast("dict[str, Any]", json.loads(cp.stdout))
    except json.JSONDecodeError:
        warn("inspec produced no JSON report (does the target reachable?)")
        return None

def _parse_oscap_arf(xml_text: str) -> dict[str, Any]:
    """Parse an OpenSCAP ARF XML into {score, pass, fail, results[]}.

    ARF = OVAL + XCCDF results; the XCCDF TestResult holds the profile
    score and per-rule results.  stdlib xml.etree only.
    """
    import xml.etree.ElementTree as ET
    out: dict[str, Any] = {"score": None, "pass": 0, "fail": 0, "notselected": 0,
                          "error": 0, "results": [], "tool": "oscap"}
    if not xml_text.strip():
        return out
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        out["error"] = 1
        out["results"] = [{"id": "_parse_error_", "status": "error",
                           "detail": str(exc)}]
        return out
    ns = {"x": "http://checklists.nist.gov/xccdf/1.2",
          "arf": "http://scap.nist.gov/schema/asset-reporting-format/1.1",
          "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5"}
    # XCCDF TestResult is nested under arf:report-request/report
    test_results = root.findall(".//x:TestResult", ns)
    tr = test_results[-1] if test_results else None
    if tr is None:
        out["results"] = [{"id": "_no_result_", "status": "error",
                           "detail": "no XCCDF TestResult in ARF"}]
        return out
    score_node = tr.find("x:score", ns)
    if score_node is not None and score_node.text:
        with contextlib.suppress(ValueError):
            out["score"] = round(float(score_node.text) * 100, 1)
    for rule in tr.findall("x:rule-result", ns):
        rid = rule.get("idref", "?")
        _res_node = rule.find("x:result", ns)
        status = (_res_node.text or "notselected") if _res_node is not None else "notselected"
        st = status.lower()
        if st == "pass":
            out["pass"] += 1
        elif st == "fail":
            out["fail"] += 1
        elif st in ("notselected", "notapplicable", "informational", "fixed", "unknown"):
            out["notselected"] += 1
        elif st == "error":
            out["error"] += 1
        out["results"].append({
            "id": rid, "status": st,
            "title": rid.rsplit("_", 1)[-1].replace("_", " "),
        })
    return out

def _parse_inspec_json(data: dict[str, Any] | None) -> dict[str, Any]:
    """Parse an InSpec JSON report into the same {score, pass, fail, results} shape."""
    out: dict[str, Any] = {"score": None, "pass": 0, "fail": 0, "notselected": 0,
                          "error": 0, "results": [], "tool": "inspec"}
    if not data:
        out["error"] = 1
        out["results"] = [{"id": "_no_data_", "status": "error",
                           "detail": "no InSpec JSON report"}]
        return out
    controls = data.get("controls") or []
    for c in controls:
        rid = c.get("id", "?")
        status = c.get("status", "skipped")
        st = status.lower()
        if st == "passed":
            out["pass"] += 1
            st = "pass"
        elif st in ("failed", "error"):
            out["fail"] += 1
            st = "fail" if st == "failed" else "error"
        else:
            out["notselected"] += 1
            st = "notselected"
        detail = "; ".join(
            (r.get("message") or "") for r in (c.get("results") or [])
            if r.get("status") != "passed") or (c.get("title") or "")
        out["results"].append({"id": rid, "status": st, "detail": detail[:160]})
    scored = out["pass"] + out["fail"]
    if scored:
        out["score"] = round(100.0 * out["pass"] / scored, 1)
    return out

def _audit_render(audit: dict[str, Any], min_score: float) -> int:
    """Print an audit summary; return exit code (0 = gate passed)."""
    banner("audit")
    info(f"tool       : {audit.get('tool', '?')}")
    info(f"rules      : {audit['pass'] + audit['fail'] + audit['notselected'] + audit['error']} "
         f"(pass {audit['pass']}, fail {audit['fail']}, "
         f"notselected {audit['notselected']}, error {audit['error']})")
    if audit.get("score") is not None:
        info(f"score      : {audit['score']:g}% (gate >= {min_score:g}%)")
    for r in audit["results"]:
        if r["status"] in ("fail", "error"):
            fail(f"{r['id']:s} | {r.get('detail') or r.get('title') or r['status']}")
    gate_ok = audit.get("score") is not None and audit["score"] >= min_score
    if gate_ok:
        ok(f"audit gate PASSED ({audit['score']:g}% >= {min_score:g}%)")
        return 0
    shown = f"{audit['score']:g}%" if audit.get("score") is not None else "unknown"
    fail(f"audit gate FAILED: score {shown} < {min_score:g}%")
    return 1

def _audit_results_sarif(audit: dict[str, Any]) -> str:
    """SARIF 2.1.0 document from an independent audit's findings."""
    rules, results = [], []
    seen: set[str] = set()
    for r in audit["results"]:
        if r["status"] not in ("fail", "error"):
            continue
        rid = r["id"]
        if rid in seen:
            continue
        seen.add(rid)
        rules.append({"id": rid, "shortDescription": {"text": r.get("title") or rid}})
        results.append({"ruleId": rid, "level": "error",
                        "message": {"text": r.get("detail") or rid}})
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": f"cis-image-audit-{audit.get('tool', '?')}",
                "version": VERSION,
                "informationUri": "https://github.com/susunola/cis-image",
                "rules": rules}},
            "results": results,
        }],
    }, ensure_ascii=False, indent=1)

def cmd_audit(args: argparse.Namespace) -> int:
    """cis-image audit — independent third-party audit (oscap / inspec / kitty)."""
    if args.tool not in ("oscap", "inspec", "kitty"):
        fail(f"Unknown audit tool: {args.tool}. Use oscap, inspec or kitty.")
        return 1
    if args.tool == "kitty":
        # HardeningKitty runs ON the Windows host (no winrm client in the
        # stdlib-only CLI); cis-image consumes its CSV export and gates.
        if not args.parse:
            fail("--parse <kitty-audit.csv> is required for the kitty tool "
                 "(run HardeningKitty on the Windows host, export CSV, then "
                 "parse it here)")
            return 1
        try:
            csv_text = Path(args.parse).read_text(encoding="utf-8-sig")
        except OSError as exc:
            fail(f"Could not read HardeningKitty CSV {args.parse}: {exc}")
            return 1
        audit = _parse_kitty_csv(csv_text)
    elif not args.host:
        fail("--host is required (the target instance to audit)")
        return 1
    elif args.tool == "oscap":
        if not args.datastream:
            fail("--datastream is required for oscap (e.g. "
                 "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml)")
            return 1
        info(f"Running oscap xccdf eval (profile={args.profile}) on {args.host} …")
        xml_text = _audit_oscap(args.host, args.ssh_user, args.ssh_port,
                                args.ssh_key, args.profile, args.datastream)
        audit = _parse_oscap_arf(xml_text)
    else:
        baseline = args.baseline or "dev-sec/linux-baseline"
        info(f"Running InSpec ({baseline}) against {args.host} …")
        audit = _parse_inspec_json(_audit_inspec(
            args.host, args.ssh_user, args.ssh_port, args.ssh_key, baseline))
    if getattr(args, "sarif", None):
        try:
            Path(args.sarif).write_text(_audit_results_sarif(audit), encoding="utf-8")
            ok(f"SARIF report written -> {args.sarif}")
        except OSError as exc:
            warn(f"Could not write SARIF report: {exc}")
    if getattr(args, "xccdf", None):
        try:
            Path(args.xccdf).write_text(_audit_results_xccdf(audit), encoding="utf-8")
            ok(f"XCCDF report written -> {args.xccdf}")
        except OSError as exc:
            warn(f"Could not write XCCDF report: {exc}")
    return _audit_render(audit, args.min_score)

def _audit_results_xccdf(audit: dict[str, Any]) -> str:
    """Minimal XCCDF 1.2 TestResult document from an independent audit."""
    from xml.sax.saxutils import escape
    rows = []
    for r in audit["results"]:
        rid = escape(r["id"])
        status = {"pass": "pass", "fail": "fail", "error": "error"}.get(
            r["status"], "notselected")
        rows.append(
            f'  <rule-result idref="{rid}"><result>{status}</result></rule-result>')
    score = audit.get("score")
    # Same convention as _build_xccdf: engine scores are 0-100 percentages,
    # emitted with max="100" so GRC tools read both exports identically.
    score_xml = f'  <score max="100">{score:.6f}</score>' if score is not None else ""
    tool_name = str(audit.get("tool", "audit"))
    from datetime import datetime
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" '
        'id="cis-image-audit">\n'
        f'  <TestResult id="cis-image-{tool_name}" '
        f'start-time="{now}Z" end-time="{now}Z">\n'
        f'{score_xml}\n' + "\n".join(rows) + "\n"
        "  </TestResult>\n</Benchmark>\n")

def _parse_kitty_csv(csv_text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"score": None, "pass": 0, "fail": 0, "notselected": 0,
                          "error": 0, "results": [], "tool": "kitty"}
    import csv as _csv
    import io as _io
    reader = _csv.DictReader(_io.StringIO(csv_text))
    if not reader.fieldnames:
        out["error"] = 1
        out["results"] = [{"id": "_no_header_", "status": "error",
                           "detail": "empty HardeningKitty CSV"}]
        return out
    for _row_no, row in enumerate(reader, start=1):
        rid = (row.get("RuleId") or row.get("Id") or row.get("Rule") or "?")
        status = (row.get("Compliant") or row.get("Status") or row.get("Result") or "").lower()
        # HardeningKitty reports "True"/"False"/"-"/"Not Applicable"
        if status in ("true", "pass", "passed", "ok", "compliant"):
            out["pass"] += 1
            st = "pass"
        elif status in ("false", "fail", "failed", "not compliant"):
            out["fail"] += 1
            st = "fail"
        elif status in ("", "-", "n/a", "not applicable", "skip", "skipped"):
            out["notselected"] += 1
            st = "notselected"
        else:
            out["error"] += 1
            st = "error"
        out["results"].append({"id": rid, "status": st,
                               "detail": (row.get("Finding") or row.get("Message") or "")[:160]})
    scored = out["pass"] + out["fail"]
    if scored:
        out["score"] = round(100.0 * out["pass"] / scored, 1)
    return out
