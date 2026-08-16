"""Rule-catalog resolution keyed by benchmark.

The engine itself is benchmark-agnostic: it loads ONE catalog via ``--catalog``
and dispatches rules purely on ``family``.  This module answers the *only*
benchmark-specific question in the core: **which catalog file does a given
profile/role use?**

Historically there is exactly one catalog per role, ``rules.json``.  To support
a second benchmark (e.g. STIG, NIST-800-53) for the same OS without renaming
anything, a profile may point at a benchmark-specific file
(``rules_<slug>.json``).  CIS and the legacy empty/unknown benchmark keep
``rules.json`` so the 12 byte-identical engine copies and all existing tests
stay untouched.
"""
from __future__ import annotations

from pathlib import Path

# Benchmarks whose catalog is the historical ``rules.json``.  Anything else
# resolves to ``rules_<slug>.json`` (falling back to ``rules.json`` when that
# file is absent, so a profile can opt into a new benchmark catalog gradually).
_LEGACY_BENCHMARKS = frozenset({"", "cis", "cis benchmark"})


def benchmark_slug(benchmark: str) -> str:
    """Normalize a benchmark string into a filesystem-safe slug.

    >>> benchmark_slug("STIG-RHEL9")
    'stig_rhel9'
    >>> benchmark_slug("CIS-v5.1.0")
    'cis_v5_1_0'
    >>> benchmark_slug("NIST-800-53")
    'nist_800_53'
    """
    return benchmark.strip().lower().replace("-", "_").replace(".", "_")


def _roles_dir() -> Path:
    return Path(__file__).parent.resolve() / "roles"


def _catalog_path(role_dir: str, benchmark: str, workdir: Path | None = None) -> Path:
    """Resolve the rules catalog file for *role_dir* under *benchmark*.

    Resolution order (first hit wins):

    1. If *workdir* is given, prefer the rendered workspace copy under
       ``<workdir>/ansible/roles/<role_dir>/files/`` (overrides are applied
       there).  This mirrors where ``_render`` writes the active catalog.
    2. The bundled package catalog under ``ohbs_image/roles/<role_dir>/files/``:
       ``rules_<slug>.json`` for non-CIS benchmarks, else ``rules.json``.
       When the benchmark-specific file is missing we fall back to
       ``rules.json`` so a profile can declare a new benchmark before its
       catalog exists.

    The returned path may not exist (callers already handle missing catalogs);
    it is always expressed relative to the ``roles`` tree so no absolute
    assumption leaks out.
    """
    files_dir = _roles_dir() / role_dir / "files"

    if workdir is not None:
        ws = (Path(workdir) / "ansible" / "roles" / role_dir / "files")
        if (ws / "rules.json").exists():
            # Overrides are always written into the workspace rules.json, so
            # once a workspace copy exists it is authoritative.
            return (ws / "rules.json").resolve()

    bm = (benchmark or "").strip().lower()
    if bm in _LEGACY_BENCHMARKS:
        return (files_dir / "rules.json").resolve()
    specific = files_dir / f"rules_{benchmark_slug(benchmark)}.json"
    if specific.exists():
        return specific.resolve()
    return (files_dir / "rules.json").resolve()


def _catalog_basename(role_dir: str, benchmark: str) -> str:
    """Filename (basename only) of the catalog ``_catalog_path`` would return.

    Used for report/CLI display so operators can see which file drives a
    profile.  Mirrors ``_catalog_path``'s resolution but returns a name rather
    than a full path, which is what the rendered HCL/templates need.
    """
    bm = (benchmark or "").strip().lower()
    if bm in _LEGACY_BENCHMARKS:
        return "rules.json"
    specific = _roles_dir() / role_dir / "files" / f"rules_{benchmark_slug(benchmark)}.json"
    if specific.exists():
        return specific.name
    return "rules.json"
