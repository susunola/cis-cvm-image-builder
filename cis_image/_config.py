from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._logging import ConfigError, warn
from ._profiles import PROFILE_NAMES_HELP, PROFILES


@dataclass
class PackerResult:
    """Normalised return from packer subprocess."""

    exit_code: int
    stdout_lines: list[str] = field(default_factory=list)

@dataclass
class ResolvedConfig:
    """Fully-resolved build configuration ready for rendering."""

    profile_name: str
    profile: dict[str, Any]
    family: str                         # "" = Linux, "windows" = Windows
    region: str
    zone: str
    instance_type: str
    source_image_id: str
    vpc_id: str
    subnet_id: str
    security_group_id: str
    associate_public_ip: bool
    ssh_port: int
    ssh_timeout: str
    ssh_username: str
    ssh_debug_password: str
    winrm_username: str
    winrm_password_env: str
    image_name_prefix: str
    image_name_override: str            # [image].name — fixed image name ("" = auto)
    instance_name: str                  # [build].instance_name — build CVM instance name ("" = plugin auto)
    image_copy_regions: list[str]
    image_share_accounts: list[str]     # [image].share_accounts — share built image with other uins
    image_share_org_units: list[str]    # [image].share_org_units — org-level sharing (same API as share_accounts)
    spot: bool                          # [build].spot — use a spot instance for the build VM (default false)
    cis_level_tag: str
    secret_id_env: str
    secret_key_env: str
    security_token_env: str         # [cloud].security_token_env — STS session token env (default "TENCENTCLOUD_SECURITY_TOKEN")
    assume_role_arn: str               # [cloud].assume_role_arn — group-account CAM role ("" = off)
    assume_role_session: str           # [cloud].assume_role_session (default "cis-image")
    assume_role_duration: int          # [cloud].assume_role_duration (default 7200, 0-43200)
    image_os_tag: str
    image_benchmark: str
    level: int
    min_score: int                      # [cis].min_score — post-reboot audit gate, 0 disables (default 85)
    role_dir: str
    smoke_test: bool                    # [meta].smoke_test — run instance-level smoke checks before snapshot (default true)
    cve_scan: bool                      # [meta].cve_scan — trivy vulnerability scan gate before snapshot (default false)
    sbom: bool                          # [meta].sbom — emit SBOM into image + provenance (default false)
    rules_include: list[str]            # [cis].rules_include — rule-id filter (empty = all)
    rules_exclude: list[str]            # [cis].rules_exclude — rule-id filter (wins over include)
    rules_overrides: dict[str, dict[str, Any]]    # [cis.overrides] — per-rule param deep-merge (rule_id -> {param: value})
    notify_webhook: str                 # [notify].webhook — WeCom group-robot webhook URL ("" = off)
    notify_on: str                      # [notify].on — "always" | "success" | "failure" (default "failure")
    deploy_webhook: str                 # [notify].deploy_webhook — POST image metadata on build success ("" = off)
    sign_key: str                       # [sign].gpg_key — GPG key id/fingerprint for SLSA provenance signing ("" = off)
    test_components: list[str]          # [meta].test_components — user-defined test scripts run before snapshot
    verify_boot: bool                   # [meta].verify_boot — boot a probe instance from the produced image and re-audit before declaring success (default false)
    packer_extra: dict[str, Any] = field(default_factory=dict)  # [build.packer] — arbitrary packer tencentcloud-cvm builder args (passthrough)

def _validate_value_present(label: str, value: Any) -> str | None:
    """Return an error message if *value* looks like a placeholder, else None."""
    if value is None or (isinstance(value, str) and not value):
        return f"{label}: cannot be empty"
    if (isinstance(value, str)
            and re.search(r"(?<![0-9a-f])x{8,}(?![0-9a-f])", value, re.IGNORECASE)):
        return f"{label}: still placeholder '{value}'"
    return None

def load_config(path: Path) -> dict[str, Any]:
    """Load and validate cis-image.toml.  Raises ConfigError on invalid input."""
    if not path.exists():
        raise ConfigError(
            f"Configuration file not found: {path}\n"
            f"  Run 'cis-image init' to generate a template."
        )

    try:
        data = tomllib.loads(path.read_bytes().decode("utf-8"))
    except Exception as exc:
        raise ConfigError(f"Failed to parse {path}: {exc}") from exc

    required: dict[str, list[str]] = {
        "build": [
            "profile", "region", "zone", "instance_type", "source_image_id",
            "vpc_id", "subnet_id", "security_group_id", "associate_public_ip",
        ],
        "image": ["name_prefix", "copy_regions"],
        "cis": ["level"],
        "cloud": ["secret_id_env", "secret_key_env"],
    }

    for section, keys in required.items():
        if section not in data:
            raise ConfigError(f"Missing [{section}] section in configuration")
        for key in keys:
            if key not in data[section]:
                raise ConfigError(f"Missing field: [{section}].{key}")

    profile_name = str(data.get("build", {}).get("profile", ""))
    if profile_name not in PROFILES:
        raise ConfigError(
            f"Unknown profile: {profile_name}\n"
            f"  Valid choices: {PROFILE_NAMES_HELP}"
        )

    level = data["cis"]["level"]
    if level not in (1, 2):
        raise ConfigError(f"[cis].level must be 1 or 2, got: {level}")

    itype = str(data["build"]["instance_type"])
    if "." not in itype:
        raise ConfigError(
            f"[build].instance_type '{itype}' is missing the CVM prefix.\n"
            f"  Use the full specifier, e.g. 'S5.MEDIUM2' (not 'S5-MEDIUM2')."
        )

    if not str(data["build"]["security_group_id"]).startswith("sg-"):
        warn(f"[build].security_group_id '{data['build']['security_group_id']}' "
             f"does not look like a security group ID (should start with 'sg-').")

    if not isinstance(data["build"]["associate_public_ip"], bool):
        raise ConfigError(
            f"[build].associate_public_ip must be a boolean, got "
            f"{type(data['build']['associate_public_ip']).__name__}. "
            f"Use true/false without quotes."
        )

    copy_regions_raw = data["image"]["copy_regions"]
    if not isinstance(copy_regions_raw, list):
        raise ConfigError(
            f"[image].copy_regions must be a list, got {type(copy_regions_raw).__name__}."
        )
    for region in copy_regions_raw:
        region_str = str(region)
        if not region_str or not all(c.isalnum() or c == "-" for c in region_str):
            warn(f"[image].copy_regions entry '{region_str}' does not look like a Tencent region code.")

    for label, key, prefix in [
        ("source image ID", "source_image_id", "img-"),
        ("VPC ID", "vpc_id", "vpc-"),
        ("subnet ID", "subnet_id", "subnet-"),
    ]:
        val = str(data["build"][key])
        if not val.startswith(prefix):
            warn(f"[build].{key} '{val}' does not look like a {label} (should start with '{prefix}').")

    return data

_CIS_REGION_DASHES = str.maketrans({
    "\u2010": "-",  # hyphen
    "\u2011": "-",  # non-breaking hyphen
    "\u2012": "-",  # figure dash
    "\u2013": "-",  # en dash
    "\u2014": "-",  # em dash
    "\u2015": "-",  # horizontal bar
    "\u2212": "-",  # minus sign
    "\uFF0D": "-",  # fullwidth hyphen-minus
})

def _sanitize_region_zone(value: str, label: str) -> str:
    """Replace non-ASCII dashes with regular ASCII hyphen '-'."""
    cleaned = str(value).translate(_CIS_REGION_DASHES)
    if cleaned != value:
        warn(f"{label} '{value}' contains a non-ASCII dash — "
             f"auto-corrected to '{cleaned}'")
    return cleaned

def resolve(data: dict[str, Any]) -> ResolvedConfig:
    """Flatten raw config + profile lookup into a ResolvedConfig."""
    profile_name: str = data["build"]["profile"]
    p = PROFILES[profile_name]
    meta: dict[str, Any] = data.get("meta", {})
    level: int = int(data["cis"]["level"])
    family: str = str(p.get("family", ""))

    copy_regions_raw = data["image"]["copy_regions"]
    if not isinstance(copy_regions_raw, list):
        raise ConfigError(
            f"[image].copy_regions must be a list, got {type(copy_regions_raw).__name__}. "
            f"Use [] for no copy or ['ap-shanghai'] for cross-region copy."
        )
    copy_regions: list[str] = [
        _sanitize_region_zone(str(r), "[image].copy_regions") for r in copy_regions_raw
    ]

    # Explicit None checks — `or` would silently discard a configured 0.
    _ssh_port_raw = meta.get("ssh_port")
    if _ssh_port_raw in (None, ""):
        _ssh_port_raw = p.get("ssh_port", 22)
    ssh_port = int(_ssh_port_raw)
    if not (1 <= ssh_port <= 65535):
        raise ConfigError(f"[meta].ssh_port must be 1-65535, got {ssh_port}")
    ssh_timeout = str(meta.get("ssh_timeout") or p.get("ssh_timeout") or "15m")

    # [image].name — optional fixed image name; empty means auto-generate.
    image_name_override = str(data.get("image", {}).get("name", "")).strip()
    if image_name_override:
        if len(image_name_override) < 1 or len(image_name_override) > 60:
            raise ConfigError(
                f"[image].name must be 1-60 characters, got {len(image_name_override)}")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", image_name_override):
            raise ConfigError(
                f"[image].name contains invalid characters: {image_name_override!r}. "
                "Use letters, digits, dot, dash, underscore only.")

    # [build].instance_name — optional explicit name for the temporary build
    # CVM (the machine Packer launches and hardens before snapshotting). Empty
    # means the Packer plugin auto-generates it. Used by the E2E runner to tag
    # target machines with a recognizable CIS_E2E_* prefix.
    instance_name = str(data.get("build", {}).get("instance_name", "")).strip()
    if instance_name:
        if len(instance_name) > 60:
            raise ConfigError(
                f"[build].instance_name must be <= 60 characters, "
                f"got {len(instance_name)}")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", instance_name):
            raise ConfigError(
                f"[build].instance_name contains invalid characters: {instance_name!r}. "
                "Use letters, digits, dot, dash, underscore only.")

    # [build.packer] — passthrough of arbitrary packer tencentcloud-cvm builder
    # args (e.g. disk_type, disk_size, data_disks, internet_max_bandwidth_out).
    # The user's own toml is trusted; value legality is enforced at render time
    # by _format_hcl_value. This lets cis-image inherit the full packer
    # capability set without hardcoding each argument.
    packer_extra = dict(data.get("build", {}).get("packer", {}) or {})
    for k in packer_extra:
        if not isinstance(k, str):
            raise ConfigError("[build.packer] keys must be strings")

    # [cloud].assume_role_* — group-account (organization) cross-account builds.
    # When set, Packer assumes the target account's CAM role with the local
    # AK/SK before launching the build instance.
    assume_role_arn = str(data.get("cloud", {}).get("assume_role_arn", "")).strip()
    if assume_role_arn and not re.fullmatch(r"[A-Za-z0-9:_/-]+", assume_role_arn):
        raise ConfigError(
            f"[cloud].assume_role_arn contains invalid characters: "
            f"{assume_role_arn!r}. Expected a CAM role ARN like "
            "qcs::cam::uin/12345:roleName/CrossAccountBuilder")
    assume_role_session = str(data.get("cloud", {}).get("assume_role_session", "cis-image")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_=,.@-]+", assume_role_session):
        raise ConfigError(
            f"[cloud].assume_role_session contains invalid characters: {assume_role_session!r}")
    assume_role_duration = int(data.get("cloud", {}).get("assume_role_duration", 7200))
    if not (0 <= assume_role_duration <= 43200):
        raise ConfigError(
            f"[cloud].assume_role_duration must be 0-43200, got {assume_role_duration}")

    # [meta].smoke_test — instance-level checks before the snapshot (default on).
    smoke_test = bool(data.get("meta", {}).get("smoke_test", True))

    # [notify] — WeCom group-robot webhook; empty webhook disables notifications.
    notify_webhook = str(data.get("notify", {}).get("webhook", "")).strip()
    notify_on = str(data.get("notify", {}).get("on", "failure")).strip().lower()
    if notify_on not in ("always", "success", "failure"):
        raise ConfigError(
            f"[notify].on must be one of always|success|failure, got {notify_on!r}")

    # [sign] — GPG key for SLSA-style provenance signing ("" = off).
    sign_key = str(data.get("sign", {}).get("gpg_key", "")).strip()

    # [cis].rules_include / rules_exclude — optional rule-id filters.
    rules_include = [str(x).strip() for x in data.get("cis", {}).get("rules_include", []) if str(x).strip()]
    rules_exclude = [str(x).strip() for x in data.get("cis", {}).get("rules_exclude", []) if str(x).strip()]
    if rules_include and rules_exclude:
        overlap = sorted(set(rules_include) & set(rules_exclude))
        if overlap:
            raise ConfigError(
                f"[cis] rules_include and rules_exclude overlap: {overlap}")

    # [cis.overrides] — per-rule parameter deep-merge (rule_id -> {param: value}).
    # Mirrors ansible-lockdown's per-control vars: tune a rule's parameters
    # without editing the bundled catalog.  Keys must be dotted rule IDs.
    overrides_raw = data.get("cis", {}).get("overrides", {})
    if not isinstance(overrides_raw, dict):
        raise ConfigError(
            f"[cis].overrides must be a table of rule_id -> params, got "
            f"{type(overrides_raw).__name__}.")
    rules_overrides: dict[str, dict[str, Any]] = {}
    for rid, params in overrides_raw.items():
        rid = str(rid).strip()
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", rid):
            raise ConfigError(
                f"[cis].overrides key {rid!r} is not a dotted CIS rule ID "
                "(e.g. \"5.2.2\").")
        if not isinstance(params, dict):
            raise ConfigError(
                f"[cis].overrides.{rid} must be a table of parameter values, "
                f"got {type(params).__name__}.")
        rules_overrides[rid] = {str(k): v for k, v in params.items()}

    # [meta].cve_scan / [meta].sbom — optional supply-chain gates.
    cve_scan = bool(data.get("meta", {}).get("cve_scan", False))
    sbom = bool(data.get("meta", {}).get("sbom", False))

    # [image].share_accounts — cross-account image sharing (empty = off).
    share_accounts = [str(x).strip() for x in data.get("image", {}).get("share_accounts", []) if str(x).strip()]
    for acc in share_accounts:
        if not re.fullmatch(r"uin/[0-9]+", acc):
            raise ConfigError(
                f"[image].share_accounts entry {acc!r} is not a valid "
                "Tencent Cloud account ID (expected \"uin/1234567890\").")

    # [image].share_org_units — org-level sharing (same API as share_accounts).
    share_org_units = [str(x).strip() for x in data.get("image", {}).get("share_org_units", []) if str(x).strip()]
    for acc in share_org_units:
        if not re.fullmatch(r"uin/[0-9]+", acc):
            raise ConfigError(
                f"[image].share_org_units entry {acc!r} is not a valid "
                "Tencent Cloud account ID (expected \"uin/1234567890\").")

    # [build].spot — spot instance for the build VM (up to ~90% cheaper).
    spot = bool(data.get("build", {}).get("spot", False))

    # [meta].test_components — user-defined test scripts run before snapshot.
    test_components = [str(x).strip() for x in data.get("meta", {}).get("test_components", []) if str(x).strip()]

    # [meta].verify_boot — clean-boot verification after the snapshot.
    verify_boot = bool(data.get("meta", {}).get("verify_boot", False))

    # [cis].min_score — post-reboot audit gate (0 disables; default 85).
    min_score = int(data.get("cis", {}).get("min_score", 85))

    return ResolvedConfig(
        profile_name=profile_name,
        profile=p,
        family=family,
        region=_sanitize_region_zone(str(data["build"]["region"]), "[build].region"),
        zone=_sanitize_region_zone(str(data["build"]["zone"]), "[build].zone"),
        instance_type=str(data["build"]["instance_type"]),
        source_image_id=str(data["build"]["source_image_id"]),
        vpc_id=str(data["build"]["vpc_id"]),
        subnet_id=str(data["build"]["subnet_id"]),
        security_group_id=str(data["build"]["security_group_id"]),
        associate_public_ip=bool(data["build"]["associate_public_ip"]),
        ssh_port=ssh_port,
        ssh_timeout=ssh_timeout,
        ssh_username=str(p.get("ssh_username", "")),
        ssh_debug_password=str(meta.get("ssh_debug_password", "")),
        winrm_username=str(p.get("winrm_username", "")),
        winrm_password_env=str(data.get("cloud", {}).get("winrm_password_env", "WINRM_PASSWORD")),
        image_name_prefix=str(data["image"]["name_prefix"]),
        image_name_override=image_name_override,
        instance_name=instance_name,
        packer_extra=packer_extra,
        image_copy_regions=copy_regions,
        image_share_accounts=share_accounts,
        image_share_org_units=share_org_units,
        spot=spot,
        cis_level_tag=f"level{level}-server",
        secret_id_env=str(data["cloud"]["secret_id_env"]),
        secret_key_env=str(data["cloud"]["secret_key_env"]),
        security_token_env=str(data.get("cloud", {}).get("security_token_env", "TENCENTCLOUD_SECURITY_TOKEN")),
        assume_role_arn=assume_role_arn,
        assume_role_session=assume_role_session,
        assume_role_duration=assume_role_duration,
        image_os_tag=str(meta.get("os_tag", p.get("os_tag", ""))),
        image_benchmark=str(meta.get("benchmark", p.get("benchmark", ""))),
        level=level,
        role_dir=str(p["role_dir"]),
        smoke_test=smoke_test,
        cve_scan=cve_scan,
        sbom=sbom,
        rules_include=rules_include,
        rules_exclude=rules_exclude,
        rules_overrides=rules_overrides,
        min_score=min_score,
        notify_webhook=notify_webhook,
        notify_on=notify_on,
        deploy_webhook=str(data.get("notify", {}).get("deploy_webhook", "")).strip(),
        sign_key=sign_key,
        test_components=test_components,
        verify_boot=verify_boot,
    )

def _lineage_path() -> Path:
    return Path.home() / ".cis-image" / "lineage.jsonl"

def _reports_dir() -> Path:
    return Path.home() / ".cis-image" / "reports"
