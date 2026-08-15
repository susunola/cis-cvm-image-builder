#!/usr/bin/env python3
"""
cis-image — CIS-hardened Golden Image Builder (Packer × Tencent Cloud CVM)

Spins up an ephemeral CVM, applies the bundled cis-os engine role for CIS
hardening, and captures the result as a custom image.  All configuration is
driven by cis-image.toml — no manual template editing.

Supported OS: Ubuntu 20/22/24, RHEL 8/9/10, TencentOS 3/4,
              Windows Server 2016/2019/2022/2025

Engine:  Bundled cis_engine.py (Linux) / cis_engine.ps1 (Windows).
         In-role gate via cis_min_score (post-reboot audit must score >= 85).
         Roles ship inside the package (cis_image/roles/) — no network at build time.

Dependencies: Python >= 3.11 (stdlib only), Packer >= 1.12, ansible-core >= 2.15.

Usage:
    cis-image init [--target DIR]      # Generate cis-image.toml
    cis-image preflight [--config F]   # Pre-flight check
    cis-image validate  [--config F]   # Render + packer init + packer validate
    cis-image build     [--config F]   # Render + packer build (produce image)
    cis-image clean     [--config F]   # Remove rendered working directory
"""
from __future__ import annotations

# Module aliases kept at package scope so `cis_image.subprocess`, `cis_image.sys`,
# `cis_image.urllib`, etc. still resolve (some tests/tools reference them).
import subprocess  # noqa: F401
import sys  # noqa: F401
import urllib.request  # noqa: F401

__all__ = [
    'CVE_SCAN_LINUX_BLOCK', 'ConfigError', 'DEFAULT_WORKDIR', 'FINALIZE_SH_TEMPLATE', 'HCL_LINUX_TEMPLATE', 'HCL_WIN_TEMPLATE',
    'HOSTS_FIX_SNIPPET', 'IDEMPOTENCY_LINUX_BLOCK', 'INSTALL_SH_TEMPLATE', 'PACKER_TIMEOUT_MINUTES', 'PROFILES', 'PROFILE_NAMES_HELP',
    'PackerResult', 'ResolvedConfig', 'SAMPLE_CONFIG', 'SBOM_LINUX_BLOCK', 'SITE_AUDIT_TEMPLATE', 'SITE_YML_TEMPLATE',
    'SITE_YML_WIN_TEMPLATE', 'SMOKE_LINUX_BLOCK', 'SMOKE_WIN_BLOCK', 'TEST_COMPONENTS_LINUX_BLOCK', 'TEST_COMPONENTS_WIN_BLOCK', 'VERSION',
    '_BANNER_ART', '_CIS_REGION_DASHES', '_FORBIDDEN_CLEAN_PREFIXES', '_RULE_FAIL_RE', '_apply_rule_overrides', '_assert_no_markers',
    '_audit_inspec', '_audit_oscap', '_audit_render', '_audit_results_sarif', '_audit_results_xccdf', '_audit_ssh_args',
    '_build_fingerprint', '_build_sarif', '_build_xccdf', '_bundle_role', '_bundled_rules_hash', '_check_ansible_windows_collection',
    '_check_bundled_role', '_check_pywinrm', '_check_security_group_ingress', '_clean_is_safe', '_color', '_delete_images',
    '_drift_diff', '_extract_image_ids', '_extract_rule_statuses', '_extract_sbom_count', '_extract_sbom_sha', '_extract_score',
    '_fetch_baseline', '_find_provenance', '_format_hcl_value', '_image_ids_still_exist', '_image_is_shared', '_image_name',
    '_images_exist', '_is_interactive', '_last_num', '_last_successful_fingerprint', '_lineage_path', '_load_resolve_preflight',
    '_my_public_ip', '_parse_failed_rules', '_parse_inspec_json', '_parse_kitty_csv', '_parse_oscap_arf', '_probe_launch',
    '_probe_public_ip', '_probe_scan', '_probe_ssh_ready', '_probe_terminate', '_record_lineage', '_reports_dir',
    '_rhel_profile', '_sanitize_region_zone', '_save_build_report', '_send_notification', '_setup_logging', '_sg_ingress_allows',
    '_share_images', '_source_image_created', '_tc3_api', '_tlinux_profile', '_trigger_deploy_webhook', '_ubuntu_profile',
    '_validate_env_var_name', '_validate_shell_arg', '_validate_value_present', '_write_provenance', '_write_sarif', '_write_xccdf',
    '_yaml_list', 'banner', 'build_parser', 'cmd_audit', 'cmd_build', 'cmd_check_source',
    'cmd_clean', 'cmd_cleanup_images', 'cmd_drift', 'cmd_images', 'cmd_init', 'cmd_list',
    'cmd_pending', 'cmd_preflight', 'cmd_save_baseline', 'cmd_scan', 'cmd_test', 'cmd_validate',
    'cmd_verify', 'cmd_verify_image', 'fail', 'info', 'load_config', 'logger',
    'main', 'ok', 'render_all', 'render_finalize', 'render_install', 'render_pkrvars',
    'render_site', 'render_site_audit', 'resolve', 'run_packer', 'run_preflight', 'warn',
]


from ._audit import (
    _RULE_FAIL_RE,
    _audit_inspec,
    _audit_oscap,
    _audit_render,
    _audit_results_sarif,
    _audit_results_xccdf,
    _audit_ssh_args,
    _build_sarif,
    _build_xccdf,
    _drift_diff,
    _extract_rule_statuses,
    _parse_failed_rules,
    _parse_inspec_json,
    _parse_kitty_csv,
    _parse_oscap_arf,
    _write_sarif,
    _write_xccdf,
    cmd_audit,
)
from ._cli import build_parser, main
from ._commands import (
    _FORBIDDEN_CLEAN_PREFIXES,
    _clean_is_safe,
    _load_resolve_preflight,
    cmd_build,
    cmd_check_source,
    cmd_clean,
    cmd_cleanup_images,
    cmd_drift,
    cmd_images,
    cmd_init,
    cmd_list,
    cmd_pending,
    cmd_preflight,
    cmd_save_baseline,
    cmd_scan,
    cmd_test,
    cmd_validate,
    cmd_verify,
    cmd_verify_image,
)
from ._config import (
    _CIS_REGION_DASHES,
    PackerResult,
    ResolvedConfig,
    _lineage_path,
    _reports_dir,
    _sanitize_region_zone,
    _validate_value_present,
    load_config,
    resolve,
)
from ._logging import (
    VERSION,
    ConfigError,
    _color,
    _setup_logging,
    banner,
    fail,
    info,
    logger,
    ok,
    warn,
)
from ._packer import (
    PACKER_TIMEOUT_MINUTES,
    _extract_image_ids,
    _extract_sbom_count,
    _extract_sbom_sha,
    _extract_score,
    _is_interactive,
    _last_num,
    run_packer,
    run_preflight,
)
from ._profiles import (
    DEFAULT_WORKDIR,
    PROFILE_NAMES_HELP,
    PROFILES,
    SAMPLE_CONFIG,
    _rhel_profile,
    _tlinux_profile,
    _ubuntu_profile,
)
from ._render import (
    _apply_rule_overrides,
    _assert_no_markers,
    _bundle_role,
    _check_ansible_windows_collection,
    _check_bundled_role,
    _check_pywinrm,
    _format_hcl_value,
    _image_name,
    _validate_env_var_name,
    _validate_shell_arg,
    _yaml_list,
    render_all,
    render_finalize,
    render_install,
    render_pkrvars,
    render_site,
    render_site_audit,
)
from ._reports import (
    _build_fingerprint,
    _bundled_rules_hash,
    _find_provenance,
    _last_successful_fingerprint,
    _record_lineage,
    _save_build_report,
    _send_notification,
    _trigger_deploy_webhook,
    _write_provenance,
)
from ._tc_cloud import (
    _check_security_group_ingress,
    _delete_images,
    _fetch_baseline,
    _image_ids_still_exist,
    _image_is_shared,
    _images_exist,
    _my_public_ip,
    _probe_launch,
    _probe_public_ip,
    _probe_scan,
    _probe_ssh_ready,
    _probe_terminate,
    _sg_ingress_allows,
    _share_images,
    _source_image_created,
    _tc3_api,
)
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

if __name__ == "__main__":
    sys.exit(main())
