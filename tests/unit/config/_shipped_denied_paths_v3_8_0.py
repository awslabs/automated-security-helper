"""The default MCP ``denied_paths`` list that release v3.8.0 shipped, as a literal.

Provenance. Captured from the bytes of the ``v3.8.0`` tag (tree
``b90cae76d4fd4b04f933047e6a7f8b640723115b``, the same under both tag commits
``c43eebf329cc2c48526c7a40724ffecc9fe6507e`` and
``f356ca77388a4c58bcf25d904a21121ab8872a66``):

- ``automated_security_helper/config/ash_config.py`` lines 1326-1529: the
  ``denied_paths`` field of ``RuntimeOverridesConfig``; its 98 string literals
  are lines 1348-1529 before the last element, and the last element,
  ``*ARCHIVE_LIMIT_RUNTIME_PATHS``, is expanded below;
- ``automated_security_helper/plugin_modules/ash_builtin/converters/archive_converter.py``
  lines 213-218: ``EXTRACTION_LIMIT_OPTIONS``, whose four names make the
  ``/converters/archive/options/<name>`` entries ``ARCHIVE_LIMIT_RUNTIME_PATHS``
  holds (``ash_config.py`` lines 1246-1247 at the tag).

``ash config init`` at v3.8.0 writes this list, in this order, as
``global_settings.mcp.runtime_overrides.denied_paths`` (102 entries). The list is
kept here, outside ``SHIPPED_DEFAULT_DENIED_PATHS``, so that a later edit of the
table cannot change what the test of the table measures it against. Do not edit
it: it records a released list.
"""

from __future__ import annotations

from typing import Tuple

V3_8_0_DEFAULT_DENIED_PATHS: Tuple[str, ...] = (
    "/fail_on_findings",
    "/fail_on_incomplete_scanners",
    "/content_db_staleness",
    "/content_db_staleness_overrides",
    "/honor_ignore_files",
    "/content_db_staleness_offline_image_default",
    "/sandbox",
    "/sandbox/**",
    "/ash_plugin_modules",
    "/ash_plugin_modules/**",
    "/scanners/detect-secrets/options/scan_settings/filters_used",
    "/scanners/detect-secrets/options/scan_settings/filters_used/**",
    "/scanners/detect-secrets/options/scan_settings/plugins_used",
    "/scanners/detect-secrets/options/scan_settings/plugins_used/**",
    "/scanners/detect-secrets/options/baseline_file",
    "/global_settings/ignore_paths",
    "/global_settings/suppressions",
    "/global_settings/mcp",
    "/global_settings/mcp/**",
    "/scanners/opengrep/options/exclude_rule",
    "/scanners/semgrep/options/exclude_rule",
    "/scanners/bandit/options/confidence_level",
    "/scanners/checkov/options/frameworks",
    "/scanners/checkov/options/skip_frameworks",
    "/scanners/opengrep/options/config",
    "/scanners/opengrep/options/patterns",
    "/scanners/opengrep/options/severity",
    "/scanners/semgrep/options/config",
    "/scanners/semgrep/options/severity",
    "/scanners/detect-secrets/options/scan_settings",
    "/scanners/cdk-nag/options/nag_packs/AwsSolutionsChecks",
    "/scanners/ferret-scan/options/checks",
    "/scanners/ferret-scan/options/confidence_levels",
    "/scanners/ferret-scan/options/disable_ip_types",
    "/scanners/ferret-scan/options/enable_preprocessors",
    "/scanners/ferret-scan/options/finding_limit",
    "/scanners/ferret-scan/options/profile",
    "/scanners/ferret-scan/options/recursive",
    "/scanners/ferret-scan/options/respect_gitignore",
    "/scanners/ferret-scan/options/use_default_config",
    "/scanners/ferret-scan/options/validator_budget",
    "/scanners/trivy-repo/options/license_full",
    "/scanners/trivy-repo/options/scanners",
    "/scanners/cfn-guard/options/rule_sets",
    "/scanners/cfn-lint/options/ignore_checks",
    "/scanners/cfn-lint/options/regions",
    "/scanners/gitleaks/options/baseline_path",
    "/scanners/trivy/options/scanners",
    "/scanners/trivy/options/ignore_unfixed",
    "/scanners/*/options/offline",
    "/scanners/ferret-scan/options/max_live_bytes",
    "/scanners/gitleaks/options/max_target_megabytes",
    "/scanners/bandit/options/config_file",
    "/scanners/checkov/options/config_file",
    "/scanners/ferret-scan/options/config_file",
    "/scanners/grype/options/config_file",
    "/scanners/syft/options/config_file",
    "/scanners/trivy-repo/options/secret_config_file",
    "/scanners/trivy-repo/options/config_file",
    "/scanners/trivy-repo/options/module_dir",
    "/scanners/trivy/options/config_file",
    "/scanners/trivy/options/secret_config_file",
    "/scanners/actionlint/options/config_file",
    "/scanners/actionlint/options/shellcheck",
    "/scanners/actionlint/options/pyflakes",
    "/scanners/cfn-guard/options/rules_paths",
    "/scanners/cfn-lint/options/config_file",
    "/scanners/gitleaks/options/config_file",
    "/scanners/zizmor/options/config_file",
    "/scanners/zizmor/options/online_audits",
    "/scanners/snyk-code/options/honor_tree_exclusions",
    "/scanners/cfn-lint/options/honor_inline_ignores",
    "/scanners/gitleaks/options/honor_inline_ignores",
    "/scanners/zizmor/options/honor_inline_ignores",
    "/scanners/*/options/tool_version",
    "/converters/jupyter/options/tool_version",
    "/scanners/opengrep/options/version",
    "/scanners/opengrep/options/sha256",
    "/scanners/opengrep/options/metrics",
    "/scanners/semgrep/options/metrics",
    "/reporters/bedrock-summary-reporter/options/aws_*",
    "/reporters/cloudwatch-logs/**",
    "/reporters/aws-security-hub/**",
    "/reporters/bedrock-summary-reporter/options/model_id",
    "/reporters/bedrock-summary-reporter/options/output_file",
    "/reporters/bedrock-summary-reporter/options/output_executive_file",
    "/reporters/bedrock-summary-reporter/options/output_technical_file",
    "/reporters/s3/**",
    "/reporters/bedrock-summary-reporter/**",
    "/reporters/gitlab-sast/options/exclude_suppressed",
    "/scanners/detect-secrets/**",
    "/scanners/npm-audit/**",
    "/scanners/opengrep/**",
    "/scanners/semgrep/**",
    "/scanners/snyk-code/**",
    "/scanners/trivy-repo/**",
    "/scanners/trivy/**",
    "/scanners/zizmor/**",
    # *ARCHIVE_LIMIT_RUNTIME_PATHS, expanded from EXTRACTION_LIMIT_OPTIONS.
    "/converters/archive/options/max_members",
    "/converters/archive/options/max_member_bytes",
    "/converters/archive/options/max_total_bytes",
    "/converters/archive/options/max_compression_ratio",
)
