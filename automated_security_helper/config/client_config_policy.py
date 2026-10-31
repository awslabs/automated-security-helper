# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file an MCP client delivered may not set what the runtime policy denies.

Why this exists
---------------
``global_settings.mcp.runtime_overrides.denied_paths`` and ``denied_value_patterns``
keep fields such as a reporter's AWS region out of what an MCP client may change
through ``select_profile``'s ``patch_ops`` and ``override_yaml`` and the
workspace tools' ``config_overrides``. A client can also hand the server a whole
config file: an upload named as a scan's ``config_path``, the ``.ash.yaml`` of a
tree it delivered, or a project config inside a delivered workspace. Before this,
such a file set those fields freely. Now every file of a config's chain that a
client delivered (``cli/mcp/sandbox.config_is_client_supplied``) is checked
against the same rules with the same matcher,
``runtime_patch.config_document_denials``.

What is checked, and against what
---------------------------------
Each client-delivered file's own document, as resolution parsed it
(``ResolvedConfigDocument.documents``), so a file swapped between the read and
the check cannot slip through. Every leaf it sets and every op of its ``patch``.
A base it extends is checked only if a client delivered that base too: an
operator's base may set what the operator likes.

A leaf whose value equals the trusted config's value at the same pointer changes
nothing and is accepted, so a delivered ``ash config init`` file, which writes
the defaults, resolves. A ``patch`` op is refused whatever it writes.

``/sandbox`` and ``/ash_plugin_modules`` are not checked here. For a
client-delivered file both are already restrict-only: ``sandbox_grants`` keeps
its grants out and lets its mode only turn the sandbox on, and
``plugin_module_trust`` keeps only installed modules outside the scanned tree and
outside every git checkout (a virtualenv inside a checkout counts as inside), and
no package that sends findings or source off the host. Refusing them as well would
refuse a file that tightens the sandbox.

The rules are a ``ClientConfigRules``: the policy and the trusted config it came
from. The MCP tools pass the session's, taken from the registered profile the
session bound (never from the session's materialized config, which a client's
``patch_ops`` wrote). Other callers get the trusted base resolve_config would
use: the operator config at ``trusted_config_path``, else the server's default
config.

The check is keyed on where a file is, not on who calls: a CLI resolve of a file
under the MCP workspace root is checked too. A file is judged by every path it
was reached by (``config_sources.ResolvedConfigDocument.names``) and every
symlink on the way, so a file outside the root that a delivered link reaches is
checked as a delivered file, and its suppressions, ignore paths and scanner
exclusions are marked and moved as a delivered file's are.

Rejected alternatives
---------------------
* Comparing the resolved config with the trusted base. A client's file replaces
  the profile rather than overlaying it, so a field the file leaves out returns
  to its default, which reads as a change the client never wrote. Only the
  leaves the file writes are compared.
* Applying the denials to every in-tree config. ``denied_paths`` describes what
  an MCP client may change; on the CLI, a repository's ``fail_on_findings`` is
  not a client's, and refusing it would break ordinary scans.
* Re-reading each file for the check. The file can change between that read and
  resolution's.
"""

from __future__ import annotations

import copy
import importlib
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from pydantic import BaseModel, ConfigDict

from automated_security_helper.config.ash_config import (
    ALWAYS_DENIED_PATHS,
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.operator_only_options import (
        RepositorySettings,
    )

#: Decision point 1: whether a delivered repository's own suppressions and ignore
#: paths are honored, as the CLI honors a repository's. True (the decision taken)
#: exempts ``global_settings.suppressions`` and ``global_settings.ignore_paths``
#: from the default ``denied_paths`` for a delivered config, and marks each entry
#: it supplies ``client_supplied`` so results show it came from the client. An
#: operator who lists either in the profile's own ``denied_paths`` still has it
#: refused. False checks them like any other denied field.
HONOR_DELIVERED_SUPPRESSIONS: bool = True

#: Decision point 2: what happens to a delivered config that sets a denied field.
#: "refuse" (the decision taken) refuses the config with
#: ``ASHConfigFieldDeniedError`` naming every such field. "drop" resolves it with
#: each such field returned to the trusted config's value, and adds a warning
#: naming them to the config's resolution warnings, which a scan's results carry
#: as config_warning validation checkpoints.
DENIED_FIELD_HANDLING: Literal["refuse", "drop"] = "refuse"

#: Bounded for a client-delivered file by ``sandbox_grants`` and
#: ``plugin_module_trust``; see the module docstring. Exempt from the default
#: ``denied_paths`` only.
RESTRICT_ONLY_PATHS: Tuple[str, ...] = (
    "/sandbox",
    "/sandbox/**",
    "/ash_plugin_modules",
    "/ash_plugin_modules/**",
)

#: Exempt from the default ``denied_paths`` when ``HONOR_DELIVERED_SUPPRESSIONS``.
SUPPRESSION_PATHS: Tuple[str, ...] = (
    "/global_settings/suppressions",
    "/global_settings/suppressions/**",
    "/global_settings/ignore_paths",
    "/global_settings/ignore_paths/**",
)

#: No effect in a client-delivered file: the policy never comes from one, and
#: ``global_settings.mcp`` holds only the policy. Not checked there at all, so a
#: delivered ``ash config init`` file, which writes the default policy, scans
#: under a profile whose policy differs.
INERT_PATHS: Tuple[str, ...] = ("/global_settings/mcp", "/global_settings/mcp/**")

#: Every ``RuntimeOverridesConfig.denied_paths`` default ASH has shipped, oldest
#: first, as sets, and last the current default. A profile whose list equals one
#: of these, as ``ash config init`` writes it, counts as using the default rather
#: than choosing its own, and gets the current list (``effective_policy``); only
#: an edited list is the operator's explicit choice. When the default changes,
#: replace the last entry if no release has shipped it, else add the new list
#: after it (``test_the_current_default_is_a_shipped_default``).
SHIPPED_DEFAULT_DENIED_PATHS: Tuple[FrozenSet[str], ...] = tuple(
    frozenset(entries)
    for entries in (
        (
            "/fail_on_findings",
            "/global_settings/ignore_paths",
            "/global_settings/suppressions",
            "/reporters/bedrock-summary-reporter/options/aws_*",
            "/reporters/cloudwatch-logs/**",
        ),
        (
            "/fail_on_findings",
            "/fail_on_incomplete_scanners",
            "/global_settings/ignore_paths",
            "/global_settings/suppressions",
            "/reporters/bedrock-summary-reporter/options/aws_*",
            "/reporters/cloudwatch-logs/**",
        ),
        (
            "/fail_on_findings",
            "/fail_on_incomplete_scanners",
            "/content_db_staleness",
            "/global_settings/ignore_paths",
            "/global_settings/suppressions",
            "/reporters/bedrock-summary-reporter/options/aws_*",
            "/reporters/cloudwatch-logs/**",
        ),
        (
            "/fail_on_findings",
            "/fail_on_incomplete_scanners",
            "/content_db_staleness",
            "/content_db_staleness_overrides",
            "/global_settings/ignore_paths",
            "/global_settings/suppressions",
            "/reporters/bedrock-summary-reporter/options/aws_*",
            "/reporters/cloudwatch-logs/**",
        ),
        (
            "/fail_on_findings",
            "/fail_on_incomplete_scanners",
            "/content_db_staleness",
            "/content_db_staleness_overrides",
            "/sandbox",
            "/sandbox/**",
            "/global_settings/ignore_paths",
            "/global_settings/suppressions",
            "/reporters/bedrock-summary-reporter/options/aws_*",
            "/reporters/cloudwatch-logs/**",
        ),
        (
            "/fail_on_findings",
            "/fail_on_incomplete_scanners",
            "/content_db_staleness",
            "/content_db_staleness_overrides",
            "/sandbox",
            "/sandbox/**",
            "/ash_plugin_modules",
            "/ash_plugin_modules/**",
            "/global_settings/ignore_paths",
            "/global_settings/suppressions",
            "/reporters/bedrock-summary-reporter/options/aws_*",
            "/reporters/cloudwatch-logs/**",
        ),
        (
            "/fail_on_findings",
            "/fail_on_incomplete_scanners",
            "/content_db_staleness",
            "/content_db_staleness_overrides",
            "/sandbox",
            "/sandbox/**",
            "/ash_plugin_modules",
            "/ash_plugin_modules/**",
            "/global_settings/ignore_paths",
            "/global_settings/suppressions",
            "/global_settings/mcp",
            "/global_settings/mcp/**",
            "/scanners/opengrep/options/exclude_rule",
            "/scanners/semgrep/options/exclude_rule",
            "/scanners/detect-secrets/options/baseline_file",
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
            "/scanners/*/options/offline",
            "/scanners/ferret-scan/options/max_live_bytes",
            "/scanners/bandit/options/config_file",
            "/scanners/checkov/options/config_file",
            "/scanners/ferret-scan/options/config_file",
            "/scanners/grype/options/config_file",
            "/scanners/syft/options/config_file",
            "/scanners/trivy-repo/options/secret_config_file",
            "/scanners/snyk-code/options/honor_tree_exclusions",
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
        ),
        (
            "/fail_on_findings",
            "/fail_on_incomplete_scanners",
            "/content_db_staleness",
            "/content_db_staleness_overrides",
            "/honor_ignore_files",
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
            "/scanners/*/options/offline",
            "/scanners/ferret-scan/options/max_live_bytes",
            "/scanners/bandit/options/config_file",
            "/scanners/checkov/options/config_file",
            "/scanners/ferret-scan/options/config_file",
            "/scanners/grype/options/config_file",
            "/scanners/syft/options/config_file",
            "/scanners/trivy-repo/options/secret_config_file",
            "/scanners/snyk-code/options/honor_tree_exclusions",
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
            "/converters/archive/options/max_members",
            "/converters/archive/options/max_member_bytes",
            "/converters/archive/options/max_total_bytes",
            "/converters/archive/options/max_compression_ratio",
        ),
        (
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
            "/scanners/*/options/offline",
            "/scanners/ferret-scan/options/max_live_bytes",
            "/scanners/bandit/options/config_file",
            "/scanners/checkov/options/config_file",
            "/scanners/ferret-scan/options/config_file",
            "/scanners/grype/options/config_file",
            "/scanners/syft/options/config_file",
            "/scanners/trivy-repo/options/secret_config_file",
            "/scanners/snyk-code/options/honor_tree_exclusions",
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
            "/converters/archive/options/max_members",
            "/converters/archive/options/max_member_bytes",
            "/converters/archive/options/max_total_bytes",
            "/converters/archive/options/max_compression_ratio",
            "/scanners/cfn-guard/options/rule_sets",
            "/scanners/cfn-lint/options/ignore_checks",
            "/scanners/cfn-lint/options/regions",
            "/scanners/gitleaks/options/baseline_path",
            "/scanners/trivy/options/scanners",
            "/scanners/trivy/options/ignore_unfixed",
            "/scanners/gitleaks/options/max_target_megabytes",
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
            "/scanners/cfn-lint/options/honor_inline_ignores",
            "/scanners/gitleaks/options/honor_inline_ignores",
            "/scanners/zizmor/options/honor_inline_ignores",
        ),
    )
)


#: Defaults of the denied options of scanners that come from a plugin package
#: (ferret-scan, snyk-code, trivy-repo). The trusted config carries a built-in
#: scanner's defaults, so a delivered value equal to one is accepted as no
#: change; it need not carry a plugin's section at all, so without this a
#: delivered file that wrote such a default would be refused. Used only where
#: the trusted config has no value of its own. snyk-code's and trivy-repo's
#: whole sections are denied (``ALWAYS_DENIED_PATHS``), so every one of their
#: options is listed.
#: ``test_the_plugin_option_defaults_are_the_plugins`` derives the list from the
#: default ``denied_paths`` and checks each value against the plugin's model.
PLUGIN_OPTION_DEFAULTS: Mapping[Tuple[str, str], Any] = {
    ("ferret-scan", "checks"): "all",
    ("ferret-scan", "confidence_levels"): "all",
    ("ferret-scan", "config_file"): None,
    ("ferret-scan", "disable_ip_types"): None,
    ("ferret-scan", "enable_preprocessors"): True,
    ("ferret-scan", "finding_limit"): 0,
    ("ferret-scan", "max_live_bytes"): None,
    ("ferret-scan", "offline"): False,
    ("ferret-scan", "profile"): None,
    ("ferret-scan", "recursive"): True,
    ("ferret-scan", "respect_gitignore"): False,
    ("ferret-scan", "tool_version"): None,
    ("ferret-scan", "use_default_config"): True,
    ("ferret-scan", "validator_budget"): None,
    ("snyk-code", "honor_tree_exclusions"): False,
    ("snyk-code", "offline"): False,
    ("snyk-code", "scan_timeout"): 1800,
    ("snyk-code", "severity_threshold"): None,
    ("trivy-repo", "config_file"): None,
    ("trivy-repo", "disable_telemetry"): True,
    ("trivy-repo", "ignore_file"): None,
    ("trivy-repo", "ignore_unfixed"): True,
    ("trivy-repo", "license_full"): True,
    ("trivy-repo", "module_dir"): None,
    ("trivy-repo", "offline"): False,
    ("trivy-repo", "scan_timeout"): 1800,
    ("trivy-repo", "scanners"): ["vuln", "secret", "misconfig", "license"],
    ("trivy-repo", "secret_config_file"): None,
    ("trivy-repo", "severity_threshold"): None,
}


class ClientConfigRules(BaseModel):
    """The policy a client-delivered config is checked against, and its source."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    #: ``denied_paths`` and ``denied_value_patterns`` are what apply.
    policy: RuntimeOverridesConfig
    #: The trusted config the policy came from. A leaf equal to what it has is
    #: accepted, and its plugin sections add to the keys a glob is matched over.
    base: AshConfig
    #: Why the policy could not be established, or None. Held rather than raised,
    #: so only a config with a client-delivered file, or with overrides an MCP
    #: client supplied, is refused for it.
    unreadable: Optional[str] = None
    #: The MCP session the rules were built for, or None. Its ``config/``
    #: directory, and no other session's, holds files the operator set aside for
    #: it (``cli/mcp/sandbox.client_named_config_is_untrusted``).
    session_id: Optional[str] = None


def policy_of(config: AshConfig) -> RuntimeOverridesConfig:
    """``config``'s runtime-override policy, or the defaults when it sets none.

    The effective policy (``effective_policy``): a ``denied_paths`` list equal
    to one ASH shipped earlier is read as today's default list.
    """
    mcp = getattr(config.global_settings, "mcp", None)
    if mcp is None:
        return RuntimeOverridesConfig()
    return effective_policy(mcp.runtime_overrides)


#: The lists already warned about, each with whether it replaced the defaults.
_WARNED_REPLACEMENTS: Set[Tuple[bool, FrozenSet[str]]] = set()


def effective_policy(policy: RuntimeOverridesConfig) -> RuntimeOverridesConfig:
    """``policy`` with the ``denied_paths`` list that applies.

    * Unset, or equal to a list ASH has shipped (``policy_is_default``): the
      current default list. A profile an earlier ``ash config init`` wrote holds
      that release's list; a stale copy would otherwise let through what the
      defaults have since denied.
    * Any other list is added to the current defaults, so an operator who lists
      one more entry does not lift the rest. A list that holds some default
      entries and leaves others out reads as an edited copy of the defaults, so
      the ones it leaves out, which still apply, are named in a warning, once
      per list.
    * With ``replace_default_denied_paths``, the list is used as written, and
      each default entry it leaves out is named in a warning, once per list.
    * Whatever the list, the ALWAYS_DENIED_PATHS entries apply.

    The operator's own list, as written, is kept on the copy
    (``_listed_denied_paths``), since ``exempt_paths`` decides from what the
    operator wrote rather than from the merged list. Applying this to its own
    result changes nothing.
    """
    if policy._effective:
        return policy
    current = list(RuntimeOverridesConfig().denied_paths)
    listed: Optional[Tuple[str, ...]] = (
        None if policy_is_default(policy) else _written_denied_paths(policy)
    )
    if listed is None:
        effective = current
    elif policy.replace_default_denied_paths:
        effective = [
            *listed,
            *(entry for entry in ALWAYS_DENIED_PATHS if entry not in set(listed)),
        ]
        removed = [entry for entry in current if entry not in set(effective)]
        if removed and (True, frozenset(effective)) not in _WARNED_REPLACEMENTS:
            _WARNED_REPLACEMENTS.add((True, frozenset(effective)))
            ASH_LOGGER.warning(
                "runtime_overrides.replace_default_denied_paths is true, so these "
                f"default denied_paths entries do not apply: {', '.join(removed)}"
            )
    else:
        effective = current + [entry for entry in listed if entry not in set(current)]
        left_out = [entry for entry in current if entry not in set(listed)]
        if (
            left_out
            and set(listed) & set(current)
            and (False, frozenset(listed)) not in _WARNED_REPLACEMENTS
        ):
            _WARNED_REPLACEMENTS.add((False, frozenset(listed)))
            ASH_LOGGER.warning(
                "runtime_overrides.denied_paths leaves out these default entries, "
                "which still apply because the list adds to the defaults: "
                f"{', '.join(left_out)}. To use the list as written, set "
                "runtime_overrides.replace_default_denied_paths: true."
            )
    resolved = policy.model_copy(update={"denied_paths": effective})
    resolved._listed_denied_paths = listed
    resolved._effective = True
    return resolved


def unreadable_rules(reason: str) -> ClientConfigRules:
    """Rules that refuse any config with a client-delivered file, for ``reason``."""
    return ClientConfigRules(
        policy=RuntimeOverridesConfig(), base=AshConfig(), unreadable=reason
    )


def _refuse_unreadable(rules: ClientConfigRules, *, delivered: bool) -> None:
    """Refuse a config because its ``rules`` could not be established.

    ``delivered`` says a client-delivered file is what the rules were needed
    for; otherwise it is overrides an MCP client supplied, and the text says so.
    """
    from automated_security_helper.core.exceptions import (
        ASHConfigPolicyUnreadableError,
    )

    subject = (
        "A config an MCP client delivered"
        if delivered
        else "A config with overrides an MCP client supplied"
    )
    raise ASHConfigPolicyUnreadableError(
        f"{subject} cannot be checked: {rules.unreadable}"
    )


def rules_from(config: AshConfig) -> ClientConfigRules:
    """The rules a trusted ``config`` sets.

    When two of ``config``'s sections in one plugin section read as the same
    plugin, which values a delivered file would repeat is undecidable, and the
    rules are ``unreadable``. The reason is returned to an MCP client, so a key
    the trusted config read from the environment is not quoted in it.
    """
    from automated_security_helper.config.ash_config import reduced_plugin_name
    from automated_security_helper.config.config_validator import redact_values
    from automated_security_helper.utils.error_text import config_environment_values

    dump = config.model_dump(by_alias=True)
    environment_values = config_environment_values(config)
    for section in ("scanners", "reporters", "converters"):
        by_plugin: Dict[str, List[str]] = {}
        for key in dump.get(section) or {}:
            reduced = reduced_plugin_name(key)
            if reduced:
                by_plugin.setdefault(reduced, []).append(key)
        clashes = [keys for keys in by_plugin.values() if len(keys) > 1]
        if clashes:
            shown = ", ".join(
                redact_values(repr(key), environment_values)
                for key in sorted(clashes[0])
            )
            return unreadable_rules(
                f"The trusted config has {section} sections {shown}, which the "
                f"plugin lookup reads as the same plugin. Keep one of them."
            )
    return ClientConfigRules(policy=policy_of(config), base=config)


def _written_denied_paths(policy: RuntimeOverridesConfig) -> Tuple[str, ...]:
    """``policy``'s ``denied_paths`` as the profile wrote it.

    Without the ALWAYS_DENIED_PATHS entries the model adds to every list
    (``RuntimeOverridesConfig._keep_the_always_denied_paths``): they are denied
    whatever the list, so they do not make a written-out default the operator's
    own list, nor say which fields the operator's list names.
    """
    written = policy._written_denied_paths
    return written if written is not None else tuple(policy.denied_paths)


def policy_is_default(policy: RuntimeOverridesConfig) -> bool:
    """Whether ``policy``'s ``denied_paths`` is a default rather than the operator's own.

    Unset, or, as written, equal (as a set) to a list in
    ``SHIPPED_DEFAULT_DENIED_PATHS``. For a policy ``effective_policy`` returned,
    whether the operator's list was.
    """
    if policy._effective:
        return policy._listed_denied_paths is None
    if "denied_paths" not in policy.model_fields_set:
        return True
    return frozenset(_written_denied_paths(policy)) in SHIPPED_DEFAULT_DENIED_PATHS


def _names(entry: str, pointer: str) -> bool:
    """Whether ``denied_paths`` entry ``entry`` reaches ``pointer``: at, above or inside it.

    The runtime-override matcher's own test (``runtime_patch._denied_path_reason``),
    so every spelling it reads (``-`` or ``_``, globs) names the field here too.
    """
    from automated_security_helper.config.runtime_patch import (
        _denied_path_reason,
        known_plugin_keys,
    )

    return _denied_path_reason(entry, pointer, known_plugin_keys(None)) is not None


def exempt_paths(policy: RuntimeOverridesConfig) -> Tuple[str, ...]:
    """The pointers a delivered file is not checked against ``denied_paths`` for.

    ``sandbox`` and ``ash_plugin_modules``, which are checked against the trusted
    base instead (``_widenings``), and, with ``HONOR_DELIVERED_SUPPRESSIONS``, the
    suppressions and ignore paths, which apply marked. Under a default
    ``denied_paths`` all of them. Under the operator's own list, each that the
    list itself names (the pointer, an entry above it, or one inside it, such as
    ``/sandbox/mode``) is decided there instead, for the whole field. Value
    patterns apply to them either way.
    """
    candidates = RESTRICT_ONLY_PATHS + (
        SUPPRESSION_PATHS if HONOR_DELIVERED_SUPPRESSIONS else ()
    )
    if policy_is_default(policy):
        return candidates
    listed = (
        policy._listed_denied_paths
        if policy._effective
        else _written_denied_paths(policy)
    ) or ()
    return tuple(
        candidate
        for candidate in candidates
        if not any(_names(entry, candidate.removesuffix("/**")) for entry in listed)
    )


def denied_fields_message(path: Path, denials: Sequence[Any]) -> str:
    """The refusal text for ``path``, naming every denied field it sets."""
    from automated_security_helper.config.config_sources import describe_config_path

    fields = "; ".join(f"{denial.key} ({denial.reason})" for denial in denials)
    return (
        f"{describe_config_path(Path(path))} came from an MCP client (it was "
        f"delivered, or named outside the directories ASH_MCP_ALLOWED_CONFIG_ROOTS "
        f"names) and sets fields this server's runtime-override policy does not "
        f"let a client set: {fields}. Remove them from the file, or ask the "
        f"operator for a profile that sets them."
    )


def client_file_denials(
    documents: Mapping[Path, Any],
    rules: ClientConfigRules,
    *,
    scanned_root: Path | str | None = None,
    all_delivered: bool = False,
    names: Optional[Mapping[Path, Sequence[Path]]] = None,
    moved_exclusions: bool = False,
) -> List[Tuple[Path, List[Any]]]:
    """(file, denials) for each client-delivered file in ``documents`` that sets a denied field.

    ``all_delivered`` counts every file of the chain as delivered: the chain of a
    config path a client named, wherever it is (``resolve_config``'s
    ``untrusted_config``). Otherwise a file is delivered when any path it was
    reached by is (``names``; ``config_sources.by_every_name``), and it is
    reported by the first of those, the path the client used, rather than by
    the file a link of the client's reaches. Under a default policy the
    restrict-only settings are checked for anything they ask beyond the trusted
    base (``_widenings``).

    ``moved_exclusions`` says the files' scanner exclusions are moved out of the
    scanners' options before any scanner runs (``apply_client_config_rules``,
    which a scan resolves every delivered file with), so an exclusion option
    the move empties of client values is not refused by the always-denied
    entries that cover a whole scanner section; any other entry, an operator's
    own entry for the option among them, still refuses it
    (``client_scanner_exclusions.moved_exclusion_pointers``,
    ``runtime_patch.config_document_denials``). A caller whose files are not
    resolved that way leaves it off and refuses them as written.

    Raises:
        ASHConfigPolicyUnreadableError: A file is delivered and ``rules`` are
            unreadable, so no policy exists to judge it against.
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        session_config_was_patched,
    )
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.client_scanner_exclusions import (
        moved_exclusion_pointers,
    )
    from automated_security_helper.config.config_sources import by_every_name
    from automated_security_helper.config.runtime_patch import (
        config_document_denials,
    )
    from automated_security_helper.config.sandbox_grants import working_directory

    found: List[Tuple[Path, List[Any]]] = []
    exempt = exempt_paths(rules.policy)
    # None with no root given and no working directory left: there is no tree
    # to judge a module request against, and the module judgment says so
    # (refusal_reason with no scanned root), instead of raising out of
    # Path.cwd().
    root = Path(scanned_root) if scanned_root is not None else working_directory()
    delivered = by_every_name(config_is_client_supplied, names)
    for path, document in documents.items():
        if not (all_delivered or delivered(path)):
            continue
        if rules.unreadable is not None:
            # The placeholder policy and empty base of unreadable rules would
            # judge this file against defaults the server does not hold.
            _refuse_unreadable(rules, delivered=True)
        denials = [
            denial
            for denial in config_document_denials(
                document,
                allowlist=rules.policy,
                config=rules.base,
                exempt=exempt,
                moved=moved_exclusion_pointers(document) if moved_exclusions else (),
                inert=INERT_PATHS,
                repeats_trusted=session_config_was_patched(path),
            )
            if not _writes_plugin_default(document, denial, rules.base)
            and not _writes_a_tightening(document, denial)
        ]
        # Always: the restrict-only check only adds refusals, and an operator's
        # own list may deny one sandbox key (replace_default_denied_paths) and
        # leave the others to this check.
        denials.extend(
            _widenings(_with_own_patch(document, rules.base), rules.base, root)
        )
        if denials:
            found.append((_as_reached(path, names), denials))
    return found


def _as_reached(path: Path, names: Optional[Mapping[Path, Sequence[Path]]]) -> Path:
    """The path a chain file was first reached by, which a message names."""
    reached = (names or {}).get(path)
    return Path(reached[0]) if reached else path


def _with_own_patch(
    document: Any, base: AshConfig, *, over_report: bool = True
) -> Any:
    """``document`` with its own ``patch`` ops applied, over the trusted ``base``.

    ``over_report`` picks which way a failed op errs. The default reads on past
    a failed op (below), which suits the restrict-only check: it only adds
    refusals. Marking which entries are the operator's has the opposite need:
    an entry counted as the operator's when the load never applied it grows the
    operator's set, so ``over_report=False`` applies the whole patch or stops
    at the first op that fails and keeps only what came before it.

    So the restrict-only check sees a sandbox setting or plugin module a ``patch``
    op asks for, as well as one written out. Applied over ``base`` because an op
    may write into a list or section the document itself does not hold, and
    ``base``'s own values ask for nothing beyond it. When the ops do not apply
    there as a whole, each op is applied on its own and the ones that apply are
    kept: an op that writes a sandbox grant or a plugin module still reaches the
    walk when a sibling op fails, instead of the whole patch falling back to the
    unpatched document. A ``test`` op that fails is skipped like any other op
    that does not apply, and the walk goes on to the ops after it. The walk
    starts from ``base`` and the file's own keys, while the load merges the
    bases the file extends before it applies the patch, so a ``test`` that
    passes in the load can fail here; ending the walk at it would leave a grant
    written after it unjudged. Reading on can show a widening the load, which
    aborts the patch at a failed test, never makes, and that over-report
    refuses where the other answer would not. An op that applies in neither form
    is left to resolution, which applies it over the real chain, and to the
    confinement that drops whatever it widens.
    """
    from automated_security_helper.config.config_sources import (
        EXTENDS_KEY,
        PATCH_KEY,
        _apply_patch,
        deep_merge,
    )
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    if not isinstance(document, dict) or not document.get(PATCH_KEY):
        return document
    own = {k: v for k, v in document.items() if k not in (PATCH_KEY, EXTENDS_KEY)}
    start = deep_merge(base.model_dump(mode="json", by_alias=True), own)
    ops = document[PATCH_KEY]
    where = Path("delivered config")
    try:
        # ``_apply_patch`` answers a ``_Patched``; the restrict-only walk reads
        # the patched document it holds, as resolution does.
        return _apply_patch(start, ops, where).document
    except ASHConfigSourceError:
        pass
    if not isinstance(ops, list):
        return document
    current: Any = start
    for op in ops:
        try:
            current = _apply_patch(current, [op], where).document
        except ASHConfigSourceError:
            if over_report:
                continue
            break
    return current


def _writes_a_tightening(document: Any, denial: Any) -> bool:
    """Whether ``denial`` is a confined option ``document`` sets to a value that only narrows.

    ``tool_config_trust.TIGHTENING_VALUES``: opengrep's and semgrep's
    ``metrics: off``. And ``enabled: false`` of a reporter that sends findings off
    the host (``reporter_trust.REPORTER_ENABLED_DEFAULTS``), under any entry that
    covers it, ``/reporters/cloudwatch-logs/**`` included. That one is not
    refused, since it asks for nothing beyond the server's config, but it takes
    no effect: ``reporter_trust`` takes ``enabled`` from the trusted base, with a
    warning naming the file's value. A ``patch`` op that writes it is refused like
    any other op on a denied path.
    """
    from automated_security_helper.config.ash_config import plugin_key_lookup_names
    from automated_security_helper.config.ash_config import reduced_plugin_name
    from automated_security_helper.config.reporter_trust import (
        REPORTER_ENABLED_DEFAULTS,
        turns_a_reporter_off,
    )
    from automated_security_helper.config.runtime_patch import _path_segments, _walk
    from automated_security_helper.config.tool_config_trust import TIGHTENING_VALUES

    if denial.from_patch:
        return False
    segments = _path_segments(denial.pointer)
    if len(segments) == 3 and segments[0] == "reporters" and segments[2] == "enabled":
        names = plugin_key_lookup_names(segments[1])
        if any(reduced_plugin_name(r) in names for r in REPORTER_ENABLED_DEFAULTS):
            present, value = _walk(document, segments)
            return present and turns_a_reporter_off(value)
        return False
    if len(segments) != 4 or segments[0] != "scanners" or segments[2] != "options":
        return False
    option = segments[3].replace("-", "_")
    names = plugin_key_lookup_names(segments[1])
    for (scanner, name), values in TIGHTENING_VALUES.items():
        if name == option and reduced_plugin_name(scanner) in names:
            present, value = _walk(document, segments)
            # Each listed value is compared as JSON: ``value in values`` is
            # Python equality, under which ``1`` and ``1.0`` are ``True``.
            return present and any(_equals_as_json(value, member) for member in values)
    return False


def _equals_as_json(value: Any, expected: Any) -> bool:
    """Whether ``value`` is the JSON value ``expected``, not merely equal in Python.

    ``1 == True`` and ``0 == False`` in Python, so a comparison that decides what a
    delivered file may write has to go through the JSON comparison the denial
    check uses. A value that is not JSON data at all (a YAML date, a cycle) or
    is nested past what the encoder will follow is not ``expected``; the
    comparison does not raise.
    """
    from automated_security_helper.config.runtime_patch import _same_json_value

    try:
        return _same_json_value(value, expected)
    except (TypeError, ValueError, RecursionError):
        return False


def _writes_plugin_default(document: Any, denial: Any, base: AshConfig) -> bool:
    """Whether ``denial`` is a plugin option ``document`` sets to its default.

    Only for an option in ``PLUGIN_OPTION_DEFAULTS`` that the trusted ``base``
    has no value for; where it has one, the denial already compared against it.
    """
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )
    from automated_security_helper.config.config_sources import _resolve_dict_key
    from automated_security_helper.config.runtime_patch import _path_segments, _walk

    if denial.from_patch:
        return False
    segments = _path_segments(denial.pointer)
    if len(segments) != 4 or segments[0] != "scanners" or segments[2] != "options":
        return False
    option = segments[3].replace("-", "_")
    names = plugin_key_lookup_names(segments[1])
    for (scanner, name), default in PLUGIN_OPTION_DEFAULTS.items():
        if name != option or reduced_plugin_name(scanner) not in names:
            continue
        trusted = base.get_plugin_config("scanner", scanner)
        # A plugin's section is plain data, so it can hold any value; one that
        # is not a mapping, or whose options are not, has no value to compare.
        options = trusted.get("options") if isinstance(trusted, dict) else None
        if not isinstance(options, dict):
            options = {}
        # Under either spelling of the key, as every other option lookup here
        # reads a plugin's section: a trusted value written ``ignore-file``
        # is the trusted base's own value too.
        if _resolve_dict_key(options, option) in options:
            return False
        present, value = _walk(document, segments)
        # As JSON values, not as Python ones: ``enable_preprocessors: 1`` is not
        # the default ``true``.
        return present and _equals_as_json(value, default)
    return False


def _scanner_gets_network(name: str, trusted: Any) -> bool:
    """Whether the trusted sandbox settings give scanner ``name`` a network.

    With ``network_scanners`` unset, a scanner's own declared need decides, read
    from its class among the scanner classes already imported (nothing is
    imported here, which would register plugins). A scanner whose class is not
    known, or whose class declares no ``SandboxRequirements``, counts as having
    none. Where several classes declare the name, the scanner gets a network
    only if every one of them says so, so the answer does not depend on the
    order the classes are found in.
    """
    from automated_security_helper.base.plugin_config import declared_plugin_name
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase
    from automated_security_helper.utils.sandbox.policy import SandboxRequirements

    if trusted.network_scanners is not None:
        return name in set(trusted.network_scanners)
    pending = list(ScannerPluginBase.__subclasses__())
    answers: List[bool] = []
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if declared_plugin_name(cls) != name:
            continue
        requirements = getattr(cls, "sandbox_requirements", None)
        if not isinstance(requirements, SandboxRequirements):
            # Nothing to read a need from on this class. A generic parametrization
            # (GrepScannerBase[SemgrepScannerConfig]) carries the name but not the
            # requirements; its subclass does. A scanner that declares them as a
            # property (cfn-guard, detect-secrets) gives the class the property
            # object, which is not evaluated: it answers for an instance, from the
            # environment and the scanner's settings. Such a scanner counts as
            # having no network, which is right for both that exist (cfn-guard
            # needs none, detect-secrets only with a grant) and fails closed for
            # any other: a config that names it asks for a network the server does
            # not give by default, and is refused until the operator's own
            # network_scanners names it. scanner_sandbox_scope makes the same test
            # of a scanner instance.
            continue
        answers.append(
            bool(requirements.network and not requirements.network_requires_grant)
        )
    return bool(answers) and all(answers)


def _environment_entry_label(entry: Any, position: int) -> str:
    """How a denial names a delivered ``sandbox.environment`` *entry* (number
    *position*, counting from one): its variable name when it starts with one, its
    position otherwise, and its type when it is not text. Never the value: the
    reason is returned to the client, and an entry that does not start with a name
    may be a secret written without it."""
    from automated_security_helper.utils.sandbox.policy import entry_variable_name

    if not isinstance(entry, str):
        return f"an entry of type {type(entry).__name__}"
    return entry_variable_name(entry) or f"entry number {position}"


def _widenings(
    document: Any,
    base: AshConfig,
    scanned_root: Optional[Path],
    *,
    sandbox: bool = True,
    modules: bool = True,
) -> List[Any]:
    """What a delivered ``document`` asks for under ``sandbox`` and ``ash_plugin_modules``
    beyond the trusted ``base``.

    Those two are exempt from the default ``denied_paths`` because their own
    limits (``sandbox_grants``, ``plugin_module_trust``) keep a delivered file
    restrict-only, accepting a value that is equal or tighter. A value that asks
    for more used to be dropped by those limits with only a log line; it is now
    a denial, so the file is refused like any other that sets a denied field.
    """
    from automated_security_helper.config.config_validator import redact_values
    from automated_security_helper.config.plugin_module_trust import (
        OFF_HOST_PLUGIN_SENDS,
        off_host_package,
        refusal_reason,
        split_plugin_modules,
    )
    from automated_security_helper.config.runtime_patch import DocumentDenial, _walk
    from automated_security_helper.utils.error_text import config_environment_values

    found: List[Any] = []
    trusted = base.sandbox
    present, section = _walk(document, ["sandbox"])
    if sandbox and present and isinstance(section, dict):
        listed, network = _walk(section, ["network_scanners"])
        if listed and isinstance(network, list):
            extra = [
                str(name)
                for name in network
                if not _scanner_gets_network(str(name), trusted)
            ]
            if extra:
                found.append(
                    DocumentDenial(
                        "sandbox.network_scanners",
                        "/sandbox/network_scanners",
                        f"gives a network to {', '.join(extra)}, which the "
                        "server's sandbox settings do not",
                        False,
                    )
                )
        elif listed and network is None and trusted.network_scanners is not None:
            # Null hands every scanner the network its own declaration asks for,
            # where the server's list names the ones that get one.
            found.append(
                DocumentDenial(
                    "sandbox.network_scanners",
                    "/sandbox/network_scanners",
                    "gives every scanner the network its own declaration asks "
                    "for, where the server's sandbox settings name the scanners "
                    "that get one",
                    False,
                )
            )
        listed, paths = _walk(section, ["extra_read_paths"])
        if listed and isinstance(paths, list):
            extra = [
                str(path) for path in paths if path not in trusted.extra_read_paths
            ]
            if extra:
                found.append(
                    DocumentDenial(
                        "sandbox.extra_read_paths",
                        "/sandbox/extra_read_paths",
                        f"lets scanners read {', '.join(extra)}, which the "
                        "server's sandbox settings do not",
                        False,
                    )
                )
        listed, scanners = _walk(section, ["read_path_scanners"])
        if listed and isinstance(scanners, list):
            extra = [
                str(name) for name in scanners if name not in trusted.read_path_scanners
            ]
            if extra:
                found.append(
                    DocumentDenial(
                        "sandbox.read_path_scanners",
                        "/sandbox/read_path_scanners",
                        f"lets {', '.join(extra)} read the host paths their own "
                        "options ask for, which the server's sandbox settings do not",
                        False,
                    )
                )
        listed, scanners = _walk(section, ["env_scanners"])
        if listed and isinstance(scanners, list):
            extra = [str(name) for name in scanners if name not in trusted.env_scanners]
            if extra:
                found.append(
                    DocumentDenial(
                        "sandbox.env_scanners",
                        "/sandbox/env_scanners",
                        f"passes {', '.join(extra)} the environment variables "
                        "their own options ask for, which the server's sandbox "
                        "settings do not",
                        False,
                    )
                )
        listed, entries = _walk(section, ["environment"])
        if listed and isinstance(entries, list):
            # Named by variable, never by entry: a NAME=value entry holds a value,
            # and this reason is returned to the client. Only a part that is a
            # variable name is shown; an entry that does not start with one may be
            # a value written without its name, so it is named by its position.
            extra = list(
                dict.fromkeys(
                    _environment_entry_label(entry, position)
                    for position, entry in enumerate(entries, start=1)
                    if entry not in trusted.environment
                )
            )
            if extra:
                found.append(
                    DocumentDenial(
                        "sandbox.environment",
                        "/sandbox/environment",
                        f"passes {', '.join(extra)} to every scanner, which the "
                        "server's sandbox settings do not",
                        False,
                    )
                )
        listed, mode = _walk(section, ["mode"])
        if listed and trusted.mode != "off" and mode != trusted.mode:
            # The server's mode can be a value its config read from the
            # environment, and this reason is returned to the client.
            server_mode = redact_values(
                repr(trusted.mode), config_environment_values(base)
            )
            found.append(
                DocumentDenial(
                    "sandbox.mode",
                    "/sandbox/mode",
                    f"replaces the server's sandbox mode {server_mode}",
                    False,
                )
            )
    present, named = _walk(document, ["ash_plugin_modules"])
    if modules and present:
        trusted_names = set(split_plugin_modules(base.ash_plugin_modules))
        refused: List[str] = []
        # Once for the whole list, not once per name.
        importlib.invalidate_caches()
        for name in split_plugin_modules(named):
            if name in trusted_names:
                continue
            package = off_host_package(name)
            if package is not None and package not in trusted_names:
                refused.append(f"{name!r} ({OFF_HOST_PLUGIN_SENDS[package]})")
                continue
            reason = refusal_reason(name, scanned_root, invalidate_caches=False)
            if reason is not None:
                refused.append(f"{name!r} ({reason})")
        if refused:
            found.append(
                DocumentDenial(
                    "ash_plugin_modules",
                    "/ash_plugin_modules",
                    f"adds {', '.join(refused)}, which a delivered config may not",
                    False,
                )
            )
    return found


def apply_client_config_rules(
    config: AshConfig,
    documents: Mapping[Path, Any],
    *,
    rules: Optional[ClientConfigRules],
    trusted_config_path: Path | str | None,
    source_dir: Path | str | None,
    permit_base: Optional[Callable[[Path], bool]],
    scanned_root: Path | str | None = None,
    all_delivered: bool = False,
    client_overrides: bool = False,
    names: Optional[Mapping[Path, Sequence[Path]]] = None,
) -> AshConfig:
    """``config``, checked for denied fields its client-delivered files set.

    Refuses or drops them according to ``DENIED_FIELD_HANDLING``; a refusal names
    the denied fields of every such file. ``rules`` None takes the trusted base's.
    The suppressions and ignore paths the operator did not supply are marked
    ``client_supplied``, and the scanner exclusions the operator did not supply
    are moved out of the scanners' options to be applied to their results instead
    (``config/client_scanner_exclusions.py``).
    ``scanned_root`` is the tree being scanned (the source directory when None).
    ``all_delivered`` counts every file of the chain as delivered, for a config
    path a client named (``resolve_config``'s ``untrusted_config``), wherever
    the file is. ``client_overrides`` says ``config`` carries overrides an MCP
    client supplied (the workspace tools' ``config_overrides``), so what no file
    of the chain the client did not deliver supplies is marked and moved even
    when no file was delivered. The overrides themselves were already checked
    against the same allowlist (``cli/mcp/workspace._gate_client_overrides``).
    ``names`` gives the paths each file of ``documents`` was reached by
    (``ResolvedConfigDocument.names``): a file is delivered when any of them is.
    """
    from automated_security_helper.config.client_scanner_exclusions import (
        strip_client_scanner_exclusions,
    )
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.config_sources import by_every_name

    is_delivered: Callable[[Path], bool] = (
        (lambda _path: True)
        if all_delivered
        else by_every_name(config_is_client_supplied, names)
    )
    file_delivered = any(is_delivered(path) for path in documents)
    if not client_overrides and not file_delivered:
        return config
    if rules is None:
        rules = rules_from(
            _trusted_config(trusted_config_path, source_dir, permit_base)
        )
    if rules.unreadable is not None:
        # Refused even with no delivered file: the marks and the scanner
        # exclusion move that client overrides need are judged against the
        # rules' trusted base, which unreadable rules do not have.
        _refuse_unreadable(rules, delivered=file_delivered)
    # None when neither is given: client_file_denials then takes the working
    # directory, and judges with no tree when that is gone too.
    root = scanned_root or source_dir or None
    # The denied-fields check sees each scanner section as the move below leaves
    # it (moved_exclusions): an exclusion option the move empties of client
    # values is not refused, and anything else a file sets in the section still
    # is, under a floor entry that covers the whole section too. The move itself
    # runs last so the config it records the exclusions on is the one returned;
    # _drop_denied_fields builds a new one.
    found = client_file_denials(
        documents,
        rules,
        scanned_root=root,
        all_delivered=all_delivered,
        names=names,
        moved_exclusions=True,
    )
    if found and DENIED_FIELD_HANDLING == "refuse":
        from automated_security_helper.core.exceptions import (
            ASHConfigFieldDeniedError,
        )

        # Every delivered file of the chain that sets a denied field, so one
        # refusal names them all.
        raise ASHConfigFieldDeniedError(
            " ".join(denied_fields_message(path, denials) for path, denials in found)
        )
    if found:
        config = _drop_denied_fields(config, found, rules.base)
    config = _mark_client_supplied(config, documents, rules.base, is_delivered)
    return strip_client_scanner_exclusions(
        config,
        documents,
        rules.base,
        source_dir=source_dir,
        scanned_root=scanned_root,
        is_delivered=is_delivered,
    )


def clear_client_supplied_marks(config: AshConfig) -> AshConfig:
    """``config`` with every ``client_supplied`` a config file or override set cleared.

    Only ASH marks an entry: ``_mark_client_supplied`` sets it, after this, on
    the suppressions and ignore paths a client's config supplied. A value
    written in a config file, of any tier, or set by an override is not
    evidence of where the entry came from, so it is cleared on every
    suppression and ignore path, including entries in a scanner's own options
    (bandit's ``excluded_paths``, checkov's ``skip_path``) and in a plugin
    section kept as plain data.
    """
    from pydantic import BaseModel as _Model

    from automated_security_helper.models.core import IgnorePathWithReason

    def clear(node: Any) -> None:
        if isinstance(node, IgnorePathWithReason):
            node.client_supplied = False
            return
        if isinstance(node, _Model):
            for name in type(node).model_fields:
                clear(getattr(node, name, None))
            for value in (node.model_extra or {}).values():
                clear(value)
        elif isinstance(node, dict):
            if "client_supplied" in node and "path" in node:
                node.pop("client_supplied")
            for value in node.values():
                clear(value)
        elif isinstance(node, (list, tuple)):
            for value in node:
                clear(value)

    clear(config)
    return config


def _mark_client_supplied(
    config: AshConfig,
    documents: Mapping[Path, Any],
    base: AshConfig,
    is_delivered: Optional[Callable[[Path], bool]] = None,
) -> AshConfig:
    """Mark every effective suppression and ignore path the operator did not supply.

    Run on the merged result, so it does not matter how an entry got there: a
    plain list, a ``patch`` append, a ``global-settings`` spelling over a base.
    An entry is the operator's only when it equals one in a non-client file of the
    chain, with that file's own ``patch`` ops applied, or in the trusted ``base``;
    every other entry is marked ``client_supplied``, so an entry whose source is
    unknown counts as the client's.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.runtime_patch import _walk
    from automated_security_helper.models.core import (
        AshSuppression,
        IgnorePathWithReason,
    )

    delivered = is_delivered or config_is_client_supplied

    models = {"suppressions": AshSuppression, "ignore_paths": IgnorePathWithReason}
    operators: Dict[str, List[Dict[str, Any]]] = {field: [] for field in models}
    sources: List[Any] = [
        _with_own_patch(document, base, over_report=False)
        for path, document in documents.items()
        if not delivered(path)
    ]
    sources.append(base.model_dump(mode="json", by_alias=True))
    for source in sources:
        for field, model in models.items():
            present, entries = _walk(source, ["global_settings", field])
            for raw in entries if present and isinstance(entries, list) else []:
                try:
                    entry = model.model_validate(raw)
                except Exception as exc:  # noqa: BLE001 -- reported elsewhere
                    ASH_LOGGER.debug(
                        "Skipping a %s entry that does not validate (%s): %r",
                        field,
                        type(exc).__name__,
                        raw,
                    )
                    continue
                operators[field].append(entry.model_dump(exclude={"client_supplied"}))
    for field in models:
        for entry in getattr(config.global_settings, field):
            if entry.model_dump(exclude={"client_supplied"}) not in operators[field]:
                entry.client_supplied = True
    return config


def _drop_denied_fields(
    config: AshConfig,
    found: Sequence[Tuple[Path, List[Any]]],
    base: AshConfig,
) -> AshConfig:
    """``config`` with each denied field back at ``base``'s value, and a warning naming them.

    A field ``base`` does not have is removed, so its default applies. A denied
    ``patch`` op cannot be undone field by field, so the config is refused then.
    """
    from automated_security_helper.config.runtime_patch import (
        _trusted_value,
        known_plugin_keys,
    )
    from automated_security_helper.core.exceptions import (
        ASHConfigFieldDeniedError,
        ASHConfigValidationError,
    )

    for path, denials in found:
        if any(denial.from_patch for denial in denials):
            raise ASHConfigFieldDeniedError(denied_fields_message(path, denials))
    data = config.model_dump(mode="python", by_alias=True)
    base_dump = base.model_dump(mode="json", by_alias=True)
    plugin_keys = known_plugin_keys(base)
    for _, denials in found:
        for denial in denials:
            present, value = _trusted_value(
                base, base_dump, denial.pointer, plugin_keys
            )
            _set_at(data, denial.pointer, value, remove=not present)
    warnings = list(config._resolution_warnings)
    try:
        dropped = AshConfig.model_validate(data)
    except Exception as exc:  # noqa: BLE001 -- reported as the refusal it is
        raise ASHConfigValidationError(
            f"A config an MCP client delivered set fields this server does not let "
            f"a client set, and the config does not validate without them: {exc}"
        ) from exc
    for path, denials in found:
        warnings.append(
            denied_fields_message(path, denials).replace(
                "Remove them from the file, or ask the operator for a profile that "
                "sets them.",
                "They were not applied; the server's values were used instead.",
            )
        )
    # The rebuilt model is the same configuration with the denied fields
    # restored, so it keeps everything its load recorded (AshConfig's private
    # attributes: the values and keys its files read from the environment, the
    # written-field record, the trust records), as apply_config_overrides keeps
    # them for its rebuild. Without them a dropped config printed and recorded
    # the environment values its file read.
    dropped.__pydantic_private__ = copy.deepcopy(config.__pydantic_private__)
    dropped._resolution_warnings = warnings
    return dropped


def _set_at(data: Any, pointer: str, value: Any, *, remove: bool) -> None:
    """Set (or remove) ``pointer`` in ``data``, matching keys as config merging does."""
    from automated_security_helper.config.config_sources import _resolve_dict_key
    from automated_security_helper.config.runtime_patch import _path_segments

    segments = _path_segments(pointer)
    current = data
    for segment in segments[:-1]:
        if not isinstance(current, dict):
            return
        key = _resolve_dict_key(current, segment)
        if key not in current:
            return
        current = current[key]
    if not isinstance(current, dict) or not segments:
        return
    key = _resolve_dict_key(current, segments[-1])
    if remove:
        current.pop(key, None)
    else:
        current[key] = value


def _trusted_config(
    trusted_config_path: Path | str | None,
    source_dir: Path | str | None,
    permit_base: Optional[Callable[[Path], bool]],
) -> AshConfig:
    """The operator config at ``trusted_config_path``, else the server's default config.

    An operator config a client delivered is not one, and falls back to the
    default, with a warning.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.config_sources import by_every_name
    from automated_security_helper.config.operator_paths import the_operators_files
    from automated_security_helper.config.resolve_config import _load_operator_config
    from automated_security_helper.config.sandbox_grants import scanned_trees

    # The operator's file: its relative paths are taken from its own directory
    # (config/operator_paths.py), judged against the scanned trees when a source
    # directory is known.
    trees = scanned_trees(Path(source_dir)) if source_dir is not None else []
    operator = _load_operator_config(
        trusted_config_path, source_dir, permit_base, the_operators_files(trees)
    )
    if operator is not None:
        delivered = by_every_name(config_is_client_supplied, operator.names)
        if not any(delivered(path) for path in operator.chain):
            return operator.config
        ASH_LOGGER.warning(
            "The config named as the trusted base has a file under the MCP "
            "workspace root, which an MCP client delivered, so the server's "
            "default config is the trusted config instead. Keep the operator's "
            "config outside the MCP workspace root."
        )
    return trusted_default_config()


def trusted_default_config(
    repository: "Optional[RepositorySettings]" = None,
) -> AshConfig:
    """The server's default config, unless ``ASH_CONFIG`` names a client's file.

    ``get_default_config`` reads ``ASH_CONFIG``. A file under the MCP workspace
    root is a client's wherever it is named from (``config_is_client_supplied``),
    so when ``ASH_CONFIG`` or a base it extends is one, the built-in defaults are
    the trusted config instead, and the policy is not read from it. The file
    ``ASH_CONFIG`` names is judged before it is loaded, so a client's file is
    not parsed here; its bases are judged from the chain the load reports. A
    named file whose load reports no chain was not judged, and the built-in
    defaults are the trusted config for it too.

    ``repository`` is the settings the caller's own load of the same chain uses
    (``operator_only_options.repository_settings_for_root``). With them the file
    is read as that load reads it: an option only the operator sets, written by a
    file in the scanned tree or in another checkout, is left out before the model
    validates it. Read bare, a value the option refuses there made this config
    unloadable, and the rules built from it refused every delivered config,
    although the load itself ignores that value.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.default_config import (
        _ash_config_file,
        get_default_config,
    )
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.utils.log import ASH_LOGGER

    delivered = (
        "ASH_CONFIG names a file under the MCP workspace root, which an MCP "
        "client delivered, so ASH's built-in defaults are the trusted config "
        "instead. Keep the server's config outside the MCP workspace root."
    )
    unreported = (
        "ASH_CONFIG names a file, but loading it reported no chain of files to "
        "judge, so ASH's built-in defaults are the trusted config instead."
    )

    def built_in_defaults(reason: str) -> AshConfig:
        ASH_LOGGER.warning(reason)
        return AshConfig()

    # The file ASH_CONFIG names is judged before it is loaded: a client's file
    # is never parsed here, so text in it that does not parse cannot make this
    # config unloadable. A name ``_ash_config_file`` refuses is left to the
    # load below, which refuses it the same way and tags the refusal.
    try:
        named_file = _ash_config_file()
    except ASHConfigValidationError:
        named_file = None
    if named_file is not None and config_is_client_supplied(named_file):
        return built_in_defaults(delivered)
    # One read: the chain is judged from the files the load itself read
    # (``views``, the carry get_default_config fills from the same read), not
    # from a second resolution of ASH_CONFIG that a file changed in between
    # could make disagree with the configuration returned.
    views: List[Tuple[List[Path], List[Path], FrozenSet[Path]]] = []
    if repository is None:
        config = get_default_config(views=views)
    else:
        config = get_default_config(
            repository.confine,
            views=views,
            repository_file=repository.is_repository_file,
        )
    # A file named and a load that reports no chain: nothing was judged.
    if named_file is not None and not views:
        return built_in_defaults(unreported)
    for chain, named, _environment_paths in views:
        if any(config_is_client_supplied(path) for path in (*chain, *named)):
            return built_in_defaults(delivered)
    return config
