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
``plugin_module_trust`` keeps only installed modules outside the tree (and no
package that sends findings or source off the host). Refusing them as well would
refuse a file that tightens the sandbox.

The rules are a ``ClientConfigRules``: the policy and the trusted config it came
from. The MCP tools pass the session's, taken from the registered profile the
session bound (never from the session's materialized config, which a client's
``patch_ops`` wrote). Other callers get the trusted base resolve_config would
use: the operator config at ``trusted_config_path``, else the server's default
config.

The check is keyed on where a file is, not on who calls: a CLI resolve of a file
under the MCP workspace root is checked too.

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

from pathlib import Path
from typing import (
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
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER

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
            "/scanners/*/options/tool_version",
            "/converters/jupyter/options/tool_version",
            "/scanners/opengrep/options/version",
            "/scanners/opengrep/options/sha256",
            "/scanners/opengrep/options/metrics",
            "/scanners/semgrep/options/metrics",
            "/reporters/bedrock-summary-reporter/options/aws_*",
            "/reporters/cloudwatch-logs/**",
            "/reporters/aws-security-hub/options/aws_region",
            "/reporters/aws-security-hub/options/aws_profile",
            "/reporters/aws-security-hub/options/account_id",
            "/reporters/bedrock-summary-reporter/options/model_id",
            "/reporters/bedrock-summary-reporter/options/output_file",
            "/reporters/bedrock-summary-reporter/options/output_executive_file",
            "/reporters/bedrock-summary-reporter/options/output_technical_file",
            "/reporters/s3/options/aws_region",
            "/reporters/s3/options/aws_profile",
            "/reporters/s3/options/bucket_name",
            "/reporters/s3/options/key_prefix",
        ),
    )
)


#: Defaults of the denied options of scanners that come from a plugin package
#: (ferret-scan, trivy-repo). The trusted config carries a built-in scanner's
#: defaults, so a delivered value equal to one is accepted as no change; it need
#: not carry a plugin's section at all, so without this a delivered file that
#: wrote such a default would be refused. Used only where the trusted config has
#: no value of its own. ``test_the_plugin_option_defaults_are_the_plugins``
#: checks each against the plugin's own model.
PLUGIN_OPTION_DEFAULTS: Mapping[Tuple[str, str], Any] = {
    ("ferret-scan", "checks"): "all",
    ("ferret-scan", "confidence_levels"): "all",
    ("ferret-scan", "disable_ip_types"): None,
    ("ferret-scan", "enable_preprocessors"): True,
    ("ferret-scan", "finding_limit"): 0,
    ("ferret-scan", "max_live_bytes"): None,
    ("ferret-scan", "profile"): None,
    ("ferret-scan", "recursive"): True,
    ("ferret-scan", "respect_gitignore"): False,
    ("ferret-scan", "use_default_config"): True,
    ("ferret-scan", "validator_budget"): None,
    ("trivy-repo", "license_full"): True,
    ("trivy-repo", "offline"): False,
    ("trivy-repo", "scanners"): ["vuln", "secret", "misconfig", "license"],
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
    #: so only a config with a client-delivered file is refused for it.
    unreadable: Optional[str] = None


def policy_of(config: AshConfig) -> RuntimeOverridesConfig:
    """``config``'s runtime-override policy, or the defaults when it sets none.

    The effective policy (``effective_policy``): a ``denied_paths`` list equal
    to one ASH shipped earlier is read as today's default list.
    """
    mcp = getattr(config.global_settings, "mcp", None)
    if mcp is None:
        return RuntimeOverridesConfig()
    return effective_policy(mcp.runtime_overrides)


_WARNED_REPLACEMENTS: Set[FrozenSet[str]] = set()


def effective_policy(policy: RuntimeOverridesConfig) -> RuntimeOverridesConfig:
    """``policy`` with the ``denied_paths`` list that applies.

    * Unset, or equal to a list ASH has shipped (``policy_is_default``): the
      current default list. A profile an earlier ``ash config init`` wrote holds
      that release's list; a stale copy would otherwise let through what the
      defaults have since denied.
    * Any other list is added to the current defaults, so an operator who lists
      one more entry does not lift the rest.
    * With ``replace_default_denied_paths``, the list is used as written, and
      each default entry it leaves out is named in a warning, once per list.

    The operator's own list is kept on the copy (``_listed_denied_paths``),
    since ``exempt_paths`` decides from what the operator wrote rather than from
    the merged list. Applying this to its own result changes nothing.
    """
    if policy._effective:
        return policy
    current = list(RuntimeOverridesConfig().denied_paths)
    listed: Optional[Tuple[str, ...]] = (
        None if policy_is_default(policy) else tuple(policy.denied_paths)
    )
    if listed is None:
        effective = current
    elif policy.replace_default_denied_paths:
        effective = list(listed)
        removed = [entry for entry in current if entry not in set(effective)]
        if removed and frozenset(effective) not in _WARNED_REPLACEMENTS:
            _WARNED_REPLACEMENTS.add(frozenset(effective))
            ASH_LOGGER.warning(
                "runtime_overrides.replace_default_denied_paths is true, so these "
                f"default denied_paths entries do not apply: {', '.join(removed)}"
            )
    else:
        effective = current + [entry for entry in listed if entry not in set(current)]
    resolved = policy.model_copy(update={"denied_paths": effective})
    resolved._listed_denied_paths = listed
    resolved._effective = True
    return resolved


def unreadable_rules(reason: str) -> ClientConfigRules:
    """Rules that refuse any config with a client-delivered file, for ``reason``."""
    return ClientConfigRules(
        policy=RuntimeOverridesConfig(), base=AshConfig(), unreadable=reason
    )


def rules_from(config: AshConfig) -> ClientConfigRules:
    """The rules a trusted ``config`` sets.

    When two of ``config``'s sections in one plugin section read as the same
    plugin, which values a delivered file would repeat is undecidable, and the
    rules are ``unreadable``.
    """
    from automated_security_helper.config.ash_config import reduced_plugin_name

    dump = config.model_dump(by_alias=True)
    for section in ("scanners", "reporters", "converters"):
        by_plugin: Dict[str, List[str]] = {}
        for key in dump.get(section) or {}:
            reduced = reduced_plugin_name(key)
            if reduced:
                by_plugin.setdefault(reduced, []).append(key)
        clashes = [keys for keys in by_plugin.values() if len(keys) > 1]
        if clashes:
            return unreadable_rules(
                f"The trusted config has {section} sections "
                f"{', '.join(repr(key) for key in sorted(clashes[0]))}, which the "
                f"plugin lookup reads as the same plugin. Keep one of them."
            )
    return ClientConfigRules(policy=policy_of(config), base=config)


def policy_is_default(policy: RuntimeOverridesConfig) -> bool:
    """Whether ``policy``'s ``denied_paths`` is a default rather than the operator's own.

    Unset, or equal (as a set) to a list in ``SHIPPED_DEFAULT_DENIED_PATHS``.
    For a policy ``effective_policy`` returned, whether the operator's list was.
    """
    if policy._effective:
        return policy._listed_denied_paths is None
    if "denied_paths" not in policy.model_fields_set:
        return True
    return frozenset(policy.denied_paths) in SHIPPED_DEFAULT_DENIED_PATHS


def _names(entry: str, pointer: str) -> bool:
    """Whether ``denied_paths`` entry ``entry`` covers ``pointer`` or a key inside it."""
    from fnmatch import fnmatchcase

    if entry.endswith("/**"):
        prefix = entry[: -len("/**")]
        return pointer == prefix or pointer.startswith(prefix + "/") or not prefix
    return fnmatchcase(pointer, entry) or pointer.startswith(entry.rstrip("/") + "/")


def exempt_paths(policy: RuntimeOverridesConfig) -> Tuple[str, ...]:
    """The pointers a delivered file is not checked against ``denied_paths`` for.

    ``sandbox`` and ``ash_plugin_modules``, which are checked against the trusted
    base instead (``_widenings``), and, with ``HONOR_DELIVERED_SUPPRESSIONS``, the
    suppressions and ignore paths, which apply marked. Under a default
    ``denied_paths`` all of them. Under the operator's own list, each that the
    list itself names (the pointer, or an entry above it) is decided there
    instead. Value patterns apply to them either way.
    """
    candidates = RESTRICT_ONLY_PATHS + (
        SUPPRESSION_PATHS if HONOR_DELIVERED_SUPPRESSIONS else ()
    )
    if policy_is_default(policy):
        return candidates
    listed = (
        policy._listed_denied_paths if policy._effective else tuple(policy.denied_paths)
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
) -> List[Tuple[Path, List[Any]]]:
    """(file, denials) for each client-delivered file in ``documents`` that sets a denied field.

    ``all_delivered`` counts every file of the chain as delivered: the chain of a
    config path a client named, wherever it is (``resolve_config``'s
    ``untrusted_config``). Under a default policy the restrict-only settings are
    checked for anything they ask beyond the trusted base (``_widenings``).
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.runtime_patch import (
        config_document_denials,
    )

    found: List[Tuple[Path, List[Any]]] = []
    exempt = exempt_paths(rules.policy)
    root = Path(scanned_root) if scanned_root is not None else Path.cwd()
    for path, document in documents.items():
        if not (all_delivered or config_is_client_supplied(path)):
            continue
        denials = [
            denial
            for denial in config_document_denials(
                document,
                allowlist=rules.policy,
                config=rules.base,
                exempt=exempt,
                inert=INERT_PATHS,
            )
            if not _writes_plugin_default(document, denial, rules.base)
        ]
        denials.extend(
            _widenings(
                document,
                rules.base,
                root,
                sandbox="/sandbox" in exempt,
                modules="/ash_plugin_modules" in exempt,
            )
        )
        if denials:
            found.append((path, denials))
    return found


def _writes_plugin_default(document: Any, denial: Any, base: AshConfig) -> bool:
    """Whether ``denial`` is a plugin option ``document`` sets to its default.

    Only for an option in ``PLUGIN_OPTION_DEFAULTS`` that the trusted ``base``
    has no value for; where it has one, the denial already compared against it.
    """
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )
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
        options = (trusted or {}).get("options") or {}
        if option in options:
            return False
        present, value = _walk(document, segments)
        return present and value == default
    return False


def _scanner_gets_network(name: str, trusted: Any) -> bool:
    """Whether the trusted sandbox settings give scanner ``name`` a network.

    With ``network_scanners`` unset, a scanner's own declared need decides, read
    from its class among the scanner classes already imported (nothing is
    imported here, which would register plugins). A scanner whose class is not
    known counts as having none.
    """
    from automated_security_helper.base.plugin_config import declared_plugin_name
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase

    if trusted.network_scanners is not None:
        return name in set(trusted.network_scanners)
    pending = list(ScannerPluginBase.__subclasses__())
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if declared_plugin_name(cls) != name:
            continue
        requirements = getattr(cls, "sandbox_requirements", None)
        return bool(
            requirements is not None
            and requirements.network
            and not requirements.network_requires_grant
        )
    return False


def _widenings(
    document: Any,
    base: AshConfig,
    scanned_root: Path,
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
    from automated_security_helper.config.plugin_module_trust import (
        OFF_HOST_PLUGIN_SENDS,
        off_host_package,
        refusal_reason,
        split_plugin_modules,
    )
    from automated_security_helper.config.runtime_patch import DocumentDenial, _walk

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
        listed, mode = _walk(section, ["mode"])
        if listed and trusted.mode != "off" and mode != trusted.mode:
            found.append(
                DocumentDenial(
                    "sandbox.mode",
                    "/sandbox/mode",
                    f"replaces the server's sandbox mode {trusted.mode!r}",
                    False,
                )
            )
    present, named = _walk(document, ["ash_plugin_modules"])
    if modules and present:
        trusted_names = set(split_plugin_modules(base.ash_plugin_modules))
        refused: List[str] = []
        for name in split_plugin_modules(named):
            if name in trusted_names:
                continue
            package = off_host_package(name)
            if package is not None and package not in trusted_names:
                refused.append(f"{name!r} ({OFF_HOST_PLUGIN_SENDS[package]})")
                continue
            reason = refusal_reason(name, scanned_root)
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
) -> AshConfig:
    """``config``, checked for denied fields its client-delivered files set.

    Refuses or drops them according to ``DENIED_FIELD_HANDLING``. ``rules`` None
    takes the trusted base's. The suppressions and ignore paths the operator did
    not supply are marked ``client_supplied``, and the scanner exclusions the
    operator did not supply are moved out of the scanners' options to be applied
    to their results instead (``config/client_scanner_exclusions.py``).
    ``scanned_root`` is the tree being scanned (the source directory when None).
    ``all_delivered`` counts every file of the chain as delivered, for a config
    path a client named (``resolve_config``'s ``untrusted_config``), wherever
    the file is.
    """
    from automated_security_helper.config.client_scanner_exclusions import (
        strip_client_scanner_exclusions,
    )
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    is_delivered: Callable[[Path], bool] = (
        (lambda _path: True) if all_delivered else config_is_client_supplied
    )
    if not any(is_delivered(path) for path in documents):
        return config
    if rules is None:
        rules = rules_from(
            _trusted_config(trusted_config_path, source_dir, permit_base)
        )
    if rules.unreadable is not None:
        from automated_security_helper.core.exceptions import (
            ASHConfigPolicyUnreadableError,
        )

        raise ASHConfigPolicyUnreadableError(
            f"A config an MCP client delivered cannot be checked: {rules.unreadable}"
        )
    root = Path(scanned_root or source_dir or Path.cwd())
    found = client_file_denials(
        documents, rules, scanned_root=root, all_delivered=all_delivered
    )
    if found and DENIED_FIELD_HANDLING == "refuse":
        from automated_security_helper.core.exceptions import (
            ASHConfigFieldDeniedError,
        )

        path, denials = found[0]
        raise ASHConfigFieldDeniedError(denied_fields_message(path, denials))
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
    chain or in the trusted ``base``; every other entry is marked
    ``client_supplied``, so an entry whose source is unknown counts as the
    client's.
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
        document for path, document in documents.items() if not delivered(path)
    ]
    sources.append(base.model_dump(mode="json", by_alias=True))
    for source in sources:
        for field, model in models.items():
            present, entries = _walk(source, ["global_settings", field])
            for raw in entries if present and isinstance(entries, list) else []:
                try:
                    entry = model.model_validate(raw)
                except Exception:  # noqa: BLE001 -- validation is reported elsewhere
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

    An operator config a client delivered is not one, and falls back to the default.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.resolve_config import _load_operator_config

    operator = _load_operator_config(trusted_config_path, source_dir, permit_base)
    if operator is not None and not any(
        config_is_client_supplied(path) for path in operator[1]
    ):
        return operator[0]
    return trusted_default_config()


def trusted_default_config() -> AshConfig:
    """The server's default config, unless ``ASH_CONFIG`` names a client's file.

    ``get_default_config`` reads ``ASH_CONFIG``. A file under the MCP workspace
    root is a client's wherever it is named from (``config_is_client_supplied``),
    so when ``ASH_CONFIG`` or a base it extends is one, the built-in defaults are
    the trusted config instead, and the policy is not read from it.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.default_config import (
        default_config_chain,
        get_default_config,
    )
    from automated_security_helper.utils.log import ASH_LOGGER

    chain = default_config_chain()
    if any(config_is_client_supplied(path) for path in chain):
        ASH_LOGGER.warning(
            "ASH_CONFIG names a file under the MCP workspace root, which an MCP "
            "client delivered, so ASH's built-in defaults are the trusted config "
            "instead. Keep the server's config outside the MCP workspace root."
        )
        return AshConfig()
    return get_default_config()
