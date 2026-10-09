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
package that sends findings off the host). Refusing them as well would refuse a
file that tightens the sandbox.

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
    Tuple,
)

from pydantic import BaseModel, ConfigDict

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
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
#: first, as sets. A profile whose list equals one of these, as ``ash config
#: init`` writes it, counts as using the default rather than choosing its own;
#: only an edited list is the operator's explicit choice. Add the new default
#: here when it changes (``test_the_current_default_is_a_shipped_default``).
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
            "/reporters/bedrock-summary-reporter/options/aws_*",
            "/reporters/cloudwatch-logs/**",
        ),
    )
)


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
    """``config``'s runtime-override policy, or the defaults when it sets none."""
    mcp = getattr(config.global_settings, "mcp", None)
    return mcp.runtime_overrides if mcp is not None else RuntimeOverridesConfig()


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
    """
    if "denied_paths" not in policy.model_fields_set:
        return True
    return frozenset(policy.denied_paths) in SHIPPED_DEFAULT_DENIED_PATHS


def exempt_paths(policy: RuntimeOverridesConfig) -> Tuple[str, ...]:
    """The pointers a delivered file is not checked against ``denied_paths`` for.

    Only under a default ``denied_paths``: an operator who edited the list
    decides about each of them there. Value patterns apply to them either way.
    """
    if not policy_is_default(policy):
        return ()
    if HONOR_DELIVERED_SUPPRESSIONS:
        return RESTRICT_ONLY_PATHS + SUPPRESSION_PATHS
    return RESTRICT_ONLY_PATHS


def denied_fields_message(path: Path, denials: Sequence[Any]) -> str:
    """The refusal text for ``path``, naming every denied field it sets."""
    from automated_security_helper.config.config_sources import describe_config_path

    fields = "; ".join(f"{denial.key} ({denial.reason})" for denial in denials)
    return (
        f"{describe_config_path(Path(path))} was delivered by an MCP client and sets "
        f"fields this server's runtime-override policy does not let a client set: "
        f"{fields}. Remove them from the file, or ask the operator for a profile "
        f"that sets them."
    )


def client_file_denials(
    documents: Mapping[Path, Any], rules: ClientConfigRules
) -> List[Tuple[Path, List[Any]]]:
    """(file, denials) for each client-delivered file in ``documents`` that sets a denied field."""
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.runtime_patch import (
        config_document_denials,
    )

    found: List[Tuple[Path, List[Any]]] = []
    for path, document in documents.items():
        if not config_is_client_supplied(path):
            continue
        denials = config_document_denials(
            document,
            allowlist=rules.policy,
            config=rules.base,
            exempt=exempt_paths(rules.policy),
            inert=INERT_PATHS,
        )
        if denials:
            found.append((path, denials))
    return found


def apply_client_config_rules(
    config: AshConfig,
    documents: Mapping[Path, Any],
    *,
    rules: Optional[ClientConfigRules],
    trusted_config_path: Path | str | None,
    source_dir: Path | str | None,
    permit_base: Optional[Callable[[Path], bool]],
) -> AshConfig:
    """``config``, checked for denied fields its client-delivered files set.

    Refuses or drops them according to ``DENIED_FIELD_HANDLING``. ``rules`` None
    takes the trusted base's.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    if not any(config_is_client_supplied(path) for path in documents):
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
    found = client_file_denials(documents, rules)
    if not found:
        return _mark_client_supplied(config, documents, rules.base)
    if DENIED_FIELD_HANDLING == "refuse":
        from automated_security_helper.core.exceptions import (
            ASHConfigFieldDeniedError,
        )

        path, denials = found[0]
        raise ASHConfigFieldDeniedError(denied_fields_message(path, denials))
    return _mark_client_supplied(
        _drop_denied_fields(config, found, rules.base), documents, rules.base
    )


def _mark_client_supplied(
    config: AshConfig, documents: Mapping[Path, Any], base: AshConfig
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

    models = {"suppressions": AshSuppression, "ignore_paths": IgnorePathWithReason}
    operators: Dict[str, List[Dict[str, Any]]] = {field: [] for field in models}
    sources: List[Any] = [
        document
        for path, document in documents.items()
        if not config_is_client_supplied(path)
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
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.config.resolve_config import _load_operator_config

    operator = _load_operator_config(trusted_config_path, source_dir, permit_base)
    if operator is not None and not any(
        config_is_client_supplied(path) for path in operator[1]
    ):
        return operator[0]
    return get_default_config()
