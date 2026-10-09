# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reporter options a config file in the scanned tree may not choose.

The AWS reporters send findings to a service: Security Hub in an account and
region, a Bedrock model in a region, an S3 bucket and key prefix, a CloudWatch
Logs group and stream. Their profile option picks the credentials they use, and
the Bedrock reporter writes its summaries to the files its options name, joined
to the reports directory, so an absolute path or ``..`` writes elsewhere. When the
config was built from a file inside the scanned tree (``config/sandbox_grants.py``
decides that), or from a file an MCP client delivered (``untrusted_config``), those
options come from the trusted base instead: the defaults, an operator config
outside the tree, and ``--config-overrides``. Each section a reporter reads under
any spelling ``AshConfig.get_plugin_config`` accepts is covered, and the values
that are not honored are named in one warning.

Only the built-in reporters' options are listed. A third-party reporter's
destination options are its own, and are not known here. Other options of these
reporters (``enabled``, formatting, model parameters) still apply from the tree.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Tuple

from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig

#: The options of each built-in reporter that pick where findings go or which
#: credentials send them. Where each is used is listed in the PR that added this.
REPORTER_DESTINATION_OPTIONS: Dict[str, Tuple[str, ...]] = {
    "aws-security-hub": ("aws_region", "aws_profile", "account_id"),
    "bedrock-summary-reporter": (
        "aws_region",
        "aws_profile",
        "model_id",
        "output_file",
        "output_executive_file",
        "output_technical_file",
    ),
    "cloudwatch-logs": ("aws_region", "log_group_name", "log_stream_name"),
    "s3": ("aws_region", "aws_profile", "bucket_name", "key_prefix"),
}

_MISSING = object()


def _as_dict(section: Any) -> Optional[Dict[str, Any]]:
    if isinstance(section, dict):
        return dict(section)
    if hasattr(section, "model_dump"):
        return section.model_dump(by_alias=True)
    return None


def confine_reporter_destinations(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
) -> None:
    """Replace the destination options an in-tree file set with the trusted base's.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built for the sandbox
            settings: the defaults, or the operator's config outside the tree.
        config_overrides: ``--config-overrides``. Those under ``reporters`` are
            replayed onto ``trusted_config``, the same way the sandbox overrides
            are, so an override still sets these options.
        in_tree: The config files inside the tree, named in the warning.
    """
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    reporter_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip().split(".")[0]
        == "reporters"
    ]
    if reporter_overrides:
        trusted_config = apply_config_overrides(trusted_config, reporter_overrides)

    extras = config.reporters.__pydantic_extra__
    if not extras:
        return
    ignored: List[str] = []
    for plugin, option_names in REPORTER_DESTINATION_OPTIONS.items():
        trusted_section = _as_dict(trusted_config.get_plugin_config("reporter", plugin))
        trusted_options = dict((trusted_section or {}).get("options") or {})
        reduced = reduced_plugin_name(plugin)
        for key in list(extras):
            if reduced not in plugin_key_lookup_names(key):
                continue
            section = _as_dict(extras[key])
            if section is None:
                continue
            options = dict(section.get("options") or {})
            changed = False
            for name in option_names:
                wanted = trusted_options.get(name, _MISSING)
                current = options.get(name, _MISSING)
                if current == wanted:
                    continue
                if current is not _MISSING:
                    ignored.append(f"reporters.{key}.options.{name}")
                if wanted is _MISSING:
                    options.pop(name, None)
                else:
                    options[name] = wanted
                changed = True
            if changed:
                section["options"] = options
                extras[key] = section
    if not ignored:
        return
    files = ", ".join(describe_config_path(path) for path in in_tree)
    ASH_LOGGER.warning(
        f"Ignoring {', '.join(ignored)} from {files}: the file is inside the scanned "
        "tree, so the repository being scanned wrote it, and these options choose "
        "where findings are sent or written and which credentials send them. Set "
        "them with --config-overrides or a config file outside the tree."
    )
