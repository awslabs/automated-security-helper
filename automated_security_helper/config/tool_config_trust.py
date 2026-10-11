# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner's own config file comes from the operator, not from the scanned tree.

Why this exists
---------------
bandit, grype and syft each read a config file of their own, and that file can
leave findings out: bandit's ``skips`` and ``exclude_dirs``, grype's ``ignore``
and ``only-fixed``, syft's ``exclude``. ASH used to find such a file by name in
the source directory (``.bandit``, ``bandit.yaml``, ``.grype.yaml``,
``.syft.yaml`` and others), and took ``scanners.<name>.options.config_file``
from whatever config the repository carried. So the repository being scanned
chose what its own scan reported. A repository's tool configs are now ignored
unless the operator sets them, as checkov's and ferret-scan's already are
(``config/path_trust.py``).

What happens now
----------------
* When the config was built from a file inside the scanned tree, or from a file
  an MCP client delivered, ``config_file`` of each scanner in
  ``SCANNER_CONFIG_FILE_OPTIONS`` comes from the trusted base ``resolve_config``
  builds (the defaults, or an operator config outside the tree), with
  ``--config-overrides`` replayed onto it (``confine_scanner_config_files``). An
  operator who wants a repository's own file names it with
  ``--config-overrides``; that path is used even inside the tree, because the
  operator chose it. Under the MCP server the default ``denied_paths`` refuse a
  client's file that names one, and the overrides ``resolve_config`` is handed
  there are the client's, so none is replayed.
* The scanners no longer look for a config file by name.
* Each of them hands its tool an explicit config, the operator's or an empty one
  ASH writes in the results directory, so the tool does not pick a file up from
  the tree on its own either (see each scanner's ``_process_config_options``).

The same rule as reporter destinations (``config/reporter_trust.py``), which this
follows.

Failure modes and known limitations
-----------------------------------
* A repository that relied on its own file now scans without it, and the scan's
  warnings name the option that was ignored. The CHANGELOG says how to keep it:
  name the file with ``--config-overrides`` or in an operator config.
* Only these three scanners' ``config_file`` are covered here. checkov's and
  ferret-scan's are refused inside the tree by ``config/path_trust.py`` whoever
  names them. detect-secrets' baseline is not covered here; under the MCP
  server it is a default ``denied_paths`` entry.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Tuple

from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig

#: Scanners whose own config file is the operator's choice, and the options that
#: name it.
SCANNER_CONFIG_FILE_OPTIONS: Dict[str, Tuple[str, ...]] = {
    "bandit": ("config_file",),
    "grype": ("config_file",),
    "syft": ("config_file",),
}

_MISSING = object()


def _options_of(section: Any) -> Any:
    if isinstance(section, dict):
        options = section.get("options")
        return options if isinstance(options, dict) else None
    return getattr(section, "options", None)


def _get(options: Any, name: str) -> Any:
    if isinstance(options, dict):
        return options.get(name, _MISSING)
    return getattr(options, name, _MISSING)


def _set(options: Any, name: str, value: Any) -> None:
    if isinstance(options, dict):
        if value is _MISSING:
            options.pop(name, None)
        else:
            options[name] = value
    else:
        setattr(options, name, None if value is _MISSING else value)


def confine_scanner_config_files(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
) -> None:
    """Replace the tool config files an in-tree or delivered file named with the trusted base's.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built for the sandbox
            settings: the defaults, or the operator's config outside the tree.
        config_overrides: ``--config-overrides``. Those under ``scanners`` are
            replayed onto ``trusted_config``, as the reporter overrides are in
            ``confine_reporter_destinations``, so an override still sets these.
        in_tree: The config files inside the tree, named in the warning.
    """
    from automated_security_helper.config.client_scanner_exclusions import (
        _scanner_sections,
    )
    from automated_security_helper.config.config_sources import describe_config_path
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    scanner_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip().split(".")[0]
        == "scanners"
    ]
    if scanner_overrides:
        trusted_config = apply_config_overrides(trusted_config, scanner_overrides)

    ignored: List[str] = []
    for scanner, option_names in SCANNER_CONFIG_FILE_OPTIONS.items():
        trusted_section = trusted_config.get_plugin_config("scanner", scanner)
        trusted_options = (trusted_section or {}).get("options") or {}
        for key, section in _scanner_sections(config, scanner):
            options = _options_of(section)
            if options is None:
                continue
            for name in option_names:
                wanted = trusted_options.get(name, _MISSING)
                current = _get(options, name)
                if current in (_MISSING, None) and wanted in (_MISSING, None):
                    continue
                if current == wanted:
                    continue
                if current not in (_MISSING, None):
                    ignored.append(f"scanners.{key}.options.{name}")
                _set(options, name, wanted)
    if ignored:
        files = ", ".join(describe_config_path(path) for path in in_tree)
        ASH_LOGGER.warning(
            f"Ignoring {', '.join(sorted(set(ignored)))} from {files}: a scanner's "
            "own config file is the operator's choice, and that config is inside "
            "the scanned tree or was delivered by an MCP client. Name the file with "
            "--config-overrides or in a config file outside the tree."
        )


def empty_tool_config(results_dir: Any, name: str, content: str) -> Path:
    """A config file that sets nothing, written in the scanner's results directory.

    Handed to a tool that would otherwise look for its config file in its
    working directory or under the scan target on its own. Written without
    following a link at that name (``utils/sandbox/fs_guard.open_for_write``),
    since a sandboxed scanner can write its results directory.
    """
    import os

    from automated_security_helper.utils.sandbox.fs_guard import open_for_write

    if results_dir is None:
        raise ValueError(f"no results directory to write {name} in")
    written = Path(os.path.abspath(results_dir)) / name
    written.parent.mkdir(parents=True, exist_ok=True)
    with open_for_write(written) as handle:
        handle.write(content)
    return written
