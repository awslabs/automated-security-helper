# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import importlib.util
from typing import Iterable, List, Mapping, Optional
from automated_security_helper.utils.log import ASH_LOGGER


def shown_import_failure(
    error: BaseException, name: str, label: str, values: Iterable[str] = ()
) -> str:
    """Why importing or looking up ``name`` failed, as a log line about it says it.

    ``label`` is how the line names the module: the masked form for a name a
    config read from the environment, and the name itself otherwise. For a
    masked name the error's own text is left out with it, because that text
    quotes the name (``No module named '...'``); only its kind is said. For a
    literal name the text is shown through ``error_text``, which redacts the
    env-read values the loader carried onto the error and the ``values`` given
    here: an import error can quote any of them, not only the module's own
    name, and an error raised afresh by this module's own import carries none,
    so its caller passes the run's values.
    """
    if label == name:
        from automated_security_helper.utils.error_text import error_text

        return error_text(error, values)
    return masked_failure_kind(type(error).__name__)


def masked_failure_kind(kind: str) -> str:
    """All a masked name's failure may say about itself: the error's kind.

    One wording for every surface that prints a failure beside a masked name --
    the import log's warning and the loader's refusal -- so the two never
    drift apart on what is withheld and why.
    """
    return (
        f"{kind}, whose text is not shown because it can quote "
        "the name, which was read from the environment"
    )


def _is_top_level_package(name: str, label: Optional[str] = None) -> bool:
    """Whether ``name`` is an importable top-level regular package.

    This used to be answered by walking ``pkgutil.iter_modules()`` -- every entry on
    sys.path -- and comparing names. That walk can raise on an entry that is not a
    module directory at all. On Windows a console-script launcher such as
    ``.venv\\Scripts\\pytest.exe`` is a zip archive and lands on sys.path, so a
    zipimporter for it sits in sys.path_importer_cache. ``importlib.invalidate_caches()``
    (which ``monkeypatch.syspath_prepend`` calls, among others) evicts that archive
    from ``zipimport._zip_directory_cache``, and pkgutil's zip walker indexes that
    private dict directly, so the next walk raised ``KeyError: '...\\pytest.exe'``
    out of discover_plugins (unit-test windows-latest py3.14, run 37632758015, job
    112839639522). Nothing about the plugin being looked for was involved.

    Asking for the one name instead touches no other sys.path entry, and the
    zipimporter's own find_spec repopulates its cache rather than indexing it.

    Kept to what the walk matched. It yielded top-level names only, so a dotted name
    never matched, and it reported a directory as a package only if it had an
    ``__init__`` -- a namespace package (origin None) was not one. One deliberate
    difference: find_spec also consults meta-path finders, so a plugin package
    installed in editable mode through an import hook is now found where the
    sys.path walk could not see it.
    """
    if not name or "." in name:
        return False
    shown = name if label is None else label
    try:
        spec = importlib.util.find_spec(name)
    except Exception as e:  # a broken finder must not stop discovery
        ASH_LOGGER.warning(
            f"Could not look up plugin package {shown}: "
            f"{shown_import_failure(e, name, shown)}"
        )
        return False
    return (
        spec is not None
        and spec.submodule_search_locations is not None
        and spec.origin is not None
    )


def discover_plugins(
    plugin_modules: List[str] | None = None,
    shown: Optional[Mapping[str, str]] = None,
    failed: Iterable[str] = (),
    values: Iterable[str] = (),
):
    """Import the top-level plugin packages *plugin_modules* names.

    A name outside the plugin namespace that ``load_additional_plugin_modules``
    enforces is skipped with the same warning, before it is looked up, so it is
    never imported. A scan refuses such a name before calling this
    (``refuse_plugin_modules_outside_namespace``); the check here keeps every other
    caller to the same rule.

    ``shown`` maps a name to how a log line names it, for a name a config read
    from the environment (``plugin_module_trust.shown_module_names``); any other
    name is named as it is.

    ``failed`` names the modules the run's loader already failed to import or
    register (the keys of the run's ``PluginLoadRecord``). They are not imported
    again: the loader recorded the failure with the run's env-read values
    redacted, removed the module from ``sys.modules`` and undid what it
    registered, so a second import would run the failing body again, log the
    error's text with nothing to redact it by, and, for a module whose
    declarations were what failed, register its plugins again. The run refuses
    such a module on its record (``refuse_failed_plugin_imports``).

    ``values`` are the values the run's configuration read from the environment
    (``error_text.config_environment_values``). A failure raised by the import
    here is a new exception object: nothing was carried onto it, so without them
    its warning line printed a value the loader had redacted from the same
    failure.
    """
    from automated_security_helper.utils.redacted_model import value_tuple

    values = value_tuple(values)
    from automated_security_helper.plugins.loader import (
        _is_allowed_module_path,
        _namespace_rule,
        masked_module_scope,
    )
    from automated_security_helper.plugins.plugin_manager import masked_module_names

    if plugin_modules is None:
        plugin_modules = ["ash_plugins"]
    labels = shown or {}
    # The import below runs the package's decorators, as the loader's import
    # does, so it runs under the same scope: a package whose body registers a
    # plugin and then raises is registered here with these names recorded.
    masked_scope = masked_module_scope(labels)
    already_failed = set(failed)
    discovered = {"converters": [], "scanners": [], "reporters": []}

    # Look for top-level packages named by plugin_modules
    for name in dict.fromkeys(plugin_modules):
        label = labels.get(name, name)
        if name in already_failed:
            ASH_LOGGER.debug(
                f"Not importing plugin package {label} again: its import or "
                "registration failed earlier in this run"
            )
            continue
        if not _is_allowed_module_path(name):
            ASH_LOGGER.warning(
                f"Skipping module with unexpected namespace: {label}. "
                f"{_namespace_rule()}"
            )
            continue
        if not _is_top_level_package(name, label):
            continue
        try:
            with masked_module_names(masked_scope):
                # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
                module = importlib.import_module(name)
            # The import itself should trigger plugin registration
            # via the AshPlugin metaclass
            ASH_LOGGER.info(f"Discovered plugin package: {label}")

            # Track what was discovered
            if hasattr(module, "ASH_CONVERTERS"):
                discovered["converters"].extend(module.ASH_CONVERTERS)
            if hasattr(module, "ASH_SCANNERS"):
                discovered["scanners"].extend(module.ASH_SCANNERS)
            if hasattr(module, "ASH_REPORTERS"):
                discovered["reporters"].extend(module.ASH_REPORTERS)

        except Exception as e:  # noqa: BLE001 -- one path for every import failure
            # Not only ImportError, as the loader's import arm
            # (loader.load_additional_plugin_modules): the loader has already
            # recorded a module whose body raised and removed it from
            # sys.modules, so this re-import raises the same error again; it
            # must not escape as an unexpected failure (exit 1) past the
            # recorded, exit-3 refusal refuse_failed_plugin_imports raises next.
            ASH_LOGGER.warning(
                f"Failed to import plugin {label}: "
                f"{shown_import_failure(e, name, label, values)}"
            )

    return discovered
