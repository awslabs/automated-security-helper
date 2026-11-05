"""The ``--skip-path`` values for ``KNOWN_IGNORE_PATHS`` match whole directory names.

checkov applies each ``--skip-path`` value with ``re.search`` and as a substring
against the walked path (``checkov/common/runners/base_runner.py``,
``filter_ignored_paths``, 3.3.26). Passed as the bare ``venv/``, the value
skipped every file under any directory whose name merely ends in ``venv``
(``devenv/``, ``prevenv/``) and ``node_modules/`` every file under
``old_node_modules/``, so IaC under such directories was silently left out of the
scan. ``_skipped`` below applies the values the way checkov does.

The anchor is a leading ``/``, never ``(^|/)`` or ``^``: a Windows launch route
that re-reads the command line through cmd.exe split the ``(^|/)`` form at its
unquoted ``|`` (the Install Method Validation failure), and cmd.exe consumes an
unquoted ``^`` as its escape character. ``/NAME/`` carries no character cmd.exe
acts on, and matches the same paths for every target ASH gives checkov, which is
always absolute (``_known_ignore_skip_pattern``'s docstring has the one relative
shape the old form covered and this one does not).
"""

from __future__ import annotations

import os
import re

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    checkov_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    _module_finder_compiles,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()


def _skipped(patterns, path: str) -> bool:
    """checkov's test: a regex search or a substring match on the walked path."""
    return any(re.search(p, path) or p in path for p in patterns)


def _known_ignore_values(test_plugin_context):
    # Construction runs ``_process_config_options`` (``model_post_init``); a second
    # call appends every value again, so the arguments are read as built.
    scanner = CheckovScanner(context=test_plugin_context, config=CheckovScannerConfig())
    return [
        arg.key[len("--skip-path=") :]
        for arg in scanner.args.extra_args
        if arg.key.startswith("--skip-path=")
    ]


@pytest.mark.parametrize(
    "path",
    [
        "/repo/devenv/main.tf",
        "/repo/prevenv/main.tf",
        "/repo/old_node_modules/stack.yaml",
        "/repo/my.venv/main.tf",
        "/repo/venvx/main.tf",
    ],
)
def test_a_directory_whose_name_only_ends_in_a_known_name_is_scanned(
    test_plugin_context, path
):
    values = _known_ignore_values(test_plugin_context)
    assert values, "KNOWN_IGNORE_PATHS produced no --skip-path values"
    assert not _skipped(values, path), (
        f"{path} is skipped by {values!r}; at the base the bare 'venv/' and "
        "'node_modules/' matched it as a substring"
    )


@pytest.mark.parametrize(
    "path",
    [
        "/repo/venv/lib/main.tf",
        "/repo/.venv/lib/main.tf",
        "/repo/node_modules/pkg/stack.yaml",
        "/repo/sub/venv/main.tf",
        "/repo/node_modules/a/node_modules/b/main.tf",
    ],
)
def test_the_known_directories_themselves_are_still_skipped(test_plugin_context, path):
    values = _known_ignore_values(test_plugin_context)
    assert _skipped(values, path), f"{path} is not skipped by {values!r}"


def test_every_known_ignore_path_is_anchored_to_a_path_component():
    for entry in KNOWN_IGNORE_PATHS:
        value = checkov_scanner._known_ignore_skip_pattern(entry)
        assert value.startswith("/"), value
        assert value.endswith("/"), value
        assert "\\." not in value, f"{value!r}: a dot is written [.], never \\."


def test_every_known_ignore_value_survives_a_cmd_exe_re_read():
    """No value holds a character cmd.exe acts on when it re-reads a line.

    ``< > | & ^ ( )`` act when written bare (``subprocess_utils``'s
    ``_CMD_CHARACTERS``), and ``%`` can pair into a variable name: the
    ``(^|/)`` form was split at its ``|`` by a batch interpreter below
    ``uv tool run`` on windows-latest, and an unquoted ``^`` is cmd.exe's
    escape character, consumed silently. These values go through every launch
    route byte-identical or the launch itself is wrong.
    """
    for entry in KNOWN_IGNORE_PATHS:
        value = checkov_scanner._known_ignore_skip_pattern(entry)
        acted_on = set(value) & set("<>|&^()%\"' \t")
        assert not acted_on, f"{value!r} holds {sorted(acted_on)!r}"


def test_a_root_level_directory_under_an_absolute_target_is_skipped(
    test_plugin_context,
):
    # ASH always hands checkov an absolute target (_execute_scan's abspath), so
    # every walked path starts with "/" and the leading-slash anchor covers a
    # known directory at the scan root too.
    values = _known_ignore_values(test_plugin_context)
    assert _skipped(values, "/venv/lib/main.tf")
    assert _skipped(values, "/repo/.venv/bin/template.yaml")


def test_the_one_uncovered_shape_is_a_relative_root_named_like_a_known_dir(
    test_plugin_context,
):
    """The documented limit of the leading-slash anchor, pinned on purpose.

    A RELATIVE walked path whose first component is the known name (a scan
    root directly named ``venv``, scanned by a relative path) was covered by
    the old ``(^|/)`` form and is not by ``/NAME/``. No ASH invocation
    produces it: ``_execute_scan`` makes the target absolute and checkov runs
    from the filesystem root, so this is a limit of the value, not of the
    scan. If this test ever matters, the walked paths stopped being absolute.
    """
    values = _known_ignore_values(test_plugin_context)
    assert not _skipped(values, "venv/main.tf")


def test_the_scanners_own_skip_values_are_the_portable_component_anchors(
    test_plugin_context,
):
    """The argv-level pin: the values the scanner itself puts in its arguments.

    One value per ``KNOWN_IGNORE_PATHS`` name, ``/NAME/`` with dots as ``[.]``,
    and nothing else under the default config -- the exact bytes the Windows
    launch route has to carry.
    """
    values = _known_ignore_values(test_plugin_context)
    assert values == ["/[.]venv/", "/venv/", "/node_modules/"]


def test_the_anchored_values_compile_in_checkovs_module_finder_regex():
    """checkov joins every value into one regex a character at a time."""
    values = [
        checkov_scanner._known_ignore_skip_pattern(entry)
        for entry in KNOWN_IGNORE_PATHS
    ]
    assert _module_finder_compiles(values)
    assert _module_finder_compiles([*values, "^/repo/x[.]tf$", "^/repo/out/"])


@pytest.mark.skipif(os.sep != "/", reason="the output-dir exclusion is POSIX-only")
def test_the_output_dir_value_skips_no_deeper_path_holding_the_same_text(tmp_path):
    """An in-tree output directory's value is anchored at the start of the path.

    Unanchored, the escaped output path also matched a deeper path that holds
    the same text, such as a copy of the tree kept under itself.
    """
    source = tmp_path / "src"
    output = source / "ash-out"
    output.mkdir(parents=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    scanner = CheckovScanner(context=context, config=CheckovScannerConfig())
    argv, _, _ = scanner._execute_scan(source, "source", [])
    values = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--skip-path"]
    # The value is an escaped regex, so the hyphen is written "\-" (re.escape).
    output_values = [v for v in values if re.escape("ash-out") in v]
    assert output_values, values
    assert all(v.startswith("^") for v in output_values), output_values

    root = source.as_posix()
    assert _skipped(values, f"{root}/ash-out/ash.log")
    deeper = f"{root}/copy{root}/ash-out/ash.log"
    assert not _skipped(values, deeper), (
        f"{deeper} is skipped by {output_values!r}; at the base the unanchored "
        "value matched the output path's text anywhere in a walked path"
    )
