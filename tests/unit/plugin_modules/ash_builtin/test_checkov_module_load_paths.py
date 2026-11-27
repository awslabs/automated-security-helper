"""The paths checkov's terraform module load may take, judged through the scan itself.

Each row builds a tree whose module source reaches a directory in a way an earlier
form of the module-load check judged differently from checkov: through a link to a
directory with a ``..`` after it, as an absolute path the operating system resolves
through a link, as the current directory (which checkov never loads), or through a
``.tf`` file larger than ASH reads. Every row goes through ``_execute_scan`` only, so
it reads the same before and after the change it pins.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

posix_only = pytest.mark.skipif(
    os.sep != "/", reason="the trees use POSIX links and paths"
)
needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="the trees need symlinks"
)


def _module(source: str) -> str:
    return f'module "m" {{\n  source = "{source}"\n}}\n'


def _write(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _link_outside(path: Path, outside: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(outside)


def _scan(source: Path, base: Path):
    context = PluginContext(
        source_dir=source,
        output_dir=base / "out",
        work_dir=base / "out" / "converted",
        config=AshConfig(),
    )
    scanner = CheckovScanner(context=context, config=CheckovScannerConfig())
    return scanner._execute_scan(source, "source", [])


@pytest.fixture
def outside(tmp_path) -> Path:
    """A file outside every scanned tree, for the links to point at."""
    target = tmp_path / "outside" / "secret.txt"
    _write(target, "outside\n")
    return target


@posix_only
@needs_symlinks
def test_a_module_reached_through_a_directory_link_joins_its_sources_there(
    tmp_path, outside
):
    """checkov loads ``mods/pkg`` as spelled through the link ``mods`` and joins
    ``../../x`` to that spelling, which names ``x`` at the top of the tree."""
    source = tmp_path / "t"
    _write(source / "main.tf", _module("./mods/pkg"))
    _write(source / "real" / "deep" / "pkg" / "main.tf", _module("../../x"))
    (source / "mods").symlink_to(source / "real" / "deep", target_is_directory=True)
    _write(source / "x" / "main.tf")
    _link_outside(source / "x" / "terraform.tfvars", outside)

    with pytest.raises(ScannerError, match=re.escape("terraform.tfvars")):
        _scan(source, tmp_path)


@posix_only
@needs_symlinks
def test_an_absolute_source_is_resolved_as_the_operating_system_resolves_it(
    tmp_path, outside
):
    """An absolute source that starts with the scanned directory is loaded as its raw
    string, so the link ``mods`` is followed before the ``..``: it names
    ``real/x``, not ``x``."""
    source = tmp_path / "t"
    _write(source / "real" / "deep" / "main.tf")
    (source / "mods").symlink_to(source / "real" / "deep", target_is_directory=True)
    _write(source / "real" / "x" / "main.tf")
    _link_outside(source / "real" / "x" / "terraform.tfvars", outside)
    _write(source / "main.tf", _module(f"{source}/mods/../x"))

    with pytest.raises(ScannerError, match=re.escape("terraform.tfvars")):
        _scan(source, tmp_path)


@posix_only
@needs_symlinks
def test_an_absolute_source_through_a_directory_link_that_leaves_the_tree_refuses(
    tmp_path,
):
    """``out`` is a link to a directory outside the tree, and ``<root>/out/../y`` is
    resolved through it, to a directory beside that one, also outside."""
    elsewhere = tmp_path / "elsewhere"
    _write(elsewhere / "dir" / "main.tf")
    _write(elsewhere / "y" / "main.tf")
    source = tmp_path / "t"
    source.mkdir()
    (source / "out").symlink_to(elsewhere / "dir", target_is_directory=True)
    _write(source / "main.tf", _module(f"{source}/out/../y"))

    with pytest.raises(ScannerError):
        _scan(source, tmp_path)


@posix_only
@needs_symlinks
def test_a_text_form_outside_the_tree_is_judged_where_the_link_takes_it(
    tmp_path, outside
):
    """``<root>/out/../../y`` reads as outside the tree as text, but ``out`` is a link
    to ``inner/dir`` inside it, so the operating system takes it to ``y`` in the
    tree, where a link leaves it."""
    source = tmp_path / "t"
    _write(source / "inner" / "dir" / "main.tf")
    (source / "out").symlink_to(source / "inner" / "dir", target_is_directory=True)
    _write(source / "y" / "main.tf")
    _link_outside(source / "y" / "terraform.tfvars", outside)
    _write(source / "main.tf", _module(f"{source}/out/../../y"))

    with pytest.raises(ScannerError, match=re.escape("terraform.tfvars")):
        _scan(source, tmp_path)


@posix_only
@needs_symlinks
@pytest.mark.parametrize("value", [".", "./"])
def test_the_current_directory_as_a_source_is_not_a_module_load(
    tmp_path, outside, value
):
    """checkov loads no module for ``.`` or ``./``, so a link of a name the load
    reads, at the top of the tree, is left to its own ``--skip-path`` value and the
    scan runs."""
    source = tmp_path / "t"
    _write(source / "main.tf", _module(value))
    _link_outside(source / "terraform.tfvars", outside)

    argv, _, _ = _scan(source, tmp_path)

    assert any("terraform[.]tfvars" in item for item in argv)


@posix_only
def test_a_tf_file_larger_than_ash_reads_refuses_the_scan(tmp_path):
    """ASH reads at most a few MiB of each ``.tf`` file to look for module sources;
    one larger than that refuses the target rather than being read whole."""
    source = tmp_path / "t"
    _write(source / "main.tf")
    big = source / "big.tf"
    big.write_bytes(b"")
    os.truncate(big, 64 * 1024 * 1024)

    with pytest.raises(ScannerError, match=re.escape("big.tf")):
        _scan(source, tmp_path)
