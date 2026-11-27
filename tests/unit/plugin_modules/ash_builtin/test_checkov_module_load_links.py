"""A local module source makes checkov load a directory with no ``--skip-path`` value.

checkov's terraform parser loads the directory a local module source names (a value
that is ``.`` or starts with ``./``, ``../`` or ``/``) with ``_internal_dir_load`` and
no ``excluded_paths`` (``checkov/terraform/tf_parser.py`` lines 253, 263-269 and
546-549, checkov 3.4.7). That load reads, following links to files,
``terraform.tfvars.json``, ``terraform.tfvars``, ``*.auto.tfvars``,
``*.auto.tfvars.json`` and every ``*.tf`` and ``*.hcl`` file in the directory (lines
569-604), and a source path that goes through a link to a directory is followed. So
on every platform a link to a file outside the scanned directory, with one of those
names and directly in such a directory, is read whatever ``--skip-path`` says: the
value ASH gives the link, and the rule that leaves a link under a directory checkov
skips out of the list, change nothing there.

``_module_load_link`` finds those links and sources, and ``_execute_scan`` refuses the
scan when it finds one. The rows here build real trees with real links. The rule
reads ``source = "<value>"`` in every ``.tf`` and ``.hcl`` file that is not itself a
link, in any block, so it errs toward refusing; a module source that leaves the
scanned directory as text, with no link, is out of its scope.
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
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    checkov_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    _is_local_module_source,
    _known_directory_skip_values,
    _module_load_link,
    _module_load_reads,
    _skip_path_root,
)
from automated_security_helper.utils.get_scan_set import file_links_leaving_tree

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

posix_only = pytest.mark.skipif(
    os.sep != "/", reason="the values are sent on POSIX only"
)
needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)

#: The names the module load reads, each as a link directly in the module directory.
_READ_NAMES = (
    "terraform.tfvars",
    "terraform.tfvars.json",
    "x.auto.tfvars",
    "x.auto.tfvars.json",
    "extra.tf",
    "x.hcl",
)


def _module(source: str) -> str:
    """The text of a Terraform file with one module block whose source is ``source``."""
    return f'module "m" {{\n  source = "{source}"\n}}\n'


def _scanner(source: Path, output: Path) -> CheckovScanner:
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return CheckovScanner(context=context, config=CheckovScannerConfig())


def _scan(source: Path, base: Path):
    """``_execute_scan`` of ``source``, with the output directory beside it."""
    return _scanner(source, base / "out")._execute_scan(source, "source", [])


def _argv_skip_values(argv) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--skip-path"]


def _own_value(source: Path, relative: str) -> str:
    """The ``--skip-path`` value ASH gives the link at ``relative`` below ``source``."""
    escaped = re.escape(f"{_skip_path_root(source)}/{relative}")
    return "^" + escaped.replace("\\.", "[.]") + "$"


def _tree(
    base: Path,
    files: dict[str, str] | None = None,
    links: tuple[str, ...] | list[str] = (),
    directory_links: dict[str, Path] | None = None,
    outside_text: str = "outside\n",
) -> Path:
    """``base/src`` with ``files`` (path below it to text), a link to a file outside
    it at each of ``links`` and a link to the directory ``directory_links`` gives at
    each of its keys. ``base/outside`` holds the file every link points at
    (``target.txt``, holding ``outside_text``) and a directory ``dir`` with a module
    ``pkg`` in it, for a directory link to point at."""
    outside = base / "outside"
    (outside / "dir" / "pkg").mkdir(parents=True)
    (outside / "target.txt").write_text(outside_text, encoding="utf-8")
    (outside / "dir" / "pkg" / "main.tf").write_text("", encoding="utf-8")
    source = base / "src"
    source.mkdir()
    for relative, text in (files or {}).items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for relative in links:
        link = source / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside / "target.txt")
    for relative, target in (directory_links or {}).items():
        link = source / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target, target_is_directory=True)
    return source


def _module_read(source: Path):
    """``_module_load_link`` over the walk the scanner makes."""
    all_files: list[str] = []
    links = file_links_leaving_tree(source, all_files=all_files)
    return _module_load_link(source, links, all_files)


@pytest.fixture
def ckv_defaults(monkeypatch):
    """The variable checkov's directory rule reads, unset, so a row starts from
    checkov's default whatever the host sets."""
    monkeypatch.delenv("CKV_IGNORED_DIRECTORIES", raising=False)


# ---------------------------------------------------------------------------
# The scan: a link in a directory a module source names refuses it
# ---------------------------------------------------------------------------


@posix_only
@needs_symlinks
def test_a_link_in_a_module_directory_under_node_modules_refuses_the_scan(tmp_path):
    """The known-directory values skip ``node_modules`` in checkov's walks, which left
    a link there with no value of its own. The module load reads it all the same:
    the scan is refused, naming the link and the file that names its directory."""
    link = "node_modules/pkg/terraform.tfvars"
    linked = _tree(
        tmp_path / "with",
        files={
            "main.tf": _module("./node_modules/pkg"),
            "node_modules/pkg/main.tf": "",
        },
        links=[link],
    )

    with pytest.raises(ScannerError, match=re.escape(repr(link))) as refused:
        _scan(linked, tmp_path / "with")

    message = str(refused.value)
    assert "link leaves the scanned tree" in message
    assert "'main.tf'" in message
    assert "none of its --skip-path values" in message


@posix_only
@needs_symlinks
def test_the_same_tree_without_the_module_block_is_not_refused(tmp_path):
    """The control for the row above: with no module block naming the directory, the
    link under ``node_modules`` is not read, and it gets no value of its own, since
    the known values skip the directory whole. Only those values are sent."""
    plain = _tree(
        tmp_path / "without",
        files={"main.tf": "", "node_modules/pkg/main.tf": ""},
        links=["node_modules/pkg/terraform.tfvars"],
    )

    argv, _, _ = _scan(plain, tmp_path / "without")

    assert _argv_skip_values(argv) == _known_directory_skip_values(
        _skip_path_root(plain)
    )


@posix_only
@needs_symlinks
@pytest.mark.parametrize("name", _READ_NAMES)
def test_a_link_the_module_load_reads_refuses_the_scan(tmp_path, name):
    """Each name the module load reads, as a link directly in the module directory:
    refused (it used to get a value of its own, which the module load ignores)."""
    relative = f"mods/pkg/{name}"
    linked = _tree(
        tmp_path / "with",
        files={"main.tf": _module("./mods/pkg"), "mods/pkg/main.tf": ""},
        links=[relative],
    )
    with pytest.raises(ScannerError, match=re.escape(repr(relative))):
        _scan(linked, tmp_path / "with")

    # The control: with no module block naming the directory the same link gets its
    # own value, as it did before the rule.
    plain = _tree(
        tmp_path / "without",
        files={"main.tf": "", "mods/pkg/main.tf": ""},
        links=[relative],
    )
    argv, _, _ = _scan(plain, tmp_path / "without")
    assert _own_value(plain, relative) in _argv_skip_values(argv)


@posix_only
@needs_symlinks
@pytest.mark.parametrize(
    "relative",
    [
        pytest.param("mods/pkg/readme.md", id="another-name"),
        pytest.param("mods/pkg/sub/terraform.tfvars", id="a-subdirectory"),
        pytest.param("mods/other/terraform.tfvars", id="another-directory"),
    ],
)
def test_a_link_the_module_load_does_not_read_keeps_its_own_value(tmp_path, relative):
    """The rule refuses what checkov reads and nothing else: a link with another name
    in the module directory, one in its subdirectory (the load does not enter it) and
    one in a directory no source names are all left out by their own value, as
    before."""
    source = _tree(
        tmp_path,
        files={"main.tf": _module("./mods/pkg"), "mods/pkg/main.tf": ""},
        links=[relative],
    )

    argv, _, _ = _scan(source, tmp_path)

    assert _own_value(source, relative) in _argv_skip_values(argv)


@posix_only
@needs_symlinks
def test_a_module_source_through_a_directory_link_that_leaves_the_tree_refuses(
    tmp_path,
):
    """``mods`` is a link to a directory outside the tree, and the source goes through
    it: checkov loads that directory whatever the files in it are called, so the
    scan is refused, naming the source and the file that holds it."""
    source = _tree(
        tmp_path,
        files={"main.tf": _module("./mods/pkg")},
        directory_links={"mods": tmp_path / "outside" / "dir"},
    )

    with pytest.raises(ScannerError, match=re.escape(repr("./mods/pkg"))) as refused:
        _scan(source, tmp_path)

    message = str(refused.value)
    assert "reaches a directory that leaves the scanned tree" in message
    assert "'main.tf'" in message


@posix_only
@needs_symlinks
def test_a_directory_link_inside_the_tree_is_judged_by_the_directory_it_names(
    tmp_path,
):
    """``mods`` is a link to ``real`` inside the tree. With no link that leaves it in
    ``real/pkg`` the scan runs; with one the scan is refused, the link named by the
    path it has in the tree (``real/pkg``, where the walk finds it)."""
    clean = _tree(
        tmp_path / "clean",
        files={"main.tf": _module("./mods/pkg"), "real/pkg/main.tf": ""},
        directory_links={"mods": tmp_path / "clean" / "src" / "real"},
    )
    _scan(clean, tmp_path / "clean")

    link = "real/pkg/terraform.tfvars"
    linked = _tree(
        tmp_path / "linked",
        files={"main.tf": _module("./mods/pkg"), "real/pkg/main.tf": ""},
        links=[link],
        directory_links={"mods": tmp_path / "linked" / "src" / "real"},
    )
    with pytest.raises(ScannerError, match=re.escape(repr(link))):
        _scan(linked, tmp_path / "linked")


@posix_only
@needs_symlinks
def test_a_source_with_dot_dot_that_stays_in_the_tree_refuses(tmp_path):
    """``envs/prod/main.tf`` reaches ``shared/pkg`` with ``../..``, inside the tree,
    and a link there that leaves the tree is read by the module load."""
    link = "shared/pkg/terraform.tfvars"
    source = _tree(
        tmp_path,
        files={
            "envs/prod/main.tf": _module("../../shared/pkg"),
            "shared/pkg/main.tf": "",
        },
        links=[link],
    )

    with pytest.raises(ScannerError, match=re.escape(repr(link))) as refused:
        _scan(source, tmp_path)

    assert repr("envs/prod/main.tf") in str(refused.value)


@posix_only
@needs_symlinks
def test_a_tf_file_that_is_a_link_is_not_read_for_module_blocks(tmp_path):
    """``linked.tf`` leaves the tree and holds a module block that would name
    ``mods/pkg``, where a link that leaves the tree has a name the load reads. ASH
    does not read a ``.tf`` file that is a link, so the rule finds nothing from it,
    and the scan runs, each link left out by its own value."""
    source = _tree(
        tmp_path,
        files={"main.tf": "", "mods/pkg/main.tf": ""},
        links=["linked.tf", "mods/pkg/terraform.tfvars"],
        outside_text=_module("./mods/pkg"),
    )
    assert _module_read(source) is None

    argv, _, _ = _scan(source, tmp_path)

    given = _argv_skip_values(argv)
    assert _own_value(source, "linked.tf") in given
    assert _own_value(source, "mods/pkg/terraform.tfvars") in given


@posix_only
@needs_symlinks
def test_a_tf_file_that_is_a_link_inside_the_tree_is_read_from_its_own_directory(
    tmp_path,
):
    """``alias.tf`` is a link to ``real/call.tf``, inside the tree. checkov reads it
    from the top directory, so its ``./mods/pkg`` names ``mods/pkg`` there, where a
    link that leaves the tree has a name the load reads. Read from ``real/`` the same
    source names a directory that does not exist, so only reading the link finds it."""
    link = "mods/pkg/terraform.tfvars"
    source = _tree(
        tmp_path,
        files={"real/call.tf": _module("./mods/pkg"), "mods/pkg/main.tf": ""},
        links=[link],
    )
    (source / "alias.tf").symlink_to(source / "real" / "call.tf")

    assert _module_read(source) == (link, "alias.tf")
    with pytest.raises(ScannerError, match=re.escape(repr(link))):
        _scan(source, tmp_path)


@posix_only
@needs_symlinks
def test_a_module_source_that_leaves_the_tree_with_no_link_is_out_of_scope(tmp_path):
    """The limit of the rule, pinned on purpose: a source that climbs out of the
    scanned directory as text (``../outside/dir/pkg``) names a directory this rule
    does not judge, and no link is involved, so nothing is refused here."""
    source = _tree(tmp_path, files={"main.tf": _module("../outside/dir/pkg")})
    assert (tmp_path / "outside" / "dir" / "pkg").is_dir()

    assert _module_read(source) is None
    _scan(source, tmp_path)


@posix_only
@needs_symlinks
def test_the_rule_holds_where_no_value_is_sent(tmp_path, monkeypatch, ckv_defaults):
    """Windows-shaped, with the separator faked as the known-directory tests do.

    No ``--skip-path`` value is sent there, and checkov's own rules skip
    ``node_modules`` by default, so the link under it was left out before the rule.
    The module block that names its directory refuses the scan all the same, and
    the tree without the block still runs with no value sent.
    """
    link = "node_modules/pkg/terraform.tfvars"
    linked = _tree(
        tmp_path / "with",
        files={
            "main.tf": _module("./node_modules/pkg"),
            "node_modules/pkg/main.tf": "",
        },
        links=[link],
    )
    plain = _tree(
        tmp_path / "without",
        files={"main.tf": "", "node_modules/pkg/main.tf": ""},
        links=[link],
    )
    refused = _scanner(linked, tmp_path / "with" / "out")
    runs = _scanner(plain, tmp_path / "without" / "out")
    monkeypatch.setattr(checkov_scanner.os, "sep", "\\")

    with pytest.raises(ScannerError, match=re.escape(repr(link))):
        refused._execute_scan(linked, "source", [])
    argv, _, _ = runs._execute_scan(plain, "source", [])

    assert _argv_skip_values(argv) == []


@posix_only
@needs_symlinks
@pytest.mark.parametrize(
    ("names", "refused"),
    [
        pytest.param(["l.tf"], False, id="the-values-compile"),
        pytest.param(["a.tf", "b(c.tf"], True, id="the-values-do-not-compile"),
    ],
)
def test_a_scan_walks_the_tree_for_links_once(tmp_path, monkeypatch, names, refused):
    """One walk serves the module rule, the links left out and the refusal that
    names a link, whether the scan runs or stops on its link values."""
    source = _tree(tmp_path, files={"m.tf": ""}, links=names)
    scanner = _scanner(source, tmp_path / "out")
    walks = []
    walk = checkov_scanner.file_links_leaving_tree

    def counted(*args, **kwargs):
        walks.append(None)
        return walk(*args, **kwargs)

    monkeypatch.setattr(checkov_scanner, "file_links_leaving_tree", counted)

    if refused:
        with pytest.raises(ScannerError, match="link leaves the scanned tree"):
            scanner._execute_scan(source, "source", [])
    else:
        scanner._execute_scan(source, "source", [])

    assert len(walks) == 1


# ---------------------------------------------------------------------------
# _module_load_link
# ---------------------------------------------------------------------------


@posix_only
@needs_symlinks
def test_the_first_link_in_path_order_is_named_with_the_file_that_names_it(tmp_path):
    source = _tree(
        tmp_path,
        files={
            "a.tf": _module("./one"),
            "b.tf": _module("./two"),
            "one/main.tf": "",
            "two/main.tf": "",
        },
        links=["two/terraform.tfvars", "one/terraform.tfvars"],
    )

    assert _module_read(source) == ("one/terraform.tfvars", "a.tf")


@posix_only
@needs_symlinks
@pytest.mark.parametrize(
    ("main", "link"),
    [
        pytest.param("main.tf", "terraform.tfvars", id="the-scanned-directory-itself"),
        pytest.param("sub/main.tf", "sub/terraform.tfvars", id="a-subdirectory"),
    ],
)
def test_a_dot_source_names_the_directory_of_its_own_file(tmp_path, main, link):
    source = _tree(tmp_path, files={main: _module(".")}, links=[link])

    assert _module_read(source) == (link, main)


@posix_only
@needs_symlinks
@pytest.mark.parametrize(
    "value",
    [
        pytest.param("terraform-aws-modules/vpc/aws", id="registry"),
        pytest.param("git::https://example.com/x.git", id="git"),
        pytest.param("mods/pkg", id="a-bare-relative-path"),
        pytest.param("${path.module}/mods/pkg", id="interpolation-is-not-resolved"),
        pytest.param("./nowhere", id="a-directory-that-does-not-exist"),
    ],
)
def test_a_source_that_names_no_local_directory_finds_nothing(tmp_path, value):
    source = _tree(
        tmp_path,
        files={"main.tf": _module(value), "mods/pkg/main.tf": ""},
        links=["mods/pkg/terraform.tfvars"],
    )

    assert _module_read(source) is None


@posix_only
@needs_symlinks
def test_a_source_attribute_in_any_block_counts(tmp_path):
    """The rule does not tell module blocks from others, so it errs toward refusing:
    a ``source`` in a resource block names the directory too."""
    source = _tree(
        tmp_path,
        files={
            "main.tf": 'resource "x" "y" {\n  source = "./mods/pkg"\n}\n',
            "mods/pkg/main.tf": "",
        },
        links=["mods/pkg/terraform.tfvars"],
    )

    assert _module_read(source) == ("mods/pkg/terraform.tfvars", "main.tf")


@posix_only
@needs_symlinks
@pytest.mark.parametrize(
    ("text", "found"),
    [
        pytest.param('module "m" {\n  source = "./mods/pkg"\n}\n', True, id="spaces"),
        pytest.param('module "m" {\n  source="./mods/pkg"\n}\n', True, id="no-spaces"),
        pytest.param('module "m" {\n  source\t=\t"./mods/pkg"\n}\n', True, id="tabs"),
        pytest.param(
            'module "m" {\n  resource_source = "./mods/pkg"\n}\n',
            False,
            id="another-attribute-ending-in-source",
        ),
        pytest.param(
            'module "m" {\n  source = "./mods/pkg\n}\n', False, id="unterminated"
        ),
        pytest.param(
            "module \"m\" {\n  source = './mods/pkg'\n}\n", False, id="single-quotes"
        ),
    ],
)
def test_the_source_attribute_is_read_as_a_double_quoted_value_on_one_line(
    tmp_path, text, found
):
    source = _tree(
        tmp_path,
        files={"main.tf": text, "mods/pkg/main.tf": ""},
        links=["mods/pkg/terraform.tfvars"],
    )

    expected = ("mods/pkg/terraform.tfvars", "main.tf") if found else None
    assert _module_read(source) == expected


@posix_only
@needs_symlinks
def test_a_file_with_bytes_that_are_not_utf8_is_still_read(tmp_path):
    source = _tree(
        tmp_path,
        files={"mods/pkg/main.tf": ""},
        links=["mods/pkg/terraform.tfvars"],
    )
    (source / "main.tf").write_bytes(
        b'# \xff\xfe\nmodule "m" {\n  source = "./mods/pkg"\n}\n'
    )

    assert _module_read(source) == ("mods/pkg/terraform.tfvars", "main.tf")


@posix_only
@needs_symlinks
def test_a_file_that_cannot_be_read_is_skipped(tmp_path, monkeypatch):
    source = _tree(
        tmp_path,
        files={"main.tf": _module("./mods/pkg"), "mods/pkg/main.tf": ""},
        links=["mods/pkg/terraform.tfvars"],
    )
    assert _module_read(source) is not None

    def unreadable(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "read_text", unreadable)

    assert _module_read(source) is None


def test_a_file_the_walk_listed_that_is_gone_is_skipped(tmp_path):
    source = tmp_path / "src"
    source.mkdir()

    assert _module_load_link(source, [], ["gone.tf", "sub/gone.hcl"]) is None


@pytest.mark.parametrize(
    ("value", "local"),
    [
        (".", True),
        ("./pkg", True),
        ("../pkg", True),
        ("/abs/pkg", True),
        ("pkg", False),
        ("terraform-aws-modules/vpc/aws", False),
        ("git::https://example.com/x.git", False),
        ("${path.module}/pkg", False),
        ("", False),
    ],
)
def test_the_local_module_sources(value, local):
    assert _is_local_module_source(value) is local


@pytest.mark.parametrize(
    ("name", "read"),
    [
        ("terraform.tfvars", True),
        ("terraform.tfvars.json", True),
        ("x.auto.tfvars", True),
        ("x.auto.tfvars.json", True),
        ("main.tf", True),
        ("x.hcl", True),
        ("readme.md", False),
        ("terraform.tfvars.bak", False),
        ("auto.tfvars", False),
        ("x.tfvars", False),
        ("main.tfx", False),
    ],
)
def test_the_names_the_module_load_reads(name, read):
    assert _module_load_reads(name) is read
