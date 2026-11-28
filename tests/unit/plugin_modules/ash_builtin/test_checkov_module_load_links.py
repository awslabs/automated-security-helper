"""A local module source makes checkov load a directory with no ``--skip-path`` value.

checkov's terraform parser loads the directory a local module source names (a value
that starts with ``./``, ``../`` or ``/``, or on Windows with a backslash form or a
drive letter; it never loads ``.`` or ``./``) with ``_internal_dir_load`` and no
``excluded_paths`` (``checkov/terraform/tf_parser.py`` lines 253, 263-269 and
546-549, checkov 3.4.7). That load reads, following links to files,
``terraform.tfvars.json``, ``terraform.tfvars``, ``*.auto.tfvars``,
``*.auto.tfvars.json`` and the ``*.tf`` and ``*.hcl`` files in the directory (lines
569-604), and a source path that goes through a link to a directory is followed. So
on every platform a link to a file outside the scanned directory, with one of those
names and directly in such a directory, is read whatever ``--skip-path`` says: the
value ASH gives the link, and the rule that leaves a link under a directory checkov
skips out of the list, change nothing there.

``_module_load_finding`` walks the directories the module sources in the tree name, as
every path checkov might take each source to name, and ``_execute_scan`` refuses the
scan when it finds a link or a source that reaches outside the tree, a file larger than
ASH reads, or a walk that passed one of its bounds. The rows here build real trees with
real links. The rule reads ``source = "<value>"`` in every ``.tf`` and ``.hcl`` file
that is a regular file and not a link that leaves the tree, in any block, so it errs
toward refusing. A module source that names a directory outside the scanned directory
as text, with no link in the way, is out of its scope.
"""

from __future__ import annotations

import builtins
import io
import os
import re
import sys
import unicodedata
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
    _folded,
    _is_local_module_source,
    _known_directory_skip_values,
    _module_load_finding,
    _module_load_reads,
    _module_source_readings,
    _skip_path_root,
    _spelled_below,
    _within_ignoring_case,
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


def _module_finding(source: Path):
    """``_module_load_finding`` over the walk the scanner makes."""
    all_files: list[str] = []
    links = file_links_leaving_tree(source, all_files=all_files)
    return _module_load_finding(source, links, all_files)


def _module_read(source: Path):
    """``(subject, where)`` of the finding over the walk the scanner makes, or None."""
    finding = _module_finding(source)
    return None if finding is None else (finding.subject, finding.where)


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
    does not read a ``.tf`` file that is a link leaving the tree, so the rule finds
    nothing from it, and the scan runs, each link left out by its own value."""
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
    scanned directory as text (``../outside/dir/pkg``) names a directory outside it
    both as text and as the operating system resolves it, and no component of the
    path below the scanned directory is a link, so this rule does not judge it and
    nothing is refused here. The same ending reached through a link is refused
    (``test_a_path_that_ends_outside_the_tree_after_passing_a_link_refuses``)."""
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
# Every path checkov might take: through a link, joined as spelled, as resolved
# ---------------------------------------------------------------------------


@posix_only
@needs_symlinks
def test_a_dot_dot_after_a_link_to_a_directory_is_joined_as_checkov_joins_it(
    tmp_path,
):
    """checkov loads ``mods/pkg`` through the link ``mods`` and joins the ``../../x``
    in the file it finds there to that spelling, so it loads ``x``. Joined to the
    file's real directory, ``real/deep/pkg``, the same source names ``real/x``, which
    is not a directory: only the spelling checkov uses finds the link in ``x``."""
    link = "x/terraform.tfvars"
    source = _tree(
        tmp_path,
        files={
            "main.tf": _module("./mods/pkg"),
            "real/deep/pkg/main.tf": _module("../../x"),
        },
        links=[link],
        directory_links={"mods": tmp_path / "src" / "real" / "deep"},
    )
    assert not (tmp_path / "src" / "real" / "x").exists()

    assert _module_read(source) == (link, "real/deep/pkg/main.tf")
    with pytest.raises(ScannerError, match=re.escape(repr(link))) as refused:
        _scan(source, tmp_path)

    assert "'real/deep/pkg/main.tf'" in str(refused.value)


@posix_only
@needs_symlinks
def test_a_chain_through_a_link_to_a_directory_keeps_the_spelling_of_each_step(
    tmp_path,
):
    """Every step goes through the link ``mods``, so no file of the walk holds the
    second step's source as checkov spells it: ``mods/pkg/sub`` is
    ``real/deep/pkg/sub`` to the operating system, and the ``../../../x`` in its
    ``main.tf`` is joined to the spelling, which reads as ``x``. Joined to
    ``real/deep/pkg/sub`` it would name ``real/x``, which is not a directory."""
    link = "x/terraform.tfvars"
    source = _tree(
        tmp_path,
        files={
            "main.tf": _module("./mods/pkg"),
            "real/deep/pkg/main.tf": _module("./sub"),
            "real/deep/pkg/sub/main.tf": _module("../../../x"),
        },
        links=[link],
        directory_links={"mods": tmp_path / "src" / "real" / "deep"},
    )
    assert not (tmp_path / "src" / "real" / "x").exists()

    assert _module_read(source) == (link, "real/deep/pkg/sub/main.tf")


@posix_only
@needs_symlinks
def test_an_absolute_source_goes_through_a_link_before_its_dot_dot(tmp_path):
    """checkov's local-path loader uses an absolute source that starts with the
    directory it is loading as it is spelled, so the operating system resolves
    ``mods`` (a link to ``real/deep``) before the ``..`` after it: the source names
    ``real/x``, not ``x``, and the link in ``real/x`` is read."""
    root = tmp_path / "src"
    link = "real/x/terraform.tfvars"
    source = _tree(
        tmp_path,
        files={"main.tf": _module(f"{root}/mods/../x"), "real/deep/main.tf": ""},
        links=[link],
        directory_links={"mods": root / "real" / "deep"},
    )
    assert not (root / "x").exists()

    assert _module_read(source) == (link, "main.tf")
    with pytest.raises(ScannerError, match=re.escape(repr(link))):
        _scan(source, tmp_path)


@posix_only
@needs_symlinks
def test_an_absolute_source_that_goes_through_a_link_out_of_the_tree_refuses(
    tmp_path,
):
    """``out`` is a link to a directory outside the tree. ``<root>/out/../y`` reads as
    ``<root>/y`` as text, which does not exist, and as ``<outside>/y`` to the
    operating system, which is what checkov loads. That directory is outside the
    tree, so the scan is refused, naming the source."""
    root = tmp_path / "src"
    value = f"{root}/out/../y"
    source = _tree(
        tmp_path,
        files={"main.tf": _module(value)},
        directory_links={"out": tmp_path / "outside" / "dir"},
    )
    assert _module_read(source) is None

    (tmp_path / "outside" / "y").mkdir()

    assert _module_read(source) == (value, "main.tf")
    with pytest.raises(ScannerError, match=re.escape(repr(value))) as refused:
        _scan(source, tmp_path)

    assert "reaches a directory that leaves the scanned tree" in str(refused.value)


@posix_only
@needs_symlinks
def test_a_source_names_a_directory_through_an_in_tree_link_of_another_spelling(
    tmp_path,
):
    """On a case-insensitive volume ``Mods`` and ``mods`` are one directory, and a
    comparison of names misses it. A case-sensitive volume can hold ``Mods`` as a
    link to ``mods``, which builds the same shape: the source names ``mods/pkg``
    through it, and the link that leaves the tree there is found by the directory
    the source names, whatever its spelling."""
    probe = tmp_path / "CaseProbe"
    probe.touch()
    if (tmp_path / "caseprobe").exists():
        pytest.skip("a case-insensitive volume cannot hold both spellings")
    link = "mods/pkg/terraform.tfvars"
    source = _tree(
        tmp_path,
        files={"main.tf": _module("./Mods/pkg"), "mods/pkg/main.tf": ""},
        links=[link],
        directory_links={"Mods": tmp_path / "src" / "mods"},
    )

    assert _module_read(source) == (link, "main.tf")
    with pytest.raises(ScannerError, match=re.escape(repr(link))):
        _scan(source, tmp_path)


@posix_only
@needs_symlinks
def test_a_scanned_directory_reached_through_a_link_is_judged_by_what_it_is(tmp_path):
    """The scan is given a link to the directory (a second spelling of it): the
    link in ``mods/pkg`` is still found, named below the scanned directory."""
    link = "mods/pkg/terraform.tfvars"
    source = _tree(
        tmp_path,
        files={"main.tf": _module("./mods/pkg"), "mods/pkg/main.tf": ""},
        links=[link],
    )
    spelled = tmp_path / "spelled"
    spelled.symlink_to(source, target_is_directory=True)

    assert _module_read(spelled) == (link, "main.tf")


@posix_only
@needs_symlinks
def test_a_source_that_names_the_scanned_directory_itself_is_judged_like_any_other(
    tmp_path,
):
    """``sub/main.tf`` names the scanned directory (``src``) by climbing out of it
    and coming back in. A link in it that leaves the tree is read: the scanned
    directory counts as inside, by identity, for the directory a source names."""
    link = "terraform.tfvars"
    source = _tree(tmp_path, files={"sub/main.tf": _module("../../src")}, links=[link])

    assert _module_read(source) == (link, "sub/main.tf")


@posix_only
@needs_symlinks
def test_a_path_that_climbs_out_of_the_tree_and_back_in_through_a_link_is_judged(
    tmp_path,
):
    """``out`` is a link to ``real/a/b``, in the tree, so ``<root>/out/../../y`` is
    ``real/y`` to the operating system, which is what checkov loads. As text it is
    ``<base>/y``, outside the tree. Where the operating system takes the path decides:
    a link that leaves the tree in ``real/y`` is read, and the scan is refused,
    naming it. The same tree without that link runs."""

    def build(base: Path, links: list[str]) -> Path:
        root = base / "src"
        return _tree(
            base,
            files={
                "main.tf": _module(f"{root}/out/../../y"),
                "real/a/b/main.tf": "",
                "real/y/main.tf": "",
            },
            links=links,
            directory_links={"out": root / "real" / "a" / "b"},
        )

    link = "real/y/terraform.tfvars"
    clean = build(tmp_path / "clean", [])
    linked = build(tmp_path / "linked", [link])
    assert not (tmp_path / "linked" / "y").exists()

    assert _module_read(clean) is None
    _scan(clean, tmp_path / "clean")
    assert _module_read(linked) == (link, "main.tf")
    with pytest.raises(ScannerError, match=re.escape(repr(link))):
        _scan(linked, tmp_path / "linked")


@posix_only
@needs_symlinks
def test_a_path_that_ends_outside_the_tree_after_passing_a_link_refuses(tmp_path):
    """``out`` is a link to a directory outside the tree, and ``<root>/out/../../y``
    ends in ``<base>/y``: outside the tree as text and as the operating system
    resolves it. The reading passes the link ``out`` below the scanned directory, so
    the source is refused, naming it. With ``out`` a plain directory the same source
    ends in the same place and passes no link: the text-only case, out of the rule's
    scope, and the scan runs."""

    def build(base: Path, through_a_link: bool) -> tuple[Path, str]:
        root = base / "src"
        value = f"{root}/out/../../y"
        if through_a_link:
            source = _tree(
                base,
                files={"main.tf": _module(value)},
                directory_links={"out": base / "outside" / "dir"},
            )
        else:
            source = _tree(base, files={"main.tf": _module(value), "out/main.tf": ""})
        (base / "y").mkdir()
        return source, value

    plain, _ = build(tmp_path / "plain", False)
    linked, value = build(tmp_path / "linked", True)

    assert _module_read(plain) is None
    _scan(plain, tmp_path / "plain")
    assert _module_read(linked) == (value, "main.tf")
    with pytest.raises(ScannerError, match=re.escape(repr(value))) as refused:
        _scan(linked, tmp_path / "linked")

    assert "reaches a directory that leaves the scanned tree" in str(refused.value)


@pytest.mark.parametrize(
    ("path", "root", "below"),
    [
        pytest.param("/w/t/a/b", "/w/t", ("a", "b"), id="below-it"),
        pytest.param("/w/t", "/w/t", (), id="the-root-itself"),
        pytest.param(
            "/w/t/out/../../y", "/w/t", ("out", "..", "..", "y"), id="dot-dot-is-kept"
        ),
        pytest.param(
            "/w/t/./a//b/", "/w/t", ("a", "b"), id="dot-and-repeated-slash-are-not"
        ),
        pytest.param("/w", "/w/t", None, id="its-parent"),
        pytest.param("/w/u/a", "/w/t", None, id="another-directory"),
        pytest.param("/w/tx/a", "/w/t", None, id="a-sibling-that-starts-with-its-name"),
    ],
)
@posix_only
def test_the_spelling_of_a_path_below_a_root_keeps_its_dot_dot(path, root, below):
    """``_spelled_below`` reads the components a path is spelled with, after the
    root's: ``..`` stays, since where the operating system takes it depends on the
    link before it, and a ``.`` or a repeated separator does not."""
    assert _spelled_below(path, root) == below


@pytest.mark.parametrize(
    ("path", "root", "inside"),
    [
        pytest.param("/w/t", "/w/t", True, id="the-root-itself"),
        pytest.param("/w/t/x/y", "/w/t", True, id="below-it"),
        pytest.param("/W/T/x", "/w/t", True, id="the-root-in-another-case"),
        pytest.param("/w/t/X", "/W/t", True, id="a-name-below-it-in-another-case"),
        pytest.param("/w/tx", "/w/t", False, id="a-sibling-that-starts-with-its-name"),
        pytest.param("/w", "/w/t", False, id="its-parent"),
        pytest.param("/other/t", "/w/t", False, id="another-directory"),
    ],
)
@posix_only
def test_a_path_that_differs_from_the_root_only_in_case_counts_as_inside_it(
    path, root, inside
):
    """The text of a reading is compared with the scanned directory with case folded,
    since ``posixpath.normcase`` folds nothing and a case-insensitive volume names
    one directory with either spelling."""
    assert _within_ignoring_case(path, root) is inside


#: One name in its two Unicode forms: an accented ``e`` as the one character of form C,
#: and as an ``e`` with a combining accent in form D. macOS file systems take the two
#: for one name; others keep them apart. Built from code points, so that no tool
#: rewrites the pair.
_CAFE_COMPOSED = "caf" + chr(0xE9)
_CAFE_DECOMPOSED = unicodedata.normalize("NFD", _CAFE_COMPOSED)


def test_the_two_unicode_forms_of_a_name_are_two_strings():
    """The control for the rows below: the pair differs as strings (form D has one
    character more) and is one name once composed, so a fold that ignored the form
    would fail them."""
    assert _CAFE_COMPOSED != _CAFE_DECOMPOSED
    assert len(_CAFE_DECOMPOSED) == len(_CAFE_COMPOSED) + 1
    assert unicodedata.normalize("NFC", _CAFE_DECOMPOSED) == _CAFE_COMPOSED


@pytest.mark.parametrize(
    ("one", "other"),
    [
        pytest.param(_CAFE_COMPOSED, _CAFE_DECOMPOSED, id="composed-and-decomposed"),
        pytest.param(
            _CAFE_COMPOSED.upper(), _CAFE_DECOMPOSED, id="upper-case-and-decomposed"
        ),
        pytest.param(
            unicodedata.normalize("NFD", _CAFE_COMPOSED.upper()),
            _CAFE_COMPOSED,
            id="upper-case-decomposed-and-composed",
        ),
    ],
)
def test_two_spellings_that_differ_in_unicode_form_or_case_fold_alike(one, other):
    """``_folded`` turns the forms of a character into one (form C) before it folds
    the case, so a name compares equal whichever form, and whichever case, a path
    spells it in."""
    assert one != other
    assert _folded(f"/w/t/{one}/x") == _folded(f"/w/t/{other}/x")


@pytest.mark.parametrize(
    ("path", "root", "inside"),
    [
        pytest.param(
            f"/w/t/{_CAFE_DECOMPOSED}/x",
            f"/w/t/{_CAFE_COMPOSED}",
            True,
            id="below-a-root-spelled-in-the-other-form",
        ),
        pytest.param(
            f"/w/t/{_CAFE_COMPOSED}/x",
            f"/w/t/{_CAFE_DECOMPOSED}",
            True,
            id="below-a-decomposed-root-in-the-composed-form",
        ),
        pytest.param(
            f"/w/t/{_CAFE_COMPOSED}x",
            f"/w/t/{_CAFE_DECOMPOSED}",
            False,
            id="a-sibling-that-starts-with-its-name-in-the-other-form",
        ),
    ],
)
@posix_only
def test_a_path_in_another_unicode_form_than_the_root_counts_as_inside_it(
    path, root, inside
):
    """The text of a reading is compared with the scanned directory with the Unicode
    form folded as well as the case, since a volume that takes the two forms for one
    name (macOS) names one directory with either."""
    assert _within_ignoring_case(path, root) is inside


@posix_only
def test_a_reading_in_another_unicode_form_than_the_scanned_directory_is_judged_by_text(
    tmp_path,
):
    """The scanned directory is named in form C, and the source names ``pkg`` below
    the same name in form D: another directory on a file system that keeps the forms
    apart, and the same one on macOS. As text it is inside the scanned directory and
    by identity it is outside, so the source is refused, naming it. (A volume that
    takes the forms for one name cannot hold the two, and the row is skipped.)"""
    scanned = tmp_path / _CAFE_COMPOSED
    scanned.mkdir()
    other = tmp_path / _CAFE_DECOMPOSED
    if other.exists():
        pytest.skip("the volume takes the two Unicode forms for one name")
    (other / "pkg").mkdir(parents=True)
    value = f"{other}/pkg"
    (scanned / "main.tf").write_text(_module(value), encoding="utf-8")

    assert _module_read(scanned) == (value, "main.tf")


# ---------------------------------------------------------------------------
# The bounds: a file ASH will not read, and a walk that is cut short
# ---------------------------------------------------------------------------


@posix_only
def test_a_tf_file_larger_than_ash_reads_refuses_the_scan(tmp_path):
    """One byte past ``_MODULE_SOURCE_READ_LIMIT``: ASH does not read the file whole
    in its own process, and cannot tell what a source in it would have checkov
    load, so the scan is refused, naming the file. (A sparse file: it holds no
    data, and the read stops at the limit.)"""
    source = _tree(tmp_path, files={"main.tf": ""})
    os.truncate(source / "main.tf", checkov_scanner._MODULE_SOURCE_READ_LIMIT + 1)

    assert _module_finding(source) == ("large", "main.tf", "")
    match = "larger than ASH reads to look for module sources"
    with pytest.raises(ScannerError, match=match) as refused:
        _scan(source, tmp_path)

    assert "'main.tf'" in str(refused.value)


@posix_only
def test_a_tf_file_of_exactly_the_limit_is_read(tmp_path):
    """The boundary of the row above: a file at the limit is read, and holds no
    module source."""
    source = _tree(tmp_path, files={"main.tf": ""})
    os.truncate(source / "main.tf", checkov_scanner._MODULE_SOURCE_READ_LIMIT)

    assert _module_finding(source) is None
    _scan(source, tmp_path)


@posix_only
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_a_fifo_named_like_a_terraform_file_is_not_opened(tmp_path, monkeypatch):
    """A FIFO opened for reading blocks until something writes to it. ``main.tf`` here
    is one, so a reader that opens it hangs: the walk asks ``os.stat`` first and
    leaves a file that is not a regular file alone. Any ``open`` of it fails this row
    instead of waiting."""
    source = _tree(tmp_path)
    fifo = source / "main.tf"
    os.mkfifo(fifo)
    real_open = builtins.open

    def guarded(file, *args, **kwargs):
        if isinstance(file, (str, os.PathLike)) and Path(file) == fifo:
            raise AssertionError(f"opened {fifo}")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded)
    monkeypatch.setattr(io, "open", guarded)

    assert _module_finding(source) is None


@posix_only
@needs_symlinks
def test_a_chain_of_module_directories_is_followed_to_the_link(tmp_path):
    """``main.tf`` names ``a``, whose ``main.tf`` names ``b``, which holds a link the
    module load reads: the scan is refused, naming the file that names ``b``."""
    link = "a/b/terraform.tfvars"
    source = _tree(
        tmp_path,
        files={
            "main.tf": _module("./a"),
            "a/main.tf": _module("./b"),
            "a/b/main.tf": "",
        },
        links=[link],
    )

    assert _module_read(source) == (link, "a/main.tf")
    with pytest.raises(ScannerError, match=re.escape(repr(link))):
        _scan(source, tmp_path)


@posix_only
@pytest.mark.parametrize(
    ("limit", "cut"),
    [
        pytest.param(2, False, id="at-the-bound"),
        pytest.param(1, True, id="past-the-bound"),
    ],
)
def test_a_walk_past_the_directory_bound_is_cut_short(
    tmp_path, monkeypatch, limit, cut
):
    """Two directories named by sources. With the bound at two the walk looks at
    both and finds nothing; with it at one the walk is cut short and the scan is
    refused, since ASH cannot tell what is left."""
    source = _tree(
        tmp_path,
        files={
            "main.tf": _module("./a") + _module("./b"),
            "a/main.tf": "",
            "b/main.tf": "",
        },
    )
    monkeypatch.setattr(checkov_scanner, "_MODULE_WALK_DIRECTORY_LIMIT", limit)

    if not cut:
        assert _module_finding(source) is None
        return
    assert _module_finding(source) == ("cut", "1 directories", "")
    with pytest.raises(ScannerError, match="cut short at 1 directories"):
        _scan(source, tmp_path)


@posix_only
@pytest.mark.parametrize(
    ("short", "cut"),
    [
        pytest.param(0, False, id="at-the-bound"),
        pytest.param(1, True, id="past-the-bound"),
    ],
)
def test_a_walk_past_the_byte_bound_is_cut_short(tmp_path, monkeypatch, short, cut):
    """The bytes read in all are bounded: the one file holds ``len(text)`` bytes, so a
    bound at that figure lets the walk finish, and one byte less cuts it short."""
    text = _module("./a")
    source = _tree(tmp_path, files={"main.tf": text, "a/main.tf": ""})
    limit = len(text.encode("utf-8")) - short
    monkeypatch.setattr(checkov_scanner, "_MODULE_WALK_BYTE_LIMIT", limit)

    if not cut:
        assert _module_finding(source) is None
        return
    assert _module_finding(source) == ("cut", f"{limit:,} bytes", "")
    with pytest.raises(ScannerError, match=f"cut short at {limit:,} bytes"):
        _scan(source, tmp_path)


@posix_only
@pytest.mark.parametrize(
    ("short", "cut"),
    [
        pytest.param(0, False, id="at-the-bound"),
        pytest.param(1, True, id="past-the-bound"),
    ],
)
def test_a_walk_past_the_reading_bound_is_cut_short(tmp_path, monkeypatch, short, cut):
    """Two sources name two directories, each by its own readings (the path as text
    and as spelled). With the bound at the number of distinct readings the walk judges
    them all and finds nothing; one fewer cuts it short and the scan is refused, since
    ASH cannot tell what is left. The number comes from the function the walk uses
    for them, so the row holds where the temporary directory is itself behind a link
    and each source has more readings."""
    source = _tree(
        tmp_path,
        files={
            "main.tf": _module("./a") + _module("./b"),
            "a/main.tf": "",
            "b/main.tf": "",
        },
    )
    readings = {
        reading
        for value in ("./a", "./b")
        for reading in _module_source_readings(
            str(source), os.path.realpath(source), value
        )
    }
    limit = len(readings) - short
    monkeypatch.setattr(checkov_scanner, "_MODULE_WALK_READING_LIMIT", limit)

    if not cut:
        assert _module_finding(source) is None
        return
    assert _module_finding(source) == ("cut", f"{limit:,} readings", "")
    with pytest.raises(ScannerError, match=f"cut short at {limit:,} readings"):
        _scan(source, tmp_path)


@posix_only
def test_a_reading_that_names_nothing_counts_toward_the_reading_bound(
    tmp_path, monkeypatch
):
    """The bound is on the readings judged, not on the directories found: a tree of
    many sources that name nothing costs ASH time in proportion to their number, so
    each counts. With the bound at one, the second reading of a source that names no
    directory cuts the walk short."""
    source = _tree(tmp_path, files={"main.tf": _module("./n1") + _module("./n2")})
    monkeypatch.setattr(checkov_scanner, "_MODULE_WALK_READING_LIMIT", 1)

    assert _module_finding(source) == ("cut", "1 readings", "")
    with pytest.raises(ScannerError, match="cut short at 1 readings"):
        _scan(source, tmp_path)


@posix_only
def test_a_reading_that_many_files_spell_alike_counts_once(tmp_path, monkeypatch):
    """Three files in one directory name ``./a``. Its readings are judged once each,
    however many files spell them, so a bound at their number is enough; judged once
    per file they would pass it."""
    source = _tree(
        tmp_path,
        files={
            "x.tf": _module("./a"),
            "y.tf": _module("./a"),
            "z.tf": _module("./a"),
            "a/main.tf": "",
        },
    )
    readings = _module_source_readings(str(source), os.path.realpath(source), "./a")
    monkeypatch.setattr(checkov_scanner, "_MODULE_WALK_READING_LIMIT", len(readings))

    assert _module_finding(source) is None


# ---------------------------------------------------------------------------
# _module_load_finding
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
@pytest.mark.parametrize("value", [".", "./"])
@pytest.mark.parametrize(
    ("main", "link"),
    [
        pytest.param("main.tf", "terraform.tfvars", id="the-scanned-directory-itself"),
        pytest.param("sub/main.tf", "sub/terraform.tfvars", id="a-subdirectory"),
    ],
)
def test_a_dot_source_is_not_loaded_by_checkov_so_it_is_not_refused(
    tmp_path, main, link, value
):
    """checkov's ``is_valid_source`` drops ``.`` and ``./`` before it loads anything
    (``tf_parser.py`` lines 643-645), so the link beside the file is not read through
    them and keeps its own ``--skip-path`` value."""
    source = _tree(tmp_path, files={main: _module(value)}, links=[link])

    assert _module_read(source) is None
    argv, _, _ = _scan(source, tmp_path)
    assert _own_value(source, link) in _argv_skip_values(argv)


@posix_only
@needs_symlinks
@pytest.mark.parametrize("value", ["./.", ".//"])
@pytest.mark.parametrize(
    ("main", "link"),
    [
        pytest.param("main.tf", "terraform.tfvars", id="the-scanned-directory-itself"),
        pytest.param("sub/main.tf", "sub/terraform.tfvars", id="a-subdirectory"),
    ],
)
def test_a_dot_source_spelled_another_way_names_the_directory_of_its_own_file(
    tmp_path, main, link, value
):
    """The two values checkov drops are exactly ``.`` and ``./``: ``./.`` and ``.//``
    pass ``is_valid_source`` and are joined to the directory of the file, which is then
    loaded with no ``--skip-path`` value, so the link beside the file is read."""
    source = _tree(tmp_path, files={main: _module(value)}, links=[link])

    assert _module_read(source) == (link, main)


@posix_only
@needs_symlinks
@pytest.mark.parametrize(
    ("value", "link"),
    [
        pytest.param(
            ".\\mods\\pkg", ".\\mods\\pkg/terraform.tfvars", id="a-backslash-form"
        ),
        pytest.param("c:/mods/pkg", "c:/mods/pkg/terraform.tfvars", id="a-drive-form"),
    ],
)
def test_a_backslash_or_drive_source_is_judged_where_it_names_a_directory(
    tmp_path, value, link
):
    """checkov takes these forms on Windows; ASH judges them on every platform, and
    where they name nothing that exists they drop out. POSIX can hold a directory
    whose name has a backslash, or a ``c:`` directory, so the form is judged here."""
    source = _tree(tmp_path, files={"main.tf": _module(value)}, links=[link])

    assert _module_read(source) == (link, "main.tf")


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
        pytest.param(".\\mods\\pkg", id="a-backslash-form-that-names-nothing"),
        pytest.param("C:\\mods\\pkg", id="a-drive-form-that-names-nothing"),
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
    real_open = builtins.open

    def unreadable(file, *args, **kwargs):
        if isinstance(file, (str, os.PathLike)) and Path(file).name == "main.tf":
            raise PermissionError(13, "Permission denied", os.fspath(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", unreadable)

    assert _module_read(source) is None


def test_a_file_the_walk_listed_that_is_gone_is_skipped(tmp_path):
    source = tmp_path / "src"
    source.mkdir()

    assert _module_load_finding(source, [], ["gone.tf", "sub/gone.hcl"]) is None


@pytest.mark.parametrize(
    ("value", "local"),
    [
        pytest.param("./pkg", True, id="dot-slash"),
        pytest.param("../pkg", True, id="dot-dot-slash"),
        pytest.param("/abs/pkg", True, id="absolute"),
        pytest.param(".\\pkg", True, id="dot-backslash"),
        pytest.param("..\\pkg", True, id="dot-dot-backslash"),
        pytest.param("\\pkg", True, id="backslash"),
        pytest.param("C:\\pkg", True, id="drive-and-backslash"),
        pytest.param("c:/pkg", True, id="drive-in-lower-case-and-slash"),
        pytest.param(".", False, id="the-current-directory"),
        pytest.param("./", False, id="the-current-directory-with-a-slash"),
        pytest.param("..", False, id="the-parent-without-a-slash"),
        pytest.param("pkg", False, id="a-bare-name"),
        pytest.param("hashicorp/consul/aws", False, id="a-registry-address"),
        pytest.param("terraform-aws-modules/vpc/aws", False, id="a-registry-path"),
        pytest.param("git::https://example.com/x.git", False, id="a-git-address"),
        pytest.param("${path.module}/pkg", False, id="interpolation"),
        pytest.param("", False, id="empty"),
    ],
)
def test_the_local_module_sources(value, local):
    assert _is_local_module_source(value) is local


@posix_only
def test_the_readings_of_a_source_are_its_text_and_as_spelled_joins_from_both_directories():
    """For a file whose directory is spelled ``mods/pkg`` and is really
    ``real/deep/pkg``: the join as text and as spelled from each, in that order."""
    readings = _module_source_readings("/w/t/mods/pkg", "/w/t/real/deep/pkg", "../../x")

    assert readings == [
        "/w/t/x",
        "/w/t/mods/pkg/../../x",
        "/w/t/real/x",
        "/w/t/real/deep/pkg/../../x",
    ]


@posix_only
@pytest.mark.parametrize(
    ("value", "readings"),
    [
        pytest.param("./a", ["/w/t/a", "/w/t/./a"], id="a-relative-source-once"),
        pytest.param(
            "/w/t/mods/../x",
            ["/w/t/x", "/w/t/mods/../x"],
            id="an-absolute-source-does-not-depend-on-the-directory",
        ),
    ],
)
def test_the_readings_are_not_repeated_when_the_two_directories_are_one(
    value, readings
):
    assert _module_source_readings("/w/t", "/w/t", value) == readings


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
