# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The in-tree-link-out refusal judges the name as the operator spelled it.

The gate collapsed the given path lexically (``os.path.abspath``) before
asking whether it was named inside the scanned tree. A spelling that walks
through a repository-written link and back out with ``..`` collapses to a path
outside the tree, so the gate stepped aside and the run mounted whatever file
the repository's link steered the name to. The gate now walks the uncollapsed
spelling component by component (``_named_in_a_scanned_tree``): a link that
sits inside a scanned tree makes the name the tree's, a link outside every
tree is collapsed to where it points and the walk goes on -- the host's own
``/tmp`` or ``/home`` is often such a link, and stopping at one hid every tree
link behind it -- and plain ``..`` spellings that never touch a tree link stay
the operator's own. A tree link that lies only inside a collapsed chain does
not make the name the tree's: the run is not refused and the config is marked
repository-written instead.
"""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path

import pytest

from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container
from automated_security_helper.interactions.run_ash_container import (
    ContainerInputError,
)
from tests.utils.config_link_layouts import (
    NAMES_STEERED_BY_THE_SCANNED_CHECKOUT,
    config_through_links,
)
from tests.utils.helpers import mark_git_checkout

MARK_FLAG = "--config-from-scanned-repository"

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt", reason="the layouts are built from POSIX symlinks"
    ),
]


def test_a_name_through_a_tree_link_and_back_out_is_refused(tmp_path):
    secret = tmp_path / "secret.yaml"
    secret.write_text("project_name: theirs\n")
    nest = tmp_path / "deep" / "nest"
    nest.mkdir(parents=True)
    source = tmp_path / "src"
    source.mkdir()
    (source / "L").symlink_to(nest)
    spelled = f"{source}/L/../../secret.yaml"
    assert os.path.realpath(spelled) == str(secret)
    assert not Path(os.path.abspath(spelled)).is_relative_to(source)
    with pytest.raises(ContainerInputError, match="link"):
        run_ash_container._refuse_config_linked_out_of_the_tree(spelled, source)


def test_a_plain_dot_dot_spelling_with_no_tree_link_stays_the_operators(tmp_path):
    mine = tmp_path / "mine.yaml"
    mine.write_text("project_name: mine\n")
    source = tmp_path / "src"
    source.mkdir()
    run_ash_container._refuse_config_linked_out_of_the_tree(
        f"{source}/../mine.yaml", source
    )


def test_an_in_tree_link_that_stays_inside_is_still_followed(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    real = source / "cfg.yaml"
    real.write_text("project_name: ours\n")
    (source / "alias.yaml").symlink_to(real)
    run_ash_container._refuse_config_linked_out_of_the_tree(
        str(source / "alias.yaml"), source
    )


def test_an_ancestor_link_above_the_tree_does_not_hide_a_tree_link(tmp_path):
    """A link ABOVE the tree is the host's, not a verdict on the name.

    On many hosts the tree's own name goes through such a link (macOS
    ``/tmp`` -> ``/private/tmp``, a linked ``/home``). The first link the
    walk meets is then that ancestor, which sits outside every tree, and a
    walk that stopped there never saw the repository's own link inside the
    tree -- so a config named inside the tree that links out of it was
    mounted. pytest's ``tmp_path`` is resolved, so the ancestor link is
    built by hand and the source directory is passed through it."""
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: theirs\n")
    real_root = tmp_path / "real"
    (real_root / "src").mkdir(parents=True)
    (real_root / "src" / "cfg.yaml").symlink_to(outside)
    entry = tmp_path / "entry"
    entry.symlink_to(real_root)
    source_through_link = entry / "src"
    with pytest.raises(ContainerInputError, match="link"):
        run_ash_container._refuse_config_linked_out_of_the_tree(
            str(source_through_link / "cfg.yaml"), source_through_link
        )


def test_an_operator_link_into_the_tree_is_judged_where_it_lands(tmp_path):
    """A name through the operator's own link into the tree keeps the tree's
    judgment. The link itself sits outside every tree and is the operator's,
    but what it leads to is the tree, and the repository's link there steers
    the rest of the name -- so a config that then resolves out of the tree is
    refused, as the same name spelled without the operator's link is. A walk
    that returned at the operator's link mounted it instead."""
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: theirs\n")
    source = tmp_path / "src"
    source.mkdir()
    (source / "cfg.yaml").symlink_to(outside)
    ops = tmp_path / "ops"
    ops.symlink_to(source)
    with pytest.raises(ContainerInputError, match="link"):
        run_ash_container._refuse_config_linked_out_of_the_tree(
            str(ops / "cfg.yaml"), source
        )


def _marked_inner_args(source: Path, out: Path, config: Path) -> list:
    """The arguments the container is started with for *config*, as the host
    assembles them for a scan of *source*."""
    cmd = run_ash_container._assemble_run_command(
        oci_command_prefix=[],
        resolved_oci_runner="/usr/bin/docker",
        image_name="automated-security-helper:non-root",
        source_dir=source.resolve(),
        output_dir=out.resolve(),
        offline=False,
        debug=False,
        color=False,
        quiet=True,
        progress=False,
        verbose=False,
        simple=True,
        python_based_plugins_only=False,
        cleanup=False,
        inspect=False,
        fail_on_findings=None,
        phases=[ExecutionPhase.SCAN],
        scanners=[],
        exclude_scanners=[],
        output_formats=[],
        config=str(config),
        config_overrides=[],
        existing_results=None,
        ash_plugin_modules=[],
        strategy=ExecutionStrategy.PARALLEL,
        ctx=None,
    )
    return cmd[cmd.index("automated-security-helper:non-root") + 1 :]


def _assert_given_unrefused_and_marked(source: Path, out: Path, config: Path) -> None:
    assert run_ash_container.container_input_refusal(source, out, str(config)) is None
    inner = _marked_inner_args(source, out, config)
    assert MARK_FLAG in inner
    assert inner[inner.index("--config") + 1].startswith("/ash-config/")


def test_an_operator_link_to_a_tree_link_to_outside_is_marked(tmp_path):
    """The chain ``ops.yaml`` -> ``src/cfg.yaml`` -> a file outside the tree.

    ``ops.yaml`` sits outside the tree and is the name the operator gave. The
    repository's link ``src/cfg.yaml`` lies inside the collapsed chain, so it
    does not make the name the tree's and the run is not refused; a local scan
    counts a config as repository-written when a symlink its path follows sits
    inside the scanned checkout, so the config is marked and the scan inside
    judges it under those rules."""
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: theirs\n")
    source = tmp_path / "src"
    source.mkdir()
    (source / "cfg.yaml").symlink_to(outside)
    (tmp_path / "ops.yaml").symlink_to(Path("src") / "cfg.yaml")
    out = tmp_path / "out"
    out.mkdir()
    assert os.path.realpath(tmp_path / "ops.yaml") == str(outside)
    run_ash_container._refuse_config_linked_out_of_the_tree(
        str(tmp_path / "ops.yaml"), source
    )
    _assert_given_unrefused_and_marked(source, out, tmp_path / "ops.yaml")


def test_an_operator_link_to_a_tree_link_directory_is_marked(tmp_path):
    """The chain ``ops`` -> ``src/L`` with ``L`` a tree link to a directory
    outside the tree, given ``ops/cfg.yaml``.

    ``ops`` is the operator's own link and is collapsed to the real directory
    the walk continues from, so the name is not the tree's and is not refused.
    The repository's link ``L`` steered the name there, so the config is
    marked repository-written."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "cfg.yaml").write_text("project_name: theirs\n")
    source = tmp_path / "src"
    source.mkdir()
    (source / "L").symlink_to(elsewhere)
    (tmp_path / "ops").symlink_to(Path("src") / "L")
    out = tmp_path / "out"
    out.mkdir()
    assert os.path.realpath(tmp_path / "ops" / "cfg.yaml") == str(
        elsewhere / "cfg.yaml"
    )
    run_ash_container._refuse_config_linked_out_of_the_tree(
        str(tmp_path / "ops" / "cfg.yaml"), source
    )
    _assert_given_unrefused_and_marked(source, out, tmp_path / "ops" / "cfg.yaml")


def test_a_final_file_link_through_a_tree_directory_link_is_marked(tmp_path):
    """``ops`` -> ``src/L`` -> an outside directory whose ``cfg.yaml`` is
    itself a file link to a second outside file.

    The collapse of the operator's ``ops`` follows the tree's ``L`` into the
    outside directory, and the final component's own file link collapses with
    the rest of its chain: the name is not the tree's, so nothing is refused,
    and the tree's ``L`` steered the name, so the mark fires on the file the
    whole chain lands at."""
    secret = tmp_path / "secret.yaml"
    secret.write_text("project_name: theirs\n")
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "cfg.yaml").symlink_to(secret)
    source = tmp_path / "src"
    source.mkdir()
    (source / "L").symlink_to(outside_dir, target_is_directory=True)
    ops = tmp_path / "ops"
    ops.symlink_to(source / "L", target_is_directory=True)
    out = tmp_path / "out"
    out.mkdir()
    named = ops / "cfg.yaml"
    assert os.path.realpath(named) == str(secret)
    run_ash_container._refuse_config_linked_out_of_the_tree(str(named), source)
    _assert_given_unrefused_and_marked(source, out, named)


def test_the_walk_reads_links_through_the_repos_own_link_test(tmp_path, monkeypatch):
    """The walk asks ``config_sources._is_a_link``, not ``os.path.islink``:
    on Windows a junction is a reparse point islink never reports, so a
    ``src\\J\\..\\..\\secret.yaml`` spelling walked as plain arithmetic and
    was not refused. Junctions cannot be built here, so the seam is pinned
    by widening the helper: a plain directory it calls a link gets the link
    verdict, which islink alone would never give. The gate is a refusal, so
    reading every reparse point as a link fails closed; the scan-set walk
    deliberately does not (OneDrive placeholders), which is why the helper
    is consulted here and not shared with it."""
    from automated_security_helper.config import config_sources

    secret = tmp_path / "secret.yaml"
    secret.write_text("project_name: theirs\n")
    source = tmp_path / "src"
    junction = source / "J"
    junction.mkdir(parents=True)
    real_is_a_link = config_sources._is_a_link
    monkeypatch.setattr(
        config_sources,
        "_is_a_link",
        lambda path: Path(path) == junction or real_is_a_link(path),
    )
    with pytest.raises(ContainerInputError, match="link"):
        run_ash_container._refuse_config_linked_out_of_the_tree(
            f"{source}/J/../../secret.yaml", source
        )


@pytest.mark.parametrize("layout", NAMES_STEERED_BY_THE_SCANNED_CHECKOUT)
def test_a_name_the_scanned_checkout_steers_out_of_it_is_refused(layout, tmp_path):
    """A ``..`` after a link that sits in the checkout outside the source
    directory, and a directory alias onto a real checkout directory followed by
    a tree file link, both put the name in the scanned tree while the file
    resolves outside it."""
    checkout = tmp_path / "repo"
    mark_git_checkout(checkout)
    source = checkout / "api"
    source.mkdir()
    (checkout / "ci").mkdir()
    config = config_through_links(layout, checkout, tmp_path)
    assert not Path(os.path.realpath(config)).is_relative_to(checkout)
    with pytest.raises(ContainerInputError, match="link"):
        run_ash_container._refuse_config_linked_out_of_the_tree(str(config), source)


def test_a_name_whose_final_component_is_a_link_loop_is_refused(tmp_path):
    """Two links pointing at each other, both outside every checkout. The
    collapse of the first cannot resolve, so the walk is undecided and the
    name is refused rather than handed to the runner as it stands."""
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.symlink_to(second)
    second.symlink_to(first)
    source = tmp_path / "src"
    source.mkdir()
    with pytest.raises(ContainerInputError, match="cannot be resolved"):
        run_ash_container._refuse_config_linked_out_of_the_tree(str(first), source)


def test_a_name_with_a_link_loop_as_a_directory_component_is_refused(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.symlink_to(second)
    second.symlink_to(first)
    source = tmp_path / "src"
    source.mkdir()
    with pytest.raises(ContainerInputError, match="cannot be resolved"):
        run_ash_container._refuse_config_linked_out_of_the_tree(
            str(first / "cfg.yaml"), source
        )


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root reads a directory whatever its mode",
)
def test_a_name_through_a_link_in_an_unreadable_directory_is_refused(tmp_path):
    """The link sits in a directory the process cannot search, so the walk
    cannot tell what the name leads to and refuses it."""
    real = tmp_path / "real.yaml"
    real.write_text("project_name: mine\n")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "lnk").symlink_to(real)
    source = tmp_path / "src"
    source.mkdir()
    locked.chmod(0o000)
    try:
        with pytest.raises(ContainerInputError, match="cannot be resolved"):
            run_ash_container._refuse_config_linked_out_of_the_tree(
                str(locked / "lnk"), source
            )
    finally:
        locked.chmod(0o755)


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root reads a directory whatever its mode",
)
def test_an_undecidable_name_through_a_collapsed_link_quotes_only_the_given_spelling(
    tmp_path, request
):
    """The operator names a config through their own link, which leads through
    a link inside the scanned tree to a directory the process cannot search.
    The refusal names the component as the operator spelled it. The collapsed
    directory's name was chosen by the repository, so it is not in the text."""
    marker = "zq7-marker\x1b[31m"
    target = tmp_path / f"target-{marker}"
    target.mkdir()
    source = tmp_path / "src"
    source.mkdir()
    (source / "tree_link").symlink_to(target)
    ops = tmp_path / "ops"
    ops.symlink_to(source / "tree_link")
    spelled = ops / "locked" / "cfg.yaml"
    target.chmod(0o000)
    request.addfinalizer(lambda: target.chmod(0o755))
    with pytest.raises(ContainerInputError, match="cannot be resolved") as raised:
        run_ash_container._refuse_config_linked_out_of_the_tree(str(spelled), source)
    text = str(raised.value)
    assert str(spelled) in text
    assert f"goes through '{ops / 'locked'}'" in text
    assert "zq7-marker" not in text


def test_a_link_loop_refusal_still_names_the_given_name(tmp_path):
    """The control for the cell above: a collapse that cannot resolve names the
    operator's own spelling, as it did before."""
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.symlink_to(second)
    second.symlink_to(first)
    source = tmp_path / "src"
    source.mkdir()
    with pytest.raises(ContainerInputError, match="cannot be resolved") as raised:
        run_ash_container._refuse_config_linked_out_of_the_tree(str(first), source)
    text = str(raised.value)
    assert f"The name '{first}' goes through '{first}'" in text


def test_an_undecidable_name_with_control_characters_is_refused_without_raw_ones(
    tmp_path,
):
    """The given name may hold a control character the operator typed or a
    shell expanded; the refusal writes it as an escape."""
    first = tmp_path / "loop\n\x1b[2Jfirst"
    second = tmp_path / "second"
    first.symlink_to(second)
    second.symlink_to(first)
    source = tmp_path / "src"
    source.mkdir()
    with pytest.raises(ContainerInputError, match="cannot be resolved") as raised:
        run_ash_container._refuse_config_linked_out_of_the_tree(str(first), source)
    text = str(raised.value)
    assert "\n" not in text
    assert "\x1b" not in text
    assert "loop\\x0a\\x1b[2Jfirst" in text


def test_a_name_whose_link_walk_the_bound_cuts_short_is_marked(tmp_path):
    """A walk the link bound cuts short is undecided, and an undecided name is
    judged the repository's, so the mark still rides.

    Forty operator-side links lead to a forty-first that sits in the scanned
    checkout and points at an outside file. The walk stops at the bound before
    it reaches that tree link; read as "no tree link on the way" the file
    would pass as the operator's."""
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: theirs\n")
    source = tmp_path / "src"
    source.mkdir()
    ops = tmp_path / "ops"
    ops.mkdir()
    tree_link = source / "link_40"
    tree_link.symlink_to(outside)
    for index in range(40):
        target = tree_link if index == 39 else ops / f"link_{index + 1}"
        (ops / f"link_{index}").symlink_to(target)
    named = ops / "link_0"
    assert os.path.realpath(named) == str(outside)
    assert run_ash_container._repository_written(named, source)


def test_a_short_chain_of_outside_links_is_not_marked(tmp_path):
    """The control for the cell above: a decided walk with no tree link on the
    way leaves the file the operator's."""
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: mine\n")
    source = tmp_path / "src"
    source.mkdir()
    ops = tmp_path / "ops"
    ops.mkdir()
    (ops / "link_1").symlink_to(outside)
    (ops / "link_0").symlink_to(ops / "link_1")
    assert not run_ash_container._repository_written(ops / "link_0", source)


def test_a_name_entirely_through_outside_links_stays_the_operators(tmp_path):
    """Following an outside link does not widen the gate: a chain that never
    touches a scanned tree is the operator's own, wherever it points."""
    other = tmp_path / "other"
    other.mkdir()
    (other / "cfg.yaml").write_text("project_name: mine\n")
    lnk = tmp_path / "lnk"
    lnk.symlink_to(other)
    source = tmp_path / "src"
    source.mkdir()
    run_ash_container._refuse_config_linked_out_of_the_tree(
        str(lnk / "cfg.yaml"), source
    )


def test_a_link_the_platform_reports_but_cannot_read_as_one_is_refused(
    tmp_path, monkeypatch
):
    """Some platforms report entries as links that reading then refuses as one
    (ValueError, not OSError: a reparse point that is not a symbolic link).
    The collapse cannot decide such a name, so the walk refuses it rather than
    handing the runner a name it could not resolve."""
    other = tmp_path / "other"
    other.mkdir()
    (other / "cfg.yaml").write_text("project_name: mine\n")
    lnk = tmp_path / "lnk"
    lnk.symlink_to(other)
    source = tmp_path / "src"
    source.mkdir()
    real_readlink = os.readlink

    def readlink_like_a_reparse_point(path, *args, **kwargs):
        if os.fspath(path) == str(lnk):
            raise ValueError("not a symbolic link")
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", readlink_like_a_reparse_point)

    with pytest.raises(ContainerInputError, match="cannot be resolved"):
        run_ash_container._refuse_config_linked_out_of_the_tree(
            str(lnk / "cfg.yaml"), source
        )


def test_a_link_into_a_directory_loop_is_refused(tmp_path):
    """``first`` points into ``loop_a/sub`` and ``loop_a`` and ``loop_b``
    point at each other. The resolution returns a path under the loop, which
    cannot be looked up: that is not a settled place, so the name is refused
    rather than judged by a path nothing could resolve."""
    loop_a = tmp_path / "loop_a"
    loop_b = tmp_path / "loop_b"
    loop_a.symlink_to(loop_b)
    loop_b.symlink_to(loop_a)
    first = tmp_path / "first"
    first.symlink_to(loop_a / "sub")
    source = tmp_path / "src"
    source.mkdir()
    with pytest.raises(ContainerInputError, match="cannot be resolved"):
        run_ash_container._refuse_config_linked_out_of_the_tree(str(first), source)


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root reads a directory whatever its mode",
)
def test_a_link_into_a_directory_the_process_cannot_search_is_refused(tmp_path):
    """The link itself reads fine; the place it lands on cannot be examined.
    The refusal says that, and does not blame a directory on the way or a
    link that cannot be read."""
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "cfg.yaml").write_text("project_name: theirs\n")
    first = tmp_path / "first"
    first.symlink_to(locked / "cfg.yaml")
    source = tmp_path / "src"
    source.mkdir()
    locked.chmod(0o000)
    try:
        with pytest.raises(ContainerInputError, match="cannot be resolved") as refusal:
            run_ash_container._refuse_config_linked_out_of_the_tree(str(first), source)
    finally:
        locked.chmod(0o755)
    message = str(refusal.value)
    assert run_ash_container._LOOP_OR_UNEXAMINABLE_LANDING in message, message
    assert run_ash_container._UNSEARCHABLE_DIRECTORY not in message, message
    assert run_ash_container._UNREADABLE_LINK not in message, message


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(
            OSError(errno.ELOOP, "Too many levels of symbolic links"), id="loop"
        ),
        pytest.param(ValueError("not a symbolic link"), id="reparse-point"),
    ],
)
def test_a_collapse_that_raises_is_refused_as_unresolvable(
    error, tmp_path, monkeypatch
):
    """Some platforms raise out of the resolution itself instead of returning
    the unresolved path; either way the walk cannot decide the rest."""
    other = tmp_path / "other"
    other.mkdir()
    (other / "cfg.yaml").write_text("project_name: mine\n")
    lnk = tmp_path / "lnk"
    lnk.symlink_to(other)
    source = tmp_path / "src"
    source.mkdir()
    real_realpath = os.path.realpath

    def realpath(path, *args, **kwargs):
        if os.fspath(path) == str(lnk):
            raise error
        return real_realpath(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "realpath", realpath)
    with pytest.raises(ContainerInputError, match="cannot be resolved"):
        run_ash_container._refuse_config_linked_out_of_the_tree(
            str(lnk / "cfg.yaml"), source
        )


def test_a_link_nothing_can_read_is_refused_as_unresolvable(tmp_path, monkeypatch):
    """A link the process cannot read cannot be collapsed: the walk refuses
    the name instead of walking past the link or guessing where it lands."""
    secret = tmp_path / "secret.yaml"
    secret.write_text("project_name: theirs\n")
    source = tmp_path / "src"
    source.mkdir()
    (source / "leak.yaml").symlink_to(secret)
    outside_link = tmp_path / "lnk"
    outside_link.symlink_to(source)
    real_readlink = os.readlink

    def readlink_refusing(path, *args, **kwargs):
        if os.fspath(path) == str(outside_link):
            raise PermissionError(13, "planted: permission denied")
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", readlink_refusing)

    with pytest.raises(ContainerInputError, match="cannot be resolved"):
        run_ash_container._refuse_config_linked_out_of_the_tree(
            str(outside_link / "leak.yaml"), source
        )


def test_a_place_the_resolution_leaves_as_a_link_is_refused(tmp_path, monkeypatch):
    """A collapse that returns its own input left a link unresolved (before
    Python 3.13 the resolution swallows a read error exactly this way): the
    walk cannot decide the rest of the name and refuses it."""
    other = tmp_path / "other"
    other.mkdir()
    (other / "cfg.yaml").write_text("project_name: mine\n")
    lnk = tmp_path / "lnk"
    lnk.symlink_to(other)
    source = tmp_path / "src"
    source.mkdir()

    monkeypatch.setattr(os.path, "realpath", lambda p, **kw: os.fspath(p))

    with pytest.raises(ContainerInputError, match="cannot be resolved"):
        run_ash_container._refuse_config_linked_out_of_the_tree(
            str(lnk / "cfg.yaml"), source
        )


def _walk_stop_messages(caplog):
    return [
        record.getMessage()
        for record in caplog.records
        if "The link walk for" in record.getMessage()
    ]


def test_a_walk_the_bound_cuts_short_says_where_it_stopped(tmp_path, caplog):
    """The name is judged the repository's, which removes grants and is
    explained by a sentence about a location, so the log names the link the
    walk stopped at, once however many times the name is judged."""
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: theirs\n")
    source = tmp_path / "src"
    source.mkdir()
    ops = tmp_path / "ops"
    ops.mkdir()
    tree_link = source / "link_40"
    tree_link.symlink_to(outside)
    for index in range(40):
        target = tree_link if index == 39 else ops / f"link_{index + 1}"
        (ops / f"link_{index}").symlink_to(target)
    with caplog.at_level(logging.WARNING, logger="ash"):
        assert run_ash_container._repository_written(ops / "link_0", source)
        assert run_ash_container._repository_written(ops / "link_0", source)
    messages = _walk_stop_messages(caplog)
    assert len(messages) == 1, messages
    assert tree_link.as_posix() in messages[0], messages
    assert "more than 40 links" in messages[0], messages


@pytest.mark.parametrize(
    ("error", "said"),
    [
        pytest.param(
            PermissionError(13, "Permission denied"),
            "Permission denied",
            id="unreadable",
        ),
        pytest.param(
            ValueError("not a symbolic link"),
            "not readable as a link",
            id="reparse-point-that-is-not-a-link",
        ),
    ],
)
def test_a_walk_through_a_link_that_cannot_be_read_says_where_it_stopped(
    error, said, tmp_path, caplog, monkeypatch
):
    from automated_security_helper.config import sandbox_grants

    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: theirs\n")
    ops = tmp_path / "ops"
    ops.mkdir()
    link = ops / "lnk"
    link.symlink_to(outside)
    real_readlink = os.readlink

    def readlink(path, *args, **kwargs):
        if os.fspath(path) == str(link):
            raise error
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", readlink)
    with caplog.at_level(logging.WARNING, logger="ash"):
        links, decided = sandbox_grants._walk_links(link)
    assert (links, decided) == ([link], False)
    messages = _walk_stop_messages(caplog)
    assert len(messages) == 1, messages
    assert link.as_posix() in messages[0], messages
    assert said in messages[0], messages


def test_a_walk_that_reaches_the_end_says_nothing(tmp_path, caplog):
    """The control for the cells above: a decided walk logs no stop."""
    outside = tmp_path / "outside.yaml"
    outside.write_text("project_name: mine\n")
    source = tmp_path / "src"
    source.mkdir()
    ops = tmp_path / "ops"
    ops.mkdir()
    (ops / "link_1").symlink_to(outside)
    (ops / "link_0").symlink_to(ops / "link_1")
    with caplog.at_level(logging.WARNING, logger="ash"):
        assert not run_ash_container._repository_written(ops / "link_0", source)
    assert _walk_stop_messages(caplog) == []
