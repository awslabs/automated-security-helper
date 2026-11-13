# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A file the host marked as the scanned repository's is nobody's tool input.

Inside the container, the mounted copies of files the host judged
repository-written sit outside every checkout, so a membership test that only
looks at the scanned trees reads them as the operator's: a scanner option
naming such a copy was handed to the tool inside while the same file was
refused on the host. ``path_trust.in_scanned_tree`` now judges by the same
rule every other membership site uses (``sandbox_grants.files_inside``), which
reads the marks, and the host lists every repository-written chain file
individually when the chain's root is marked, so a base of that chain is a
marked file of its own inside. A mark only takes grants away.
"""

from __future__ import annotations


import pytest

from automated_security_helper.config.sandbox_grants import (
    marked_files_repository_written,
    marked_repository_written,
)
from automated_security_helper.interactions import run_ash_container
from automated_security_helper.config.path_trust import honored_path, in_scanned_tree

pytestmark = pytest.mark.unit


def test_a_marked_file_is_in_the_scanned_tree_wherever_it_sits(tmp_path):
    copy = tmp_path / "mounted" / "cfg.yaml"
    copy.parent.mkdir()
    copy.write_text("project_name: theirs\n")
    assert not in_scanned_tree(copy, None)
    with marked_files_repository_written([copy]):
        assert in_scanned_tree(copy, None)
    assert not in_scanned_tree(copy, None)


def test_a_chain_marked_root_is_the_scanned_partys_too(tmp_path):
    root = tmp_path / "mounted" / "cfg.yaml"
    root.parent.mkdir()
    root.write_text("project_name: theirs\n")
    with marked_repository_written(root):
        assert in_scanned_tree(root, None)


def test_honored_path_refuses_a_marked_file(tmp_path):
    from automated_security_helper.config import path_trust

    path_trust.reset_path_refusal_warnings()
    copy = tmp_path / "mounted" / "tool.cfg"
    copy.parent.mkdir()
    copy.write_text("[tool]\n")
    source = tmp_path / "src"
    source.mkdir()
    honored = honored_path(copy, source_dir=source, key="config_file")
    assert honored == copy.resolve()
    with marked_files_repository_written([copy]):
        assert honored_path(copy, source_dir=source, key="config_file") is None
    assert honored_path(copy, source_dir=source, key="config_file") == copy.resolve()


def _mount_plan_of(config, source, mount_root=None):
    """The plan the mounts were built from, as `_assemble_run_command` gets it."""
    *_, plan = run_ash_container._host_file_in_container(
        str(config),
        source,
        mount_root or run_ash_container.CONTAINER_CONFIG_ROOT,
        follow_extends=True,
    )
    return plan


def _checkout_with_chain(tmp_path):
    """A git checkout holding src/, a two-file config chain, and its source dir."""
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    source = checkout / "src"
    source.mkdir()
    config = checkout / "cfg.yaml"
    config.write_text("extends: base.yaml\nproject_name: theirs\n")
    (checkout / "base.yaml").write_text("project_name: base\n")
    return config, source


def test_the_marks_consume_the_mount_plan_without_resolving_again(
    tmp_path, monkeypatch
):
    """One plan per scan: the chain is resolved when the mounts are built, and
    the marks judge that plan. A marks pass that resolved the chain again could
    drift from what was mounted, which is how mounted checkout bases shipped
    unmarked when the second resolution failed."""
    from automated_security_helper.config import config_sources

    config, source = _checkout_with_chain(tmp_path)

    resolve_calls = []
    real_resolve = config_sources.resolve_config_document

    def counting_resolve(path, *args, **kwargs):
        resolve_calls.append(str(path))
        return real_resolve(path, *args, **kwargs)

    chain_calls = []
    # The one placement entry point the mount plan calls; the compatibility
    # wrapper (``_chain_placements``) routes through this module global at call
    # time, so a caller of either spelling is counted.
    real_chain = run_ash_container._chain_placements_shown

    def counting_chain(*args, **kwargs):
        chain_calls.append(args)
        return real_chain(*args, **kwargs)

    monkeypatch.setattr(config_sources, "resolve_config_document", counting_resolve)
    monkeypatch.setattr(run_ash_container, "_chain_placements_shown", counting_chain)

    plan = _mount_plan_of(config, source)
    resolved_at_mount = len(resolve_calls)
    placed_at_mount = len(chain_calls)
    assert resolved_at_mount >= 1 and placed_at_mount >= 1, "the mount built a plan"

    from_repository, marked = run_ash_container._config_marks(str(config), source, plan)
    assert from_repository is True
    assert any(path.endswith("/base.yaml") for path in marked)
    assert len(resolve_calls) == resolved_at_mount, "the marks resolved the chain again"
    assert len(chain_calls) == placed_at_mount, "the marks placed the chain again"

    env_plan = _mount_plan_of(
        config, source, run_ash_container.CONTAINER_ENV_CONFIG_ROOT
    )
    resolved_at_mount = len(resolve_calls)
    placed_at_mount = len(chain_calls)
    marked = run_ash_container._env_config_marks(str(config), source, env_plan)
    assert any(path.endswith("/cfg.yaml") for path in marked)
    assert len(resolve_calls) == resolved_at_mount, (
        "the env marks resolved the chain again"
    )
    assert len(chain_calls) == placed_at_mount, "the env marks placed the chain again"


def test_a_failed_marks_judgment_refuses_the_scan(tmp_path, monkeypatch):
    """A judgment that fails after the chain was prepared for mounting refuses
    the scan, rather than send the mounted checkout files in without marks for
    the scan inside to honor."""
    config, source = _checkout_with_chain(tmp_path)
    plan = _mount_plan_of(config, source)
    env_plan = _mount_plan_of(
        config, source, run_ash_container.CONTAINER_ENV_CONFIG_ROOT
    )

    def raising(path, source_dir):
        raise OSError("transient read failure")

    monkeypatch.setattr(run_ash_container, "_repository_written", raising)
    with pytest.raises(run_ash_container.ContainerInputError, match="without the mark"):
        run_ash_container._config_marks(str(config), source, plan)
    with pytest.raises(run_ash_container.ContainerInputError, match="without the mark"):
        run_ash_container._env_config_marks(str(config), source, env_plan)


def test_a_marked_root_lists_its_chain_bases_for_the_scan_inside(tmp_path):
    """A repository-written --config is mounted with the chain mark, and every
    BASE of its chain comes marked individually too, so a mounted base checked
    on its own inside the container is a marked file. The root is not listed
    twice: the chain mark already names it, and a single-file chain carries
    the chain mark alone."""
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    source = checkout / "src"
    source.mkdir()
    config = checkout / "cfg.yaml"
    config.write_text("extends: base.yaml\nproject_name: theirs\n")
    (checkout / "base.yaml").write_text("project_name: base\n")
    from_repository, marked = run_ash_container._config_marks(
        str(config), source, _mount_plan_of(config, source)
    )
    assert from_repository is True
    assert any(path.endswith("/base.yaml") for path in marked), (
        "the chain's bases are listed for the scan inside"
    )
    assert not any(path.endswith("/cfg.yaml") for path in marked), (
        "the root rides the chain mark, not the per-file list"
    )
    assert all(path.startswith("/") for path in marked)

    lone = checkout / "lone.yaml"
    lone.write_text("project_name: theirs\n")
    from_repository, marked = run_ash_container._config_marks(
        str(lone), source, _mount_plan_of(lone, source)
    )
    assert from_repository is True
    assert marked == []


def test_an_operators_unmarked_file_stays_honored(tmp_path):
    from automated_security_helper.config import path_trust

    path_trust.reset_path_refusal_warnings()
    mine = tmp_path / "mine.cfg"
    mine.write_text("[tool]\n")
    source = tmp_path / "src"
    source.mkdir()
    assert not in_scanned_tree(mine, source)
    assert honored_path(mine, source_dir=source, key="config_file") == mine.resolve()
