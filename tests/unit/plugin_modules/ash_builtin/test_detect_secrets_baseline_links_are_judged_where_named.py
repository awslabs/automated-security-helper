# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A detect-secrets baseline is judged by the path that named it, not by its target.

The scanner resolved each baseline candidate with ``os.path.realpath`` and then
judged that resolved path everywhere: ``_baseline_refusal`` saw it as the path
"named", and ``_untrusted_baseline_reason`` handed it to
``scanned_checkout_reason``. So an in-tree ``.secrets.baseline`` that was a
symlink to a file outside the tree was read, and its settings, the verification
filter included, were judged by where the target sat: outside the scanned tree,
so the operator's.

Now the chosen baseline keeps the path as named (anchored to the source
directory, no link resolved) beside the resolved path the file is read through.
A baseline found in the tree whose target is outside the scanned directory is
not read at all; a baseline the operator names is read and judged by the name
the operator gave AND by the file it resolves to: a name outside the tree that
is a link into it reads the repository's file, so its settings are the
repository's too.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)


def _baseline_text() -> str:
    return json.dumps(
        {
            "version": "1.5.0",
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [{"path": VERIFICATION_FILTER, "min_level": 2}],
            "results": {},
            "generated_at": "2026-01-01T00:00:00Z",
        }
    )


def _context(tmp_path: Path) -> PluginContext:
    """A scan of ``tmp_path/src``, which is made its own git checkout.

    The trust rules look for a checkout at or above the scanned directory, and
    every directory above ``tmp_path`` is the host's. Making ``src`` the
    nearest checkout fixes what "the repository" is for these tests, so a
    ``.git`` that happens to sit in a parent of the temporary directory cannot
    widen what they treat as the repository's."""
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True, exist_ok=True)
    _git_shaped_checkout(context.source_dir)
    context.output_dir.mkdir(parents=True, exist_ok=True)
    return context


def _git_shaped_checkout(root: Path) -> Path:
    """``root`` as a git checkout the trust rules recognize: a ``.git``
    directory holding ``HEAD`` (an empty ``.git`` is a stray mkdir to them)."""
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    return root


def _link_in_tree_to_outside(tmp_path: Path, context: PluginContext) -> Path:
    """``<source>/.secrets.baseline`` as a symlink to a baseline outside the tree."""
    outside = tmp_path / "elsewhere" / "team.baseline"
    outside.parent.mkdir(parents=True)
    outside.write_text(_baseline_text(), encoding="utf-8")
    link = context.source_dir / ".secrets.baseline"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlinks unavailable on this platform: {exc}")
    return outside


def test_an_in_tree_baseline_that_links_out_of_the_tree_is_not_read(
    tmp_path, monkeypatch, caplog
):
    monkeypatch.chdir(tmp_path)
    # Offline mode drops the verification filter whatever its source, which
    # would make the "filter absent" assertions below pass vacuously.
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    context = _context(tmp_path)
    _link_in_tree_to_outside(tmp_path, context)

    with caplog.at_level(logging.WARNING):
        scanner = DetectSecretsScanner(
            context=context, config=DetectSecretsScannerConfig()
        )

    assert not scanner._baseline_in_use()
    assert scanner._baseline_document is None
    assert any(
        "a link to a file outside the scanned directory" in record.message
        for record in caplog.records
    ), [record.message for record in caplog.records]
    # The scan still has detectors: the full default set, not the link's one.
    assert len(scanner.config.options.scan_settings.plugins_used) > 10
    # The link's settings are not the scan's: the verification filter it names
    # was not loaded.
    assert not any(
        item.path == VERIFICATION_FILTER
        for item in scanner.config.options.scan_settings.filters_used
    )


def test_an_operator_named_in_tree_link_is_judged_where_it_is_named(
    tmp_path, monkeypatch
):
    """The operator may name the link; its settings are still the repository's,
    because the file named sits inside the scanned directory."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    outside = _link_in_tree_to_outside(tmp_path, context)
    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=".secrets.baseline")
        ),
    )

    assert scanner._baseline_in_use()
    assert scanner._baseline_named == context.source_dir / ".secrets.baseline"
    assert scanner._baseline_real == Path(os.path.realpath(outside))
    reason = scanner._untrusted_baseline_reason(None)
    assert reason is not None and "inside the scanned directory" in reason, reason


def test_an_outside_name_that_links_into_the_tree_is_judged_by_its_target(
    tmp_path, monkeypatch
):
    """The mirror case: the operator names a path outside the tree, and that
    path is a link to the tree's own ``.secrets.baseline``. The file read is
    the repository's, so its settings are the repository's: the verification
    filter it carries is not loaded. Judged by the name alone, the baseline
    read as the operator's and the filter stayed."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    context = _context(tmp_path)
    in_tree = context.source_dir / ".secrets.baseline"
    in_tree.write_text(_baseline_text(), encoding="utf-8")
    link = tmp_path / "ci" / "proj.baseline"
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(in_tree)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlinks unavailable on this platform: {exc}")

    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=str(link))
        ),
    )

    assert scanner._baseline_in_use()
    assert scanner._baseline_named == link
    assert scanner._baseline_real == Path(os.path.realpath(in_tree))
    reason = scanner._untrusted_baseline_reason(None)
    assert reason is not None and "inside the scanned directory" in reason, reason
    assert not any(
        item.path == VERIFICATION_FILTER
        for item in scanner.config.options.scan_settings.filters_used
    )


def test_an_outside_baseline_that_is_no_link_is_the_operators(tmp_path, monkeypatch):
    """Control for the test above: the same outside name, a regular file, is
    the operator's, and its verification filter is loaded (offline mode would
    drop it whatever the source, so it is off here)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    context = _context(tmp_path)
    outside = tmp_path / "ci" / "proj.baseline"
    outside.parent.mkdir(parents=True)
    outside.write_text(_baseline_text(), encoding="utf-8")

    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=str(outside))
        ),
    )

    assert scanner._baseline_in_use()
    assert scanner._untrusted_baseline_reason(None) is None
    assert any(
        item.path == VERIFICATION_FILTER
        for item in scanner.config.options.scan_settings.filters_used
    )


def test_a_regular_in_tree_baseline_is_named_where_it_sits(tmp_path, monkeypatch):
    """Control: a baseline that is no link is used, and named by its own path."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    (context.source_dir / ".secrets.baseline").write_text(
        _baseline_text(), encoding="utf-8"
    )
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())

    assert scanner._baseline_in_use()
    assert scanner._baseline_named == context.source_dir / ".secrets.baseline"
    assert [p.name for p in scanner.config.options.scan_settings.plugins_used] == [
        "AWSKeyDetector"
    ]
    reason = scanner._untrusted_baseline_reason(None)
    assert reason is not None and "inside the scanned directory" in reason, reason


def test_an_in_tree_link_elsewhere_in_the_checkout_is_read(
    tmp_path, monkeypatch, caplog
):
    """A monorepo: the scanned directory is ``repo/service``, and its
    ``.secrets.baseline`` is a link to the checkout's own ``repo/.secrets.baseline``.
    The target is the repository's file, inside the nearest checkout that
    holds the scanned directory, so it is read, and judged as the
    repository's. Tested against the scanned directory alone, the link was
    refused as pointing outside."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    checkout = tmp_path / "repo"
    _git_shaped_checkout(checkout)
    shared = checkout / ".secrets.baseline"
    shared.write_text(_baseline_text(), encoding="utf-8")
    context = PluginContext(
        source_dir=checkout / "service",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    link = context.source_dir / ".secrets.baseline"
    try:
        link.symlink_to(Path("..") / ".secrets.baseline")
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlinks unavailable on this platform: {exc}")

    with caplog.at_level(logging.WARNING):
        scanner = DetectSecretsScanner(
            context=context, config=DetectSecretsScannerConfig()
        )

    assert scanner._baseline_in_use()
    assert scanner._baseline_named == link
    assert scanner._baseline_real == Path(os.path.realpath(shared))
    assert not any(
        "a link to a file outside" in record.message for record in caplog.records
    ), [record.message for record in caplog.records]
    reason = scanner._untrusted_baseline_reason(None)
    assert reason is not None and "inside the" in reason, reason
    # The repository's settings: the link's verification filter is not loaded.
    assert not any(
        item.path == VERIFICATION_FILTER
        for item in scanner.config.options.scan_settings.filters_used
    )


def test_a_source_directory_reached_through_a_link_keeps_its_own_baseline(
    tmp_path, monkeypatch, caplog
):
    """A scanned directory spelled through a symlink (a linked workspace, or a
    platform whose temporary directory is a link), with no enclosing checkout,
    keeps its own regular ``.secrets.baseline``: the admitted link root is the
    scanned directory itself, resolved before the containment test as every
    other root the scanner hands ``is_within``. The test compares by file
    identity, so the answer was the same with the root unresolved; this pins
    the shape against a later reader that compares the paths as spelled, where
    the unresolved root would refuse the tree's own file with the misleading
    "a link to a file outside" warning."""
    monkeypatch.chdir(tmp_path)
    real_src = tmp_path / "real" / "src"
    real_src.mkdir(parents=True)
    (real_src / ".secrets.baseline").write_text(_baseline_text(), encoding="utf-8")
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(tmp_path / "real", target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlinks unavailable on this platform: {exc}")
    context = PluginContext(
        source_dir=linked / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.output_dir.mkdir(parents=True)

    with caplog.at_level(logging.WARNING):
        scanner = DetectSecretsScanner(
            context=context, config=DetectSecretsScannerConfig()
        )

    assert scanner._baseline_in_use()
    assert scanner._baseline_named == linked / "src" / ".secrets.baseline"
    assert not any(
        "a link to a file outside" in record.message for record in caplog.records
    ), [record.message for record in caplog.records]


def test_an_in_tree_link_into_an_outer_checkout_is_refused(
    tmp_path, monkeypatch, caplog
):
    """The scanned repository ``home/project`` is its own checkout, and the
    directory above it, ``home``, is a checkout too (a home directory kept in
    git). A committed ``project/.secrets.baseline -> ../operator.baseline``
    reaches a file of the outer checkout, which is not the repository's: the
    admitted targets are the nearest checkout's, so the link is refused and
    the scan runs without a baseline. Admitting every enclosing checkout read
    the operator's file under the repository's own settings."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    home = _git_shaped_checkout(tmp_path / "home")
    outer = home / "operator.baseline"
    outer.write_text(_baseline_text(), encoding="utf-8")
    project = _git_shaped_checkout(home / "project")
    context = PluginContext(
        source_dir=project,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.output_dir.mkdir(parents=True)
    link = project / ".secrets.baseline"
    try:
        link.symlink_to(Path("..") / "operator.baseline")
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlinks unavailable on this platform: {exc}")

    with caplog.at_level(logging.WARNING):
        scanner = DetectSecretsScanner(
            context=context, config=DetectSecretsScannerConfig()
        )

    assert not scanner._baseline_in_use()
    assert scanner._baseline_document is None
    assert any(
        "a link to a file outside the scanned directory" in record.message
        for record in caplog.records
    ), [record.message for record in caplog.records]
    assert not any(
        item.path == VERIFICATION_FILTER
        for item in scanner.config.options.scan_settings.filters_used
    )


def test_the_named_path_is_absolute_and_normalized(tmp_path, monkeypatch):
    """The named path is compared with other paths by the gate and the trust
    rule, so it is made absolute and normalized (``..`` folded) with no link
    resolved. A ``baseline_file`` spelled through a ``..`` part names the
    in-tree file; a relative source directory, which a library caller can
    pass, yields an absolute name."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    in_tree = context.source_dir / ".secrets.baseline"
    in_tree.write_text(_baseline_text(), encoding="utf-8")

    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(
                baseline_file="sub/../.secrets.baseline"
            )
        ),
    )
    assert scanner._baseline_in_use()
    assert scanner._baseline_named == in_tree
    assert ".." not in scanner._baseline_named.parts

    relative = PluginContext(
        source_dir=Path("src"),
        output_dir=Path("out"),
        work_dir=Path("out") / "converted",
        config=get_default_config(),
    )
    scanner = DetectSecretsScanner(
        context=relative, config=DetectSecretsScannerConfig()
    )
    assert scanner._baseline_in_use()
    assert scanner._baseline_named is not None
    assert scanner._baseline_named.is_absolute()
    assert scanner._baseline_named == Path.cwd() / "src" / ".secrets.baseline"


def test_a_client_delivered_link_is_refused_by_its_name(tmp_path, monkeypatch):
    """An MCP client's delivered tree is known by its path. A ``.secrets.baseline``
    in it that links out of the tree was tested by its resolved path only, which
    is not under the delivered tree, so the client's choice of what to hide was
    read. The name the client delivered is what is tested."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    _link_in_tree_to_outside(tmp_path, context)
    from automated_security_helper.cli.mcp import sandbox

    delivered = os.path.normpath(str(context.source_dir / ".secrets.baseline"))

    def client_supplied(config_path):
        return os.path.normpath(str(config_path)) == delivered

    monkeypatch.setattr(sandbox, "config_is_client_supplied", client_supplied)
    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=".secrets.baseline")
        ),
    )

    assert scanner._baseline_trust_refused is True
    assert not scanner._baseline_in_use()
