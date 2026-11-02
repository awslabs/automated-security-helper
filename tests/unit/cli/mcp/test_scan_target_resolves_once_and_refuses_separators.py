#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan target is the path the sandbox judged, and output parts are one component each.

``resolve_scan_target`` resolved the caller's text itself, beside the sandbox's
own resolution, and returned its own: two resolutions of one name can lead to two
places (a link re-pointed between them), and the scan then wrote under a target
no gate permitted. ``validate_output_tree`` checked each relative part through a
containment check that reads a backslash as a separator, while the directory
later made from the part on POSIX is one flat name holding the backslash: the
path checked was not the path created.
"""

from __future__ import annotations

from pathlib import Path

import os

import pytest

from automated_security_helper.cli.mcp.scan_target import (
    ASH_MCP_ALLOWED_ROOTS_ENV,
    resolve_scan_target,
    validate_output_tree,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_grant(monkeypatch, tmp_path):
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))


class TestTheTargetIsResolvedOnce:
    def test_the_callers_path_is_resolved_once(self, monkeypatch, tmp_path):
        """Red at the base: the target's text was resolved twice, once per side.

        The expected path is resolved before the recorder is installed, so the
        count below is the production code's alone: an earlier shape resolved
        ``target`` inside the assertion while the recorder was live, which added
        the test's own call to the count it was checking.

        The gate resolves with ``os.path.realpath`` (``Path.resolve`` raised on a
        looping link on Python 3.12 and older), so that is the call it makes; a
        recorder on ``Path.resolve`` alone counted nothing once the gate moved.
        Both are recorded, by name: ``Path.resolve`` is called with the target
        too if a second resolution comes back, and the list reads
        ``["realpath"]`` only when the gate's one call is the whole of it.
        """
        target = tmp_path / "checkout"
        target.mkdir()
        expected = target.resolve()
        seen = []
        real_realpath = os.path.realpath
        real_resolve = Path.resolve

        def recording_realpath(path, *args, **kwargs):
            if os.fspath(path) == str(target):
                seen.append("realpath")
            return real_realpath(path, *args, **kwargs)

        def recording_resolve(self, strict=False):
            if str(self) == str(target):
                seen.append("resolve")
            return real_resolve(self, strict=strict)

        monkeypatch.setattr(os.path, "realpath", recording_realpath)
        monkeypatch.setattr(Path, "resolve", recording_resolve)

        resolution = resolve_scan_target(target)

        assert resolution.error is None
        assert resolution.resolved == expected
        assert seen == ["realpath"], seen

    def test_the_resolved_path_is_the_one_the_sandbox_judged(
        self, monkeypatch, tmp_path
    ):
        """The sandbox's resolution is returned, not a resolution made here.

        The link is re-pointed right after the gate's resolution, so a second
        one would land elsewhere; the path returned is where the gate looked.
        The hook is on ``os.path.realpath``, the call the gate makes (a hook on
        ``Path.resolve`` never ran once the gate moved, and the equality below
        held whatever the code did); the test asserts that the hook ran and that
        the link leads elsewhere afterwards, so it cannot pass without the
        re-pointing it exists to survive.
        """
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()
        link = tmp_path / "link"
        link.symlink_to(first)
        first_resolved = first.resolve()
        second_resolved = second.resolve()
        real_realpath = os.path.realpath
        repointed = []

        def repointing_realpath(path, *args, **kwargs):
            result = real_realpath(path, *args, **kwargs)
            if os.fspath(path) == str(link) and not repointed:
                repointed.append(result)
                link.unlink()
                link.symlink_to(second)
            return result

        monkeypatch.setattr(os.path, "realpath", repointing_realpath)

        resolution = resolve_scan_target(link)

        assert resolution.error is None
        assert repointed == [str(first_resolved)], "the gate never resolved the link"
        assert Path(real_realpath(link)) == second_resolved
        assert resolution.resolved == first_resolved

    def test_a_refusal_is_still_a_refusal(self, tmp_path):
        """Control: a refused target returns the error and no path."""
        resolution = resolve_scan_target("/")

        assert resolution.error is not None
        assert resolution.resolved is None


class TestOutputPartsAreOneComponentEach:
    @pytest.mark.parametrize("part", ["a\\b", "a/b"])
    def test_a_part_holding_a_separator_is_refused(self, tmp_path, part):
        """Red at the base on POSIX for the backslash: checked nested, made flat."""
        target = tmp_path / "checkout"
        target.mkdir()

        refusal = validate_output_tree(target.resolve(), ".ash", part)

        assert refusal is not None
        assert "path separator" in str(refusal)
        # The context renders the component joined under ``.ash`` as a path of
        # the platform: on Windows ``a/b`` reads back as ``a\b``, while on POSIX
        # the backslash is one flat name and reads back as written.
        assert refusal.context["output_component"].endswith(part.replace("/", os.sep))

    def test_plain_parts_are_still_admitted(self, tmp_path):
        """Control: the usual output tree is a contained path."""
        target = tmp_path / "checkout"
        target.mkdir()

        assert validate_output_tree(target.resolve(), ".ash", "ash_output") is None
