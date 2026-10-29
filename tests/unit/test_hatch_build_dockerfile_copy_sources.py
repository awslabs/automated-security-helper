# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every COPY source of the staged assets/Dockerfile is inside the assets context.

Why this file exists
--------------------
hatch_build.py copies the root Dockerfile into automated_security_helper/assets/
and rewrites its COPY sources, because the shipped Dockerfile is built with the
assets directory as its context (run_ash_container passes the Dockerfile's parent),
where ``automated_security_helper/assets/Gemfile`` is just ``Gemfile``. The rewrite
replaced the text ``COPY automated_security_helper/assets/`` with ``COPY ``, which
touches only the source right after the instruction. The cfn-nag step copies two
files in one instruction::

    COPY automated_security_helper/assets/Gemfile automated_security_helper/assets/Gemfile.lock /deps/

so the staged line kept its second source at the checkout path, a path the assets
context does not contain, and the packaged image build failed at that COPY with
"file not found" while the same Dockerfile built from a checkout. Nothing read the
staged text: the existing hook test checks which files are written, not what the
Dockerfile says.

What is asserted
----------------
The rewrite is a pure function of the Dockerfile's text, so it is asserted here
in-process over the committed Dockerfile: every source of every COPY from the build
context is a bare name, and the staged package files are named by their staged
names. A planted two-source line pins the mechanism directly, so the assertion
over the real Dockerfile cannot pass by the cfn-nag step having moved.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"


def _load_hook(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "hatch_build_copy_sources", REPO_ROOT / "hatch_build.py"
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _copy_sources(dockerfile_text: str) -> list[tuple[str, list[str]]]:
    """``(line, sources)`` for every COPY from the build context.

    A ``--from=`` COPY reads another stage, not the context, so it is left out;
    other ``--`` flags are not sources; the last argument is the destination.
    """
    found = []
    for line in dockerfile_text.splitlines():
        words = line.split()
        if not words or words[0] != "COPY":
            continue
        if any(word.startswith("--from=") for word in words[1:]):
            continue
        arguments = [word for word in words[1:] if not word.startswith("--")]
        found.append((line, arguments[:-1]))
    return found


class TestEverySourceIsRewritten:
    def test_both_sources_of_a_two_source_copy_are_rewritten(self, monkeypatch):
        hook = _load_hook(monkeypatch)
        text = (
            "COPY automated_security_helper/assets/Gemfile "
            "automated_security_helper/assets/Gemfile.lock /deps/\n"
        )
        assert hook.staged_dockerfile_text(text) == "COPY Gemfile Gemfile.lock /deps/\n"

    def test_a_staged_package_file_is_named_by_its_staged_name(self, monkeypatch):
        hook = _load_hook(monkeypatch)
        source_rel, staged_name = hook.DOCKERFILE_STAGED_PACKAGE_FILES[0]
        text = f"COPY automated_security_helper/{source_rel} /ash-pins/x.py\n"
        assert (
            hook.staged_dockerfile_text(text) == f"COPY {staged_name} /ash-pins/x.py\n"
        )

    def test_other_lines_are_left_as_they_are(self, monkeypatch):
        hook = _load_hook(monkeypatch)
        text = (
            "# COPY automated_security_helper/assets/x is documentation\n"
            "COPY --from=uv-reqs /src/dist/*.whl .\n"
            "COPY . /ash-context\n"
            "RUN cat automated_security_helper/assets/x\n"
        )
        assert hook.staged_dockerfile_text(text) == text


class TestTheCommittedDockerfile:
    def test_the_root_dockerfile_copies_assets_by_their_checkout_path(self):
        """The control: the rewrite has something to do. A Dockerfile that already
        named bare files would make the assertions below vacuous."""
        sources = [
            s for _line, found in _copy_sources(DOCKERFILE.read_text()) for s in found
        ]
        assert any(s.startswith("automated_security_helper/assets/") for s in sources)

    def test_every_staged_copy_source_is_inside_the_assets_context(self, monkeypatch):
        hook = _load_hook(monkeypatch)
        staged = hook.staged_dockerfile_text(DOCKERFILE.read_text())
        staged_names = {name for _rel, name in hook.DOCKERFILE_STAGED_PACKAGE_FILES}
        outside = [
            (line, source)
            for line, sources in _copy_sources(staged)
            for source in sources
            if source != "." and ("/" in source or source.startswith("automated_"))
        ]
        assert outside == [], (
            "these COPY sources of the staged assets/Dockerfile name a path the "
            f"assets build context does not contain: {outside}"
        )
        assert any(
            source in staged_names
            for _line, sources in _copy_sources(staged)
            for source in sources
        ), "the staged package files are no longer copied by their staged names"

    def test_the_gemfile_lock_is_copied_by_its_bare_name(self, monkeypatch):
        hook = _load_hook(monkeypatch)
        staged = hook.staged_dockerfile_text(DOCKERFILE.read_text())
        gemfile_lines = [
            line for line, sources in _copy_sources(staged) if "Gemfile.lock" in sources
        ]
        assert gemfile_lines, "the cfn-nag step no longer copies Gemfile.lock"
        assert "automated_security_helper" not in gemfile_lines[0]
