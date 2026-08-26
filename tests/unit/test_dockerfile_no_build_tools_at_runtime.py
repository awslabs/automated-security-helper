# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A compiler must not ship in the runtime image.

Why this file exists
--------------------
``build-essential`` and ``ruby-dev`` were installed in the ``core`` stage, and
both ``ci`` and ``non-root`` are ``FROM core``, so a C toolchain and Ruby headers
shipped in every published image. They are needed only to build cfn-nag's gems.
A compiler present at runtime is its own finding in a security scanner, and it is
what CIS Docker hardening guidance is about.

Why deleting the two packages would have broken the image
---------------------------------------------------------
``ruby-dev`` was the *only* Ruby package in the Dockerfile. There was no separate
``ruby``, so the interpreter arrived transitively as its dependency. Dropping the
line would have removed the interpreter cfn-nag runs on, turning an image-size
change into a broken scanner -- and the tests here would not have caught it,
since a Dockerfile is only text to them. That is why the first assertion is that
``ruby`` is installed in its own right: it has to be a manually-installed package
so that purging ``ruby-dev`` and running ``apt-get autoremove`` cannot take it.

Why the purge must share a layer with the install
------------------------------------------------
Docker layers are additive. Purging in a *later* ``RUN`` removes the files from
the union filesystem, so the runtime container no longer has a compiler, but the
earlier layer still carries them and the image is no smaller. Installing, using
and purging in one ``RUN`` means they never land in any layer. The second
assertion enforces that rather than merely checking a purge happens somewhere.

Why static assertions
---------------------
Building the image needs minutes and a working OCI runtime, so it cannot happen
in the unit suite. CI does build it, and the container matrix is what proves
cfn-nag still runs; these tests guard the structural property that a later edit
would quietly undo.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"

BUILD_ONLY_PACKAGES = ("build-essential", "ruby-dev")


@pytest.fixture(scope="module")
def dockerfile_text() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _run_blocks(text: str):
    """Yield each RUN instruction with its line continuations joined."""
    blocks = []
    current = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if current is not None:
            current.append(stripped)
            if not stripped.endswith("\\"):
                blocks.append(" ".join(current))
                current = None
            continue
        if re.match(r"^RUN\b", stripped):
            if stripped.endswith("\\"):
                current = [stripped]
            else:
                blocks.append(stripped)
    if current:
        blocks.append(" ".join(current))
    return blocks


def test_ruby_interpreter_is_installed_in_its_own_right(dockerfile_text):
    """Otherwise purging ruby-dev takes the interpreter cfn-nag needs with it.

    Scoped to a persistent apt-get install rather than the whole file. Searching
    the file text passed against unmodified main, because the word "ruby" also
    appears in a layer-caching comment -- a test that a comment can satisfy is
    worse than no test.
    """
    persistent = [
        block
        for block in _run_blocks(dockerfile_text)
        if "apt-get install" in block
        and "apt-get purge" not in block
        and "apt-get autoremove" not in block
    ]

    # A bare `ruby` package name, not the `ruby-dev` / `ruby3.1-dev` spellings.
    bare_ruby = re.compile(r"(?<![\w./-])ruby(?![\w-])")
    assert any(bare_ruby.search(block) for block in persistent), (
        "No standalone `ruby` package is installed in a layer that keeps it. "
        "ruby-dev used to supply the interpreter transitively, so removing it "
        "without installing ruby explicitly leaves cfn-nag with no Ruby to run "
        "on. It also has to be manually installed so apt-get autoremove cannot "
        "collect it."
    )


@pytest.mark.parametrize("package", BUILD_ONLY_PACKAGES)
def test_build_only_package_is_purged_in_the_layer_that_installs_it(
    dockerfile_text, package
):
    installing = [
        block
        for block in _run_blocks(dockerfile_text)
        if package in block and "apt-get install" in block
    ]

    assert installing, (
        f"No RUN installs {package}. If cfn-nag no longer needs it at build "
        "time, drop it from BUILD_ONLY_PACKAGES in this test rather than "
        "leaving an assertion that cannot fail."
    )

    for block in installing:
        assert "apt-get purge" in block or "apt-get autoremove" in block, (
            f"{package} is installed in a RUN that never removes it, so it "
            "persists into the runtime image. Docker layers are additive: "
            "purging in a later RUN hides the files but the layer still carries "
            "them. Install, use and purge in one RUN."
        )


@pytest.mark.parametrize("package", BUILD_ONLY_PACKAGES)
def test_build_only_package_is_absent_from_the_persistent_apt_install(
    dockerfile_text, package
):
    """The base install layer is never purged, so nothing build-only belongs in it."""
    persistent = [
        block
        for block in _run_blocks(dockerfile_text)
        if "apt-get install" in block
        and "apt-get purge" not in block
        and "apt-get autoremove" not in block
    ]

    offenders = [block for block in persistent if package in block]

    assert not offenders, (
        f"{package} appears in an apt-get install that is never purged, so it "
        f"ships at runtime. Offending RUN: {offenders[0][:160]}"
    )


def test_cfn_nag_is_still_installed(dockerfile_text):
    """Guard against 'fixing' this by dropping the gem build altogether."""
    assert "bundle install" in dockerfile_text, (
        "bundle install is gone, so cfn-nag would not be installed. Removing the "
        "build tools must not mean removing what they were there to build."
    )
