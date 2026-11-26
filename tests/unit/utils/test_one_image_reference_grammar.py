# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One image-reference grammar, and every way a reference enters ASH reads it.

A reference reaches grype, syft and trivy from four places: the CLI's
``--image``, the ``run_ash_scan`` API, the MCP ``set_source_image`` tool and an
``ImageLocator`` built in code. The tools read text that is not a reference as
something else -- a leading ``-`` as an option, ``/etc`` or ``../x`` as a
directory to catalog -- so each surface must refuse what the grammar refuses,
and the surfaces must agree. The grammar itself is pinned here once
(``utils/image_reference``); the surface rows live beside each surface's other
rows, and the locator rows are here because the locator is what every surface
builds.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.core.asset import ImageLocator

pytestmark = pytest.mark.unit

DIGEST = "sha256:" + "ab" * 32

#: Real references in every shape the grammar admits.
ACCEPTED = [
    "alpine",
    "alpine:3.20",
    "library/alpine",
    "docker.io/library/alpine:3",
    "registry.example.com/team/app:1.2.3",
    "registry.example.com:5000/team/app",
    "Registry.Example.com/team/app:V1",
    "localhost/app:1",
    "localhost:5000/app",
    "[::1]:5000/app:1",
    "192.0.2.10:5000/team/app",
    f"app@{DIGEST}",
    f"registry.example.com/team/app:1.2@{DIGEST}",
    "app@sha512:" + "c" * 128,
    "a__b/c--d/e.f-g_h",
    # The longest repository path the grammar allows: 255 characters.
    "r/" + "a" * 255,
    # The Docker-in-Docker image: a repository named like a tool scheme is
    # still a reference, and the tools are told it is one (no scheme is read
    # from the text, see image_tool_targets).
    "docker:24-dind",
]

#: What is not a reference, each with a word its refusal must carry.
REFUSED = [
    pytest.param("", "empty", id="empty"),
    pytest.param("   ", "empty", id="whitespace-only"),
    pytest.param("-x", "option", id="leading-dash"),
    pytest.param("--insecure", "option", id="double-dash-flag"),
    # The grammar alone refuses these too; the word is the path reason's own,
    # so a refusal that only names the form does not pass for it.
    pytest.param("/etc", "filesystem path", id="absolute-path"),
    pytest.param("/etc/passwd", "filesystem path", id="absolute-file"),
    pytest.param("./app", "filesystem path", id="dot-relative"),
    pytest.param("../app", "filesystem path", id="dot-dot-relative"),
    pytest.param("~/app", "filesystem path", id="home-relative"),
    pytest.param("~", "filesystem path", id="home"),
    pytest.param("C:\\images\\app", "filesystem path", id="windows-path"),
    pytest.param("app/", "not an image reference", id="trailing-slash"),
    pytest.param("a//b", "not an image reference", id="double-slash"),
    pytest.param("team/../etc", "not an image reference", id="inner-dot-dot"),
    pytest.param("a/./b", "not an image reference", id="inner-dot"),
    pytest.param("Team/App", "not an image reference", id="uppercase-path"),
    pytest.param("dir:/etc", "not an image reference", id="scheme-and-path"),
    pytest.param("app:", "not an image reference", id="empty-tag"),
    pytest.param("app@", "not an image reference", id="empty-digest"),
    pytest.param(":tag", "not an image reference", id="no-name"),
    pytest.param("a b", "whitespace", id="inner-space"),
    pytest.param(" app", "whitespace", id="padded"),
    pytest.param("a\tb", "whitespace", id="tab"),
    pytest.param("repo\x1b[31m:tag", "control", id="escape-sequence"),
    pytest.param("repo:tag" + chr(0x202E), "non-ASCII", id="bidi-override"),
    pytest.param("app@sha256:abc", "digest", id="short-digest"),
    pytest.param("app@md5:" + "0" * 32, "digest", id="unsupported-algorithm"),
    pytest.param("app@sha256:" + "A" * 64, "digest", id="uppercase-digest"),
    pytest.param("a" * 64, "image ID", id="bare-hex-id"),
    pytest.param("r/" + "a" * 256, "255", id="path-too-long"),
    pytest.param("a" * 600, "512", id="far-too-long"),
    # The grammar admits this one (a long registry name, a short path and the
    # longest tag); only the length bound refuses it.
    pytest.param(
        ".".join(["d" * 60] * 7) + "/team/app:" + "t" * 128,
        "512",
        id="long-registry-otherwise-valid",
    ),
]


class TestTheGrammar:
    @pytest.mark.parametrize("ref", ACCEPTED)
    def test_a_reference_has_no_problem(self, ref):
        from automated_security_helper.utils.image_reference import (
            image_reference_problem,
        )

        assert image_reference_problem(ref) is None

    @pytest.mark.parametrize("ref, word", REFUSED)
    def test_a_non_reference_is_named_with_its_reason(self, ref, word):
        from automated_security_helper.utils.image_reference import (
            image_reference_problem,
        )

        problem = image_reference_problem(ref)
        assert problem is not None
        assert word in problem

    def test_the_checked_form_raises_and_names_the_value(self):
        from automated_security_helper.utils.image_reference import (
            checked_image_reference,
        )

        assert checked_image_reference("alpine:3.20") == "alpine:3.20"
        with pytest.raises(ValueError, match="'/etc'"):
            checked_image_reference("/etc")

    def test_a_non_string_is_no_reference(self):
        from automated_security_helper.utils.image_reference import (
            image_reference_problem,
        )

        assert image_reference_problem(None) is not None
        assert image_reference_problem(42) is not None


class TestTheLocatorReadsTheGrammar:
    """Every surface builds an ImageLocator, so the locator is the floor."""

    @pytest.mark.parametrize("ref", ACCEPTED)
    def test_a_reference_builds_a_locator(self, ref):
        assert ImageLocator(ref=ref).ref == ref

    @pytest.mark.parametrize("ref, word", REFUSED)
    def test_a_non_reference_builds_none(self, ref, word):
        with pytest.raises(ValidationError, match=word):
            ImageLocator(ref=ref)
