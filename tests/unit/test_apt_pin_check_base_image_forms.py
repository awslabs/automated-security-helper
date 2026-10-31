# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The apt pin check reads the Debian codename from dated and digest-pinned tags.

Why this file exists
--------------------
``scripts/check_pinned_tool_versions.py`` names the apt suites to look pins up in from
the tag of ``ARG BASE_IMAGE``. It took the last ``-`` part of the tag that is not a
variant, so two common forms of a pinned base image were refused or misread:

* ``debian:bookworm-20241016-slim`` is the codename, a build date and a variant. With
  the variant removed the last part was ``20241016``, which is no codename, and the
  run exited 2.
* ``python:3.12-slim-bookworm@sha256:<digest>`` carries a digest after the tag. The
  pattern matched up to the last colon, so the hex digest was read as the tag.

The codename is now the last lowercase word among the tag's ``-`` parts that is not a
variant, and a digest is cut off before the tag is looked for. A reference with no tag
at all (a bare name, a digest only, a registry port without a tag) is still refused.

No network: the Dockerfiles are written under ``tmp_path``.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"

DIGEST = "sha256:" + "0123456789abcdef" * 4


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_check_pinned_apt_base_image_forms", SCRIPT
    )
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_script()


def _dockerfile(tmp_path: Path, base: str) -> Path:
    path = tmp_path / "Dockerfile"
    path.write_text(
        f"ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}} AS core\n", encoding="utf-8"
    )
    return path


def _labels(tmp_path: Path, base: str) -> list[str]:
    return [i.label for i in checker.apt_indexes(_dockerfile(tmp_path, base))]


class TestTheCodenameIsTheSuite:
    @pytest.mark.parametrize(
        ("base", "codename"),
        [
            ("debian:bookworm-20241016-slim", "bookworm"),
            ("debian:bookworm-20241016", "bookworm"),
            ("python:3.12.7-slim-bookworm", "bookworm"),
            (f"python:3.12-slim-bookworm@{DIGEST}", "bookworm"),
            (
                f"public.ecr.aws/docker/library/python:3.12-slim-bullseye@{DIGEST}",
                "bullseye",
            ),
            (f"debian:bookworm-20241016-slim@{DIGEST}", "bookworm"),
        ],
    )
    def test_a_date_and_a_digest_are_not_the_codename(self, tmp_path, base, codename):
        # Red before: a dated tag named the suite "20241016", and a digest was read
        # as the tag, so both were refused as having no codename.
        labels = _labels(tmp_path, base)
        assert labels[:3] == [codename, f"{codename}-updates", f"{codename}-security"]

    @pytest.mark.parametrize(
        "base",
        [
            "python:3.12-slim-bookworm",
            "debian:bookworm-slim",
            "localhost:5000/library/python:3.12-slim-bookworm",
        ],
    )
    def test_the_plain_forms_are_read_as_before(self, tmp_path, base):
        """Control: a tag with no date or digest, a registry port included."""
        assert _labels(tmp_path, base)[0] == "bookworm"


class TestAReferenceWithNoCodenameIsRefused:
    @pytest.mark.parametrize(
        "base",
        [
            "python",
            f"python@{DIGEST}",
            "localhost:5000/python",
            "python:3.12",
            "python:3.12-slim",
            f"python:3.12-slim@{DIGEST}",
            "debian:20241016-slim",
        ],
    )
    def test_no_tag_word_means_no_codename(self, tmp_path, base):
        """Control: a digest or a date alone must not stand in for a suite."""
        with pytest.raises(checker.PinEnumerationError, match="codename"):
            checker.apt_indexes(_dockerfile(tmp_path, base))
