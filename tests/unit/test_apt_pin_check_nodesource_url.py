# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The apt pin check reads the NodeSource major from the repository URL as well.

Why this file exists
--------------------
``scripts/check_pinned_tool_versions.py`` looks the nodejs pin up in the NodeSource
index of the major the Dockerfile configures. It read that major only from
``NODE_MAJOR``. A Dockerfile that writes ``https://deb.nodesource.com/node_22.x``
straight into its sources line, with no variable, was refused although the major is
right there, and a URL that had drifted from ``NODE_MAJOR`` was looked up under the
variable's major while apt read the URL's.

The major is now read from ``deb.nodesource.com/node_<digits>.x`` and from
``NODE_MAJOR``, in either place. It is refused only when neither names one, or when
the two name different majors.

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


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_check_pinned_apt_nodesource_url", SCRIPT
    )
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_script()


def _labels(tmp_path: Path, body: str) -> list[str]:
    path = tmp_path / "Dockerfile"
    path.write_text(
        "ARG BASE_IMAGE=python:3.12-slim-bookworm\nFROM ${BASE_IMAGE} AS core\n" + body,
        encoding="utf-8",
    )
    return [i.label for i in checker.apt_indexes(path)]


def _nodesource_labels(labels: list[str]) -> list[str]:
    return [label for label in labels if label.startswith("nodesource")]


URL_22 = "https://deb.nodesource.com/node_22.x nodistro main"


class TestTheMajorInTheUrl:
    def test_a_url_with_no_node_major_is_read(self, tmp_path):
        # Red before: only NODE_MAJOR named the major, so this Dockerfile was refused
        # although the URL says node_22.x.
        labels = _labels(tmp_path, f"RUN echo 'deb {URL_22}' > /etc/apt/x.list\n")
        assert _nodesource_labels(labels) == ["nodesource node_22.x"]

    def test_a_url_followed_by_a_path_is_read(self, tmp_path):
        body = "RUN curl -fsSL https://deb.nodesource.com/node_20.x/dists/x\n"
        assert _nodesource_labels(_labels(tmp_path, body)) == ["nodesource node_20.x"]

    def test_the_setup_script_url_names_the_major(self, tmp_path):
        # Red before: only node_<n>.x was read, and NodeSource's own recipe, which
        # fetches setup_<n>.x, was refused as naming no major.
        body = "RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash -\n"
        assert _nodesource_labels(_labels(tmp_path, body)) == ["nodesource node_22.x"]

    def test_a_setup_url_and_a_drifted_variable_are_ambiguous(self, tmp_path):
        body = "RUN NODE_MAJOR=20 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash\n"
        with pytest.raises(checker.PinEnumerationError, match="ambiguous"):
            _labels(tmp_path, body)

    def test_a_setup_script_that_names_no_number_is_still_refused(self, tmp_path):
        """Control: setup_lts.x carries no major to look the nodejs pin up under."""
        body = "RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -\n"
        with pytest.raises(checker.PinEnumerationError, match="NODE_MAJOR"):
            _labels(tmp_path, body)

    def test_a_url_and_the_variable_that_agree_are_one_index(self, tmp_path):
        """Control: naming the major twice is not an ambiguity."""
        body = f"RUN NODE_MAJOR=22 && echo 'deb {URL_22}'\n"
        assert _nodesource_labels(_labels(tmp_path, body)) == ["nodesource node_22.x"]

    def test_a_url_built_from_the_variable_still_uses_the_variable(self, tmp_path):
        """Control: the existing Dockerfile shape, ``node_$NODE_MAJOR.x``."""
        body = (
            "RUN NODE_MAJOR=22; \\\n"
            '    echo "deb https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main"\n'
        )
        assert _nodesource_labels(_labels(tmp_path, body)) == ["nodesource node_22.x"]


class TestTheUrlAndTheVariableDisagree:
    def test_a_drifted_url_is_refused_as_ambiguous(self, tmp_path):
        # Red before: NODE_MAJOR=22 chose node_22.x and the URL's node_20.x, the index
        # apt really reads, was never looked at.
        body = f"RUN NODE_MAJOR=22 && echo 'deb {URL_22.replace('22', '20')}'\n"
        with pytest.raises(checker.PinEnumerationError, match="ambiguous"):
            _labels(tmp_path, body)

    def test_two_urls_with_different_majors_are_refused(self, tmp_path):
        body = f"RUN echo 'deb {URL_22}'\nRUN echo 'deb {URL_22.replace('22', '20')}'\n"
        with pytest.raises(checker.PinEnumerationError, match="ambiguous"):
            _labels(tmp_path, body)


class TestNoMajorAnywhere:
    def test_nodesource_with_an_unreadable_variable_is_still_refused(self, tmp_path):
        """Control: the URL is built from a variable that has no digits."""
        body = (
            "RUN NODE_MAJOR=$WANTED && "
            "echo 'deb https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main'\n"
        )
        with pytest.raises(checker.PinEnumerationError, match="NODE_MAJOR"):
            _labels(tmp_path, body)

    def test_a_url_in_a_comment_does_not_choose_the_major(self, tmp_path):
        """Control: comment lines are not read, as for NODE_MAJOR."""
        body = (
            "# the old repository was https://deb.nodesource.com/node_18.x\n"
            f"RUN NODE_MAJOR=22 && echo 'deb {URL_22}'\n"
        )
        assert _nodesource_labels(_labels(tmp_path, body)) == ["nodesource node_22.x"]

    def test_no_nodesource_at_all_adds_no_index(self, tmp_path):
        """Control: a Dockerfile that never uses NodeSource is not refused."""
        labels = _labels(tmp_path, "RUN apt-get install -y curl=7.88.1-10+deb12u15\n")
        assert _nodesource_labels(labels) == []
