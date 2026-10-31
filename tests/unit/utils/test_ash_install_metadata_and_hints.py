# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reading ASH's own distribution, and the install hints it prints.

* ``packages_distributions`` walks every installed distribution; a broken
  sibling dist-info makes it raise KeyError or TypeError, which the first
  strategy did not catch, so one unrelated package took the command down.
* The install-location strategy accepted any distribution installed from an
  ANCESTOR directory of this module, so an editable project that merely encloses
  an ASH checkout was taken for ASH.
* The printed ``uv pip install`` hints are copied and run where the operator
  stands, usually the scanned repository: ``--no-config`` keeps uv from reading
  that repository's uv configuration, and ``-P`` (3.11 and later) keeps the
  working directory off the ``-m uv`` import path.
"""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import ash_install

pytestmark = pytest.mark.unit


class _Distribution:
    def __init__(self, name: str, project_dir: Path):
        self.metadata = {"Name": name}
        self._url = project_dir.resolve().as_uri()

    def read_text(self, filename: str):
        if filename == "direct_url.json":
            return json.dumps({"url": self._url, "dir_info": {"editable": True}})
        return None


def test_a_broken_sibling_distribution_does_not_take_the_lookup_down(monkeypatch):
    def _raises():
        raise KeyError("Name")

    monkeypatch.setattr(ash_install, "packages_distributions", _raises)
    monkeypatch.setattr(ash_install, "distributions", lambda: iter([]))
    assert ash_install._distributions_declaring_this_module("not-a-package") == []


def test_an_enclosing_editable_project_is_not_taken_for_ash(monkeypatch, tmp_path):
    outer = tmp_path / "workspace"
    checkout = outer / "ash"
    module = checkout / "automated_security_helper" / "utils" / "ash_install.py"
    module.parent.mkdir(parents=True)
    module.write_text("", encoding="utf-8")
    monkeypatch.setattr(ash_install, "__file__", str(module))
    monkeypatch.setattr(ash_install, "packages_distributions", dict)
    monkeypatch.setattr(
        ash_install,
        "distributions",
        lambda: iter(
            [_Distribution("workspace-tools", outer), _Distribution("ash", checkout)]
        ),
    )
    assert ash_install._distributions_declaring_this_module(
        "automated_security_helper"
    ) == ["ash"]


class _MetadatalessDistribution(_Distribution):
    """A .dist-info with no METADATA file: its ``metadata`` reads as None."""

    def __init__(self, project_dir: Path):
        super().__init__("broken", project_dir)
        self.metadata = None


def test_a_sibling_with_no_metadata_does_not_take_the_lookup_down(
    monkeypatch, tmp_path
):
    checkout = tmp_path / "ash"
    module = checkout / "automated_security_helper" / "utils" / "ash_install.py"
    module.parent.mkdir(parents=True)
    module.write_text("", encoding="utf-8")
    monkeypatch.setattr(ash_install, "__file__", str(module))
    monkeypatch.setattr(ash_install, "packages_distributions", dict)
    monkeypatch.setattr(
        ash_install,
        "distributions",
        lambda: iter(
            [_MetadatalessDistribution(tmp_path), _Distribution("ash", checkout)]
        ),
    )
    assert ash_install._distributions_declaring_this_module(
        "automated_security_helper"
    ) == ["ash"]


def test_a_src_layout_project_is_still_found(monkeypatch, tmp_path):
    """The control: the project directory of a src layout is one level higher."""
    checkout = tmp_path / "ash"
    module = checkout / "src" / "automated_security_helper" / "utils" / "ash_install.py"
    module.parent.mkdir(parents=True)
    module.write_text("", encoding="utf-8")
    monkeypatch.setattr(ash_install, "__file__", str(module))
    monkeypatch.setattr(ash_install, "packages_distributions", dict)
    monkeypatch.setattr(
        ash_install, "distributions", lambda: iter([_Distribution("ash", checkout)])
    )
    assert ash_install._distributions_declaring_this_module(
        "automated_security_helper"
    ) == ["ash"]


# The hint is a shell command line, and the interpreter path in it is
# shell-quoted (a space in it, as under a "Program Files" prefix, would
# otherwise split the word): the tests read it back the way a shell would,
# so the positions below hold whatever the path contains.
def _hint_words() -> list:
    return shlex.split(ash_install._uv_pip_install())


def test_the_hint_reads_no_repository_uv_configuration():
    words = _hint_words()
    assert "--no-config" in words
    assert words.index("--no-config") > words.index("install")


def test_the_hint_names_the_running_interpreter_as_one_word():
    words = _hint_words()
    assert words[0] == sys.executable
    assert words.count(sys.executable) == 2, words


@pytest.mark.skipif(sys.version_info < (3, 11), reason="-P exists from Python 3.11")
def test_the_hint_keeps_the_working_directory_off_the_import_path():
    words = _hint_words()
    assert words[1:3] == ["-P", "-m"], words


@pytest.mark.skipif(sys.version_info >= (3, 11), reason="-P exists from Python 3.11")
def test_the_hint_omits_a_flag_this_interpreter_does_not_accept():
    words = _hint_words()
    assert words[1:3] == ["-m", "uv"], words


def test_a_quoted_interpreter_path_reads_back_as_one_word(monkeypatch):
    """A path with a space is quoted into the hint and splits back whole."""
    spaced = "/opt/Program Files/python3"
    # The module's own name for sys, so the interpreter's sys stays untouched.
    monkeypatch.setattr(
        ash_install,
        "sys",
        SimpleNamespace(executable=spaced, version_info=sys.version_info),
    )
    words = shlex.split(ash_install._uv_pip_install())
    assert words[0] == spaced and words.count(spaced) == 2, words
    assert "install" in words and "--no-config" in words


class TestARecordedDirectoryOfTheProject:
    """A record naming a directory INSIDE the project that encloses the module
    (the percent-encoded fixture of the cdk container-deps tests names the
    package's own utils directory) is the project's; an ancestor above the
    project is another project's."""

    MODULE = Path("/work/ash/src/automated_security_helper/utils/ash_install.py")
    ACCEPTED = {Path("/work/ash/src"), Path("/work/ash")}

    def test_a_directory_below_the_root_that_encloses_the_module_is_accepted(self):
        inside = Path("/work/ash/src/automated_security_helper/utils")
        assert ash_install._declares_this_module(inside, self.MODULE, self.ACCEPTED)

    def test_the_install_roots_are_accepted(self):
        for root in self.ACCEPTED:
            assert ash_install._declares_this_module(root, self.MODULE, self.ACCEPTED)

    def test_an_ancestor_above_the_project_is_refused(self):
        """The control: the enclosing monorepo is still another project."""
        for above in (Path("/work"), Path("/")):
            assert not ash_install._declares_this_module(
                above, self.MODULE, self.ACCEPTED
            )

    def test_a_directory_that_does_not_enclose_the_module_is_refused(self):
        assert not ash_install._declares_this_module(
            Path("/work/ash/src/other_package"), self.MODULE, self.ACCEPTED
        )
