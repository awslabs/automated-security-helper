# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""version_management: failures that stayed silent or crashed the package import.

Why this file exists
--------------------
Four behaviors of ``automated_security_helper.utils.version_management`` were wrong
in ways the checkout-first tests do not reach:

* ``get_version_from_pyproject`` caught every exception and returned None, so a
  pyproject.toml that would not parse gave a version of "unknown" with no message
  saying which file was at fault.
* ``get_version`` runs when ``automated_security_helper`` is imported. Its last
  step, ``importlib.metadata.version``, was guarded against
  ``PackageNotFoundError`` only, so a distribution record that exists but cannot be
  read raised from ``import automated_security_helper`` itself.
* ``update_version_in_pyproject`` wrote the new version into a TOML string as
  given. ``scripts/version_bump.py`` accepts ``1.2.3-<anything>``, so a suffix with
  a double quote or a backslash was written into pyproject.toml and the function
  returned True over a file that no longer parsed or named another version. It also
  edited whatever pyproject.toml sat at the default root, which for an installed copy
  is the directory that holds site-packages, whoever's file that was.
* The same function read the file in text mode with universal newlines, so a CRLF
  pyproject.toml came back out with LF endings (and an LF one came out CRLF on
  Windows), which a version bump showed as a change to every line.

What is asserted
----------------
Each class pins one of them. The write tests build their own tree under
``tmp_path``; nothing reads or writes this repository's pyproject.toml.
"""

from __future__ import annotations

import importlib.metadata
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.utils import version_management
from automated_security_helper.utils.version_management import (
    get_version,
    get_version_from_pyproject,
    update_version_in_pyproject,
)

pytestmark = pytest.mark.unit

MODULE = "automated_security_helper.utils.version_management"
NAME = "automated-security-helper"


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def warnings_logged():
    """The records the module's own logger receives at WARNING or above."""
    logger = version_management._LOGGER
    handler = _Collect()
    old_level, old_disabled = logger.level, logger.disabled
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    logger.disabled = False
    try:
        yield handler.records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
        logger.disabled = old_disabled


class TestAnUnreadablePyprojectSaysSo:
    def test_a_malformed_file_is_named_in_a_warning(self, tmp_path, warnings_logged):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(f'[project\nname = "{NAME}"\n', encoding="utf-8")

        assert get_version_from_pyproject(tmp_path) is None

        messages = [r.getMessage() for r in warnings_logged]
        assert len(messages) == 1, messages
        assert str(pyproject) in messages[0]

    def test_a_missing_file_is_not_a_warning(self, tmp_path, warnings_logged):
        assert get_version_from_pyproject(tmp_path) is None
        assert warnings_logged == []

    def test_another_projects_file_is_not_a_warning(self, tmp_path, warnings_logged):
        tmp_path.joinpath("pyproject.toml").write_text(
            '[project]\nname = "some-other-project"\nversion = "9.9.9"\n',
            encoding="utf-8",
        )
        assert get_version_from_pyproject(tmp_path) is None
        assert warnings_logged == []


class TestAnUnreadableDistributionDoesNotBreakTheImport:
    @pytest.mark.parametrize(
        "error",
        [OSError("cannot read METADATA"), ValueError("bad header"), TypeError("none")],
        ids=["oserror", "valueerror", "typeerror"],
    )
    def test_get_version_reports_unknown(self, error):
        with (
            patch(f"{MODULE}.get_version_from_pyproject", return_value=None),
            patch(f"{MODULE}.importlib.metadata.distributions", return_value=iter([])),
            patch(f"{MODULE}.importlib.metadata.version", side_effect=error),
        ):
            assert get_version() == "unknown"

    def test_a_missing_distribution_is_still_unknown(self):
        with (
            patch(f"{MODULE}.get_version_from_pyproject", return_value=None),
            patch(f"{MODULE}.importlib.metadata.distributions", return_value=iter([])),
            patch(
                f"{MODULE}.importlib.metadata.version",
                side_effect=importlib.metadata.PackageNotFoundError(NAME),
            ),
        ):
            assert get_version() == "unknown"


def _pyproject(root: Path, version: str = "1.2.3", name: str = NAME) -> Path:
    path = root / "pyproject.toml"
    path.write_text(
        f'[project]\nname = "{name}"\nversion = "{version}"\n\n'
        f'[tool.commitizen]\nversion = "{version}"\n',
        encoding="utf-8",
    )
    return path


class TestAVersionThatIsNotATomlStringIsRefused:
    @pytest.mark.parametrize(
        "bad_version",
        [
            '1.2.3-"quoted',
            "1.2.3-\\d",
            "1.2.3-\\n",
            "1.2.3-\nextra = 1",
        ],
        ids=["double-quote", "bad-escape", "newline-escape", "line-break"],
    )
    def test_the_file_is_left_as_it_was(self, tmp_path, bad_version):
        pyproject = _pyproject(tmp_path)
        before = pyproject.read_bytes()

        assert update_version_in_pyproject(bad_version, project_root=tmp_path) is False

        assert pyproject.read_bytes() == before
        assert [p.name for p in tmp_path.iterdir()] == ["pyproject.toml"]

    def test_a_prerelease_suffix_is_still_written(self, tmp_path):
        pyproject = _pyproject(tmp_path)

        assert update_version_in_pyproject("2.0.0-rc.1", project_root=tmp_path) is True

        text = pyproject.read_text(encoding="utf-8")
        assert text.count('version = "2.0.0-rc.1"') == 2, text


class TestAnotherProjectsPyprojectIsNotEdited:
    def test_an_explicit_root_with_another_name_is_refused(self, tmp_path):
        pyproject = _pyproject(tmp_path, name="some-other-project")
        before = pyproject.read_bytes()

        assert update_version_in_pyproject("2.0.0", project_root=tmp_path) is False

        assert pyproject.read_bytes() == before

    def test_the_default_root_with_another_name_is_refused(self, tmp_path):
        # An installed copy's default root is the directory above the package.
        pyproject = _pyproject(tmp_path, name="some-other-project")
        before = pyproject.read_bytes()

        with patch(f"{MODULE}.get_project_root", return_value=tmp_path):
            assert update_version_in_pyproject("2.0.0") is False

        assert pyproject.read_bytes() == before

    def test_a_spelling_of_the_name_that_pep_503_equates_is_this_project(
        self, tmp_path
    ):
        pyproject = _pyproject(tmp_path, name="Automated_Security.Helper")

        assert update_version_in_pyproject("2.0.0", project_root=tmp_path) is True

        assert pyproject.read_text(encoding="utf-8").count('version = "2.0.0"') == 2


class TestLineEndingsSurviveTheRewrite:
    def test_crlf_stays_crlf(self, tmp_path):
        pyproject = _pyproject(tmp_path)
        pyproject.write_bytes(pyproject.read_bytes().replace(b"\n", b"\r\n"))

        assert update_version_in_pyproject("2.0.0", project_root=tmp_path) is True

        data = pyproject.read_bytes()
        assert data.count(b'version = "2.0.0"') == 2, data
        assert data.count(b"\r\n") == data.count(b"\n") > 0, data

    def test_lf_stays_lf(self, tmp_path):
        pyproject = _pyproject(tmp_path)

        assert update_version_in_pyproject("2.0.0", project_root=tmp_path) is True

        data = pyproject.read_bytes()
        assert data.count(b'version = "2.0.0"') == 2, data
        assert b"\r" not in data, data
