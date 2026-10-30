# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH's own install record is read from the right distribution, and a hint names
what it should.

Each test pins one change in ``utils/ash_install.py``:

* a ``packages_distributions`` mapping holding only None (a dist-info with no
  METADATA) no longer counts as a located distribution, so the install-location
  strategy runs;
* where two dist-infos carry one name, the one that ships this module is read,
  not whichever ``sys.path`` lists first, and its requirements alone are read;
* an extra's requirement keeps its environment marker clauses and loses only the
  ``extra == "..."`` clause;
* an ssh URL's user name is kept, an http(s) one's is stripped, and a remote
  archive's query (a presigned URL's credential) is dropped;
* a VCS record naming a local clone that is gone is unusable, and a local path
  this process cannot stat is unusable rather than an error.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePath
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.utils import ash_install

pytestmark = pytest.mark.unit


class TestNoneIsNotALocatedDistribution:
    def test_a_none_mapping_falls_through_to_the_location_strategy(self, monkeypatch):
        monkeypatch.setattr(
            ash_install,
            "packages_distributions",
            lambda: {ash_install._ROOT_PACKAGE: [None]},
        )
        monkeypatch.setattr(ash_install, "distributions", lambda: iter([]))
        located = ash_install._distributions_declaring_this_module(
            ash_install._ROOT_PACKAGE
        )
        assert None not in located
        assert located == []

    def test_a_real_name_is_still_returned(self, monkeypatch):
        """The control."""
        monkeypatch.setattr(
            ash_install,
            "packages_distributions",
            lambda: {ash_install._ROOT_PACKAGE: [None, "ash-fork"]},
        )
        assert ash_install._distributions_declaring_this_module(
            ash_install._ROOT_PACKAGE
        ) == ["ash-fork"]


def _dist(name: str, *, ships_here: bool, requires=None, direct_url=None):
    """A distribution object as importlib.metadata shapes one."""
    here = Path(ash_install.__file__).resolve()
    entry = PurePath("automated_security_helper/utils/ash_install.py")
    located = here if ships_here else here.parent / "elsewhere" / "ash_install.py"

    def read_text(filename):
        assert filename == "direct_url.json"
        return direct_url

    return SimpleNamespace(
        name=name,
        files=[entry],
        locate_file=lambda _entry: located,
        read_text=read_text,
        requires=requires,
    )


class TestTheDistributionThatShipsThisModuleIsRead:
    def test_the_shipping_copy_is_chosen_over_a_stale_one_first_on_sys_path(
        self, monkeypatch
    ):
        stale = _dist("ash", ships_here=False)
        current = _dist("ash", ships_here=True)
        monkeypatch.setattr(ash_install, "_same_named", lambda name: [stale, current])
        assert ash_install._distributions_to_read("ash") == [current]

    def test_the_record_read_is_the_shipping_copys(self, monkeypatch):
        stale = _dist(
            "ash",
            ships_here=False,
            direct_url=json.dumps({"url": "https://example.invalid/stale.tar.gz"}),
        )
        current = _dist(
            "ash",
            ships_here=True,
            direct_url=json.dumps(
                {
                    "url": "https://github.com/awslabs/automated-security-helper",
                    "vcs_info": {"vcs": "git", "commit_id": "a" * 40},
                }
            ),
        )
        monkeypatch.setattr(ash_install, "_same_named", lambda name: [stale, current])
        monkeypatch.setattr(
            ash_install, "_distributions_declaring_this_module", lambda _root: ["ash"]
        )
        record = ash_install._direct_url()
        assert record["vcs_info"]["commit_id"] == "a" * 40

    def test_only_the_shipping_copys_requirements_are_read(self, monkeypatch):
        stale = _dist(
            "ash", ships_here=False, requires=["aws-cdk-lib<2; extra == 'cdk'"]
        )
        current = _dist(
            "ash", ships_here=True, requires=["aws-cdk-lib>=2.100; extra == 'cdk'"]
        )
        monkeypatch.setattr(ash_install, "_same_named", lambda name: [stale, current])
        monkeypatch.setattr(
            ash_install, "_distributions_declaring_this_module", lambda _root: ["ash"]
        )
        assert ash_install.extra_requirements_from_metadata("cdk") == [
            "aws-cdk-lib>=2.100"
        ]

    def test_with_no_distribution_objects_the_by_name_read_still_serves(
        self, monkeypatch
    ):
        """The control: the shape the existing tests replace."""
        monkeypatch.setattr(ash_install, "_same_named", lambda name: [])
        monkeypatch.setattr(
            ash_install, "_distributions_declaring_this_module", lambda _root: ["ash"]
        )
        with patch.object(
            ash_install, "requires", return_value=["b>=1; extra == 'cdk'"]
        ):
            assert ash_install.extra_requirements_from_metadata("cdk") == ["b>=1"]


class TestTheExtraClauseAloneIsRemoved:
    def test_an_environment_clause_is_kept(self):
        assert (
            ash_install._without_extra_clause(
                'tomli; python_version < "3.11" and extra == "cdk"', "cdk"
            )
            == 'tomli; python_version < "3.11"'
        )
        assert (
            ash_install._without_extra_clause(
                "tomli; extra == 'cdk' and python_version < '3.11'", "cdk"
            )
            == "tomli; python_version < '3.11'"
        )

    def test_a_marker_that_is_only_the_extra_is_dropped(self):
        assert (
            ash_install._without_extra_clause('b>=1; extra == "cdk"', "cdk") == "b>=1"
        )

    def test_a_disjunction_is_dropped_whole_as_before(self):
        assert (
            ash_install._without_extra_clause(
                'c; extra == "cdk" or python_version < "3.9"', "cdk"
            )
            == "c"
        )

    def test_the_kept_clause_reaches_the_declared_list(self, monkeypatch):
        monkeypatch.setattr(ash_install, "_same_named", lambda name: [])
        monkeypatch.setattr(
            ash_install, "_distributions_declaring_this_module", lambda _root: ["ash"]
        )
        with patch.object(
            ash_install,
            "requires",
            return_value=['tomli>=1; python_version < "3.11" and extra == "cdk"'],
        ):
            assert ash_install.extra_requirements_from_metadata("cdk") == [
                'tomli>=1; python_version < "3.11"'
            ]


class TestCredentialsInHints:
    def test_an_ssh_user_name_is_kept(self):
        assert (
            ash_install._without_credentials("ssh://deploy@git.example/repo.git")
            == "ssh://deploy@git.example/repo.git"
        )

    def test_an_http_user_name_alone_is_stripped(self):
        """The control: over http(s) a lone user name can be a token."""
        assert (
            ash_install._without_credentials("https://ghp_token@github.com/x/y.git")
            == "https://github.com/x/y.git"
        )

    def test_an_ssh_password_is_still_stripped(self):
        assert (
            ash_install._without_credentials("ssh://deploy:secret@git.example/repo.git")
            == "ssh://git.example/repo.git"
        )

    def test_a_remote_archives_query_is_dropped(self):
        assert (
            ash_install._remote_archive(
                "https://bucket.example/ash.tar.gz?X-Amz-Signature=abc&X-Amz-Credential=k"
            )
            == "https://bucket.example/ash.tar.gz"
        )


class TestRecordedSources:
    def test_a_vcs_record_naming_a_clone_that_is_gone_is_unusable(self, tmp_path):
        gone = tmp_path / "clone"
        record = {
            "url": gone.as_uri(),
            "vcs_info": {"vcs": "git", "commit_id": "b" * 40},
        }
        assert ash_install._recorded_source(record) is None

    def test_a_vcs_record_naming_a_clone_that_exists_is_used(self, tmp_path):
        """The control."""
        clone = tmp_path / "clone"
        clone.mkdir()
        record = {
            "url": clone.as_uri(),
            "vcs_info": {"vcs": "git", "commit_id": "b" * 40},
        }
        assert ash_install._recorded_source(record) == (
            "url",
            f"git+{clone.as_uri()}@{'b' * 40}",
        )

    def test_a_path_this_process_cannot_stat_is_unusable_not_an_error(
        self, tmp_path, monkeypatch
    ):
        project = tmp_path / "project"
        project.mkdir()
        real_is_dir = Path.is_dir

        def _is_dir(self, *args, **kwargs):
            if self == project:
                raise PermissionError(13, "Permission denied", str(self))
            return real_is_dir(self, *args, **kwargs)

        monkeypatch.setattr(Path, "is_dir", _is_dir)
        record = {"url": project.as_uri(), "dir_info": {"editable": True}}
        assert ash_install._recorded_source(record) is None
