# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Four judgments of ``config/plugin_module_trust.py``.

* With no root at all (the working directory gone), a client-supplied config
  may name only the trusted list's modules. ASH's own modules are exempt, but
  the exemption never covers a package that sends findings off the host: that
  one needs the trusted list, as the judged path already requires.
* ASH's own package is exempt from the in-tree judgment only where a location
  sits inside the package AS NAMED: an in-tree entry that reaches the installed
  package through a link the repository placed is judged by where it sits.
* A module location inside an ``also_scanned`` tree is refused as one inside the
  scan root's trees is.
* The operator's off-host plugin packages stay loaded when a repository's
  config leaves them out of ``ash_plugin_modules``: a reporter whose module is
  not imported never runs, and reporter_trust says such a config may not turn
  the operator's off-host reporters off.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import automated_security_helper
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.plugin_module_trust import (
    confine_plugin_modules,
    refusal_reason,
)
from automated_security_helper.core.exceptions import ASHConfigSourceError
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

AWS_PLUGINS = "automated_security_helper.plugin_modules.ash_aws_plugins"
OWN_BUILTIN = "automated_security_helper.plugin_modules.ash_builtin"
LINKED = "linkedown_ash_plugins"
ALSO = "recalso_ash_plugins"


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    for name in (LINKED, ALSO):
        monkeypatch.delitem(sys.modules, name, raising=False)


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks are not available here: {error}")


def test_a_rootless_client_config_may_not_add_an_off_host_package():
    config = AshConfig.model_validate({"ash_plugin_modules": [AWS_PLUGINS]})

    with pytest.raises(ASHConfigSourceError):
        confine_plugin_modules(
            config,
            AshConfig(),
            [],
            None,
            [],
            no_scanned_tree=True,
            untrusted=True,
            checkout_membership=True,
            mixed_membership=False,
            given_root_membership=False,
            undecided_membership=False,
        )


def test_a_rootless_client_config_keeps_an_off_host_package_the_trusted_list_names():
    config = AshConfig.model_validate({"ash_plugin_modules": [AWS_PLUGINS]})
    trusted = AshConfig.model_validate({"ash_plugin_modules": [AWS_PLUGINS]})

    confine_plugin_modules(
        config,
        trusted,
        [],
        None,
        [],
        no_scanned_tree=True,
        untrusted=True,
        checkout_membership=True,
        mixed_membership=False,
        given_root_membership=False,
        undecided_membership=False,
    )

    assert config.ash_plugin_modules == [AWS_PLUGINS]


def test_an_in_tree_link_into_ashs_own_package_is_judged_where_it_sits(
    tmp_path, monkeypatch
):
    own = Path(automated_security_helper.__file__).resolve().parent
    repo = tmp_path / "repo"
    repo.mkdir()
    _symlink(repo / LINKED, own / "plugin_modules" / "ash_builtin")
    monkeypatch.syspath_prepend(str(repo))

    # The control: ASH's own package under its own name stays exempt.
    assert refusal_reason(OWN_BUILTIN, repo) is None
    reason = refusal_reason(LINKED, repo)
    assert reason is not None and "scanned tree" in reason, reason


def test_a_module_inside_an_also_scanned_tree_is_refused(tmp_path, monkeypatch):
    results = tmp_path / "results-repo"
    package = results / ALSO
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("PLANTED = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(results))
    scan_root = tmp_path / "scan"
    scan_root.mkdir()

    # The control: judged against the scan root alone, the module is outside.
    assert refusal_reason(ALSO, scan_root) is None
    reason = refusal_reason(ALSO, scan_root, also_scanned=[results])
    assert reason is not None, reason


def test_the_operators_off_host_package_is_kept_when_the_configs_list_omits_it(
    tmp_path,
):
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    (repo / ".ash").mkdir()
    in_tree = repo / ".ash" / ".ash.yaml"
    in_tree.write_text("project_name: repo\n", encoding="utf-8")
    trusted = AshConfig.model_validate({"ash_plugin_modules": [AWS_PLUGINS]})
    config = AshConfig.model_validate({"project_name": "repo"})

    confine_plugin_modules(
        config,
        trusted,
        [],
        repo,
        [in_tree],
        checkout_membership=True,
        mixed_membership=False,
        given_root_membership=False,
        undecided_membership=False,
    )

    assert config.ash_plugin_modules == [AWS_PLUGINS]
