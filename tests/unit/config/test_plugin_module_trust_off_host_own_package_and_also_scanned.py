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
  scan root's trees is, and ``resolve_config`` and ``confine_to_trusted_base``
  pass the value on to the confinement.
* The operator's off-host plugin packages stay loaded when a repository's
  config leaves them out of ``ash_plugin_modules``: a reporter whose module is
  not imported never runs, and reporter_trust says such a config may not turn
  the operator's off-host reporters off.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

import automated_security_helper
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.plugin_module_trust import (
    confine_plugin_modules,
    refusal_reason,
)
from automated_security_helper.config.resolve_config import (
    confine_to_trusted_base,
    resolve_config,
)
from automated_security_helper.core.exceptions import ASHConfigSourceError
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

AWS_PLUGINS = "automated_security_helper.plugin_modules.ash_aws_plugins"
OWN_BUILTIN = "automated_security_helper.plugin_modules.ash_builtin"
LINKED = "linkedown_ash_plugins"
ALSO = "recalso_ash_plugins"
RESULTS_MODULE = "resultsrepo_ash_plugins"
SITE_MODULE = "siteonly_ash_plugins"


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    for name in (LINKED, ALSO, RESULTS_MODULE, SITE_MODULE):
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


def _package(root: Path, name: str) -> None:
    package = root / name
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")


def _outside_every_checkout(tmp_path: Path) -> None:
    # A basetemp inside a repository would make the keeps below fail for a
    # reason that is not the one under test.
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )


def _repository_naming(tmp_path: Path, *modules: str) -> Path:
    """A scanned repository whose own config file names *modules*."""
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    config_file = repo / ".ash" / ".ash.yaml"
    config_file.parent.mkdir(parents=True)
    config_file.write_text(
        "project_name: x\nash_plugin_modules:\n"
        + "".join(f"  - {name}\n" for name in modules),
        encoding="utf-8",
    )
    return repo


def test_resolve_config_refuses_a_module_installed_in_an_also_scanned_tree(
    tmp_path, monkeypatch, caplog
):
    """``ash report`` passes the results' repository as ``also_scanned``: a
    module installed in it is the scanned party's, so the repository's config
    may not import it, as it may not import one inside the scan root."""
    _outside_every_checkout(tmp_path)
    results = tmp_path / "results-repo"
    _package(results, RESULTS_MODULE)
    site = tmp_path / "site"
    _package(site, SITE_MODULE)
    monkeypatch.syspath_prepend(str(results))
    monkeypatch.syspath_prepend(str(site))
    repo = _repository_naming(tmp_path, RESULTS_MODULE, SITE_MODULE)

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=repo, also_scanned=[results])

    assert RESULTS_MODULE not in (config.ash_plugin_modules or [])
    assert SITE_MODULE in (config.ash_plugin_modules or [])
    assert "Ignoring ash_plugin_modules entries" in caplog.text
    assert "it resolves inside the scanned tree" in caplog.text


def test_resolve_config_without_also_scanned_keeps_the_same_module(
    tmp_path, monkeypatch
):
    """The control: the same module and the same repository, with no
    ``also_scanned``, keep today's answer, so the refusal above is the
    value's."""
    _outside_every_checkout(tmp_path)
    results = tmp_path / "results-repo"
    _package(results, RESULTS_MODULE)
    monkeypatch.syspath_prepend(str(results))
    repo = _repository_naming(tmp_path, RESULTS_MODULE)

    config = resolve_config(source_dir=repo)

    assert RESULTS_MODULE in (config.ash_plugin_modules or [])


def test_confine_to_trusted_base_passes_also_scanned_to_the_module_step(
    tmp_path, monkeypatch
):
    _outside_every_checkout(tmp_path)
    results = tmp_path / "results-repo"
    _package(results, RESULTS_MODULE)
    site = tmp_path / "site"
    _package(site, SITE_MODULE)
    monkeypatch.syspath_prepend(str(results))
    monkeypatch.syspath_prepend(str(site))
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    in_tree = [repo / ".ash" / ".ash.yaml"]
    modules = {"ash_plugin_modules": [RESULTS_MODULE, SITE_MODULE]}

    # The control: with no also_scanned the results' module is kept.
    kept = AshConfig.model_validate(modules)
    confine_to_trusted_base(kept, AshConfig(), [], repo, in_tree)
    assert RESULTS_MODULE in kept.ash_plugin_modules

    confined = AshConfig.model_validate(modules)
    confine_to_trusted_base(
        confined, AshConfig(), [], repo, in_tree, also_scanned=[results]
    )

    assert RESULTS_MODULE not in confined.ash_plugin_modules
    assert SITE_MODULE in confined.ash_plugin_modules
