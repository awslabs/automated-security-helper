# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool path that leaves the scanned tree through a link inside it is not passed on.

``path_trust.honored_path`` passes a tool its config or plugin file only from
outside the scanned tree. A path inside the tree that is a symbolic link to a
file outside it resolves outside, but the repository chose that file by placing
the link, so it is refused as a file inside the tree is: a link at any depth, a
directory link, or a chain of links that ends outside. A link outside the tree,
and a path that leaves by ``..`` with no link, are passed as before. Each
scanner that takes such a path goes through ``honored_path``: trivy's and
trivy-repo's ignore file and secret config (option and environment variable),
checkov's and ferret's ``config_file``, and detect-secrets' ``file://`` plugins.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.path_trust import (
    honored_path,
    reset_path_refusal_warnings,
)
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.uv_tool_runner import UVToolRunner

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        not hasattr(os, "symlink") or os.name == "nt",
        reason="creates symbolic links, which need privileges on Windows",
    ),
]


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.delenv("TRIVY_IGNOREFILE", raising=False)
    monkeypatch.delenv("TRIVY_SECRET_CONFIG", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    reset_path_refusal_warnings()
    with patch.object(UVToolRunner, "is_uv_available", return_value=False):
        yield
    reset_path_refusal_warnings()


@pytest.fixture
def tree(tmp_path: Path):
    """The scanned tree, and an operator directory beside it."""
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    operator = tmp_path / "operator"
    operator.mkdir()
    return source, operator


def _file(path: Path, text: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _link(link: Path, target: Path) -> Path:
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)
    return link


# ---------------------------------------------------------------------------
# honored_path
# ---------------------------------------------------------------------------


def _layouts(source: Path, operator: Path):
    """Each layout's path as the operator writes it, and whether it is honored."""
    outside = _file(operator / "tool.yaml")
    inside = _file(source / "real.yaml")
    return {
        "in-tree link to an outside file": (
            _link(source / "linked.yaml", outside),
            False,
        ),
        "in-tree directory link to an outside directory": (
            _link(source / "conf", operator) / "tool.yaml",
            False,
        ),
        "chain of in-tree links ending outside": (
            _link(source / "first.yaml", _link(source / "second.yaml", outside)),
            False,
        ),
        "outside link through an in-tree link to an outside file": (
            _link(operator / "via.yaml", _link(source / "relay.yaml", outside)),
            False,
        ),
        "in-tree link to an in-tree file, refused as before": (
            _link(source / "same-tree.yaml", inside),
            False,
        ),
        "a link outside the tree to an outside file": (
            _link(operator / "alias.yaml", outside),
            True,
        ),
        "a path that leaves by .. with no link": (
            Path("..") / operator.name / "tool.yaml",
            True,
        ),
    }


@pytest.mark.parametrize(
    "layout",
    [
        "in-tree link to an outside file",
        "in-tree directory link to an outside directory",
        "chain of in-tree links ending outside",
        "outside link through an in-tree link to an outside file",
        "in-tree link to an in-tree file, refused as before",
        "a link outside the tree to an outside file",
        "a path that leaves by .. with no link",
    ],
)
def test_honored_path_refuses_a_path_that_leaves_through_an_in_tree_link(
    tree, layout: str
) -> None:
    source, operator = tree
    value, honored = _layouts(source, operator)[layout]

    path = honored_path(value, source_dir=source, key="scanners.x.options.config_file")

    if honored:
        assert path == Path(os.path.realpath(source / value))
    else:
        assert path is None


def test_the_refusal_names_the_path_as_written(tree, caplog) -> None:
    import logging

    from automated_security_helper.utils.log import ASH_LOGGER

    source, operator = tree
    link = _link(source / "linked.yaml", _file(operator / "tool.yaml"))

    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        honored_path(link, source_dir=source, key="scanners.x.options.config_file")

    # The link is judged by the name it has in the scanned tree, so the warning
    # names that name and the setting, not the file the link reaches.
    (message,) = [
        r.getMessage()
        for r in caplog.records
        if "scanners.x.options.config_file" in r.getMessage()
    ]
    assert link.as_posix() in message
    assert (operator / "tool.yaml").as_posix() not in message


# ---------------------------------------------------------------------------
# Each scanner that takes such a path
# ---------------------------------------------------------------------------


def _context(source: Path, tmp_path: Path, config) -> PluginContext:
    output = tmp_path / "out"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True, exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=config,
    )


def _trivy_argv(tmp_path: Path, source: Path, scanner_name: str, options=None) -> list:
    """The argv ``trivy`` or ``trivy-repo`` would run with ``options`` set.

    The config is built from no file in the scanned tree, so ``options`` are the
    operator's (``utils/config_trust.record_provenance``): a value refused here is
    refused for where its path leads, not for who set it.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        TrivyScanner,
        TrivyScannerConfig,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
        TrivyRepoScannerConfig,
    )

    config = AshConfig()
    record_provenance(config, in_tree=[])
    context = _context(source, tmp_path, config)
    if scanner_name == "trivy":
        fs = TrivyScanner(
            context=context, config=TrivyScannerConfig(options=options or {})
        )
        final_args, _, _ = fs._execute_scan(source, "source", [])
        return [str(a) for a in final_args]
    scanner = TrivyRepoScanner(
        context=context,
        config=TrivyRepoScannerConfig(options=options or {}),
    )
    scanner.dependencies_satisfied = True
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_run_subprocess", return_value={}) as run,
    ):
        scanner.scan(target=source, target_type="source")
    return [str(a) for a in run.call_args.kwargs["command"]]


def _flag(argv: list, name: str) -> Path:
    values = [a.split("=", 1)[1] for a in argv if a.startswith(f"--{name}=")]
    assert len(values) == 1, argv
    return Path(values[0])


@pytest.mark.parametrize("scanner_name", ["trivy", "trivy-repo"])
@pytest.mark.parametrize(
    "option, env, flag",
    [
        ("ignore_file", None, "ignorefile"),
        ("secret_config_file", None, "secret-config"),
        (None, "TRIVY_IGNOREFILE", "ignorefile"),
        (None, "TRIVY_SECRET_CONFIG", "secret-config"),
    ],
)
def test_trivy_does_not_get_a_file_an_in_tree_link_reaches(
    tree, tmp_path: Path, monkeypatch, option, env, flag, scanner_name: str
) -> None:
    source, operator = tree
    outside = _file(operator / "trivy-input", "github-pat\n")
    link = _link(source / "trivy-link", outside)
    options = {}
    if option:
        options[option] = str(link)
    else:
        monkeypatch.setenv(env, str(link))

    passed = _flag(_trivy_argv(tmp_path, source, scanner_name, options), flag)

    assert passed.resolve() != outside.resolve()
    assert "github-pat" not in passed.read_text()


@pytest.mark.parametrize("scanner_name", ["trivy", "trivy-repo"])
@pytest.mark.parametrize(
    "option, flag",
    [("ignore_file", "ignorefile"), ("secret_config_file", "secret-config")],
)
def test_control_trivy_gets_the_operators_file_through_an_outside_link(
    tree, tmp_path: Path, option: str, flag: str, scanner_name: str
) -> None:
    """The same option names a file it is given, so the test above can fail."""
    source, operator = tree
    outside = _file(operator / "trivy-input", "github-pat\n")
    link = _link(operator / "alias", outside)

    passed = _flag(
        _trivy_argv(tmp_path, source, scanner_name, {option: str(link)}), flag
    )

    assert passed == outside.resolve()


def test_checkov_does_not_get_a_file_an_in_tree_link_reaches(tree, tmp_path) -> None:
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
    )

    source, operator = tree
    outside = _file(operator / "checkov.yaml")
    link = _link(source / "checkov-link.yaml", outside)
    config = resolve_config(
        source_dir=source,
        config_overrides=[f"scanners.checkov.options.config_file={link}"],
    )
    scanner = CheckovScanner(
        config=config.get_plugin_config("scanner", "checkov"),
        context=_context(source, tmp_path, config),
    )

    argv = scanner._resolve_arguments(source, tmp_path / "results.sarif")

    assert "--config-file" not in argv
    assert not any(outside.resolve().as_posix() in a for a in argv)


def test_ferret_does_not_get_a_file_an_in_tree_link_reaches(tree, tmp_path) -> None:
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScanScanner,
        FerretScannerConfig,
    )

    source, operator = tree
    outside = _file(operator / "ferret.yaml")
    link = _link(source / "ferret-link.yaml", outside)
    config = resolve_config(source_dir=source)
    scanner = FerretScanScanner(
        config=FerretScannerConfig(options={"config_file": str(link)}),
        context=_context(source, tmp_path, config),
    )

    found = scanner._find_config_file(scanner.config.options.config_file)

    assert found is None or found.resolve() != outside.resolve()


def test_detect_secrets_drops_a_plugin_an_in_tree_link_reaches(tree, tmp_path) -> None:
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )

    source, operator = tree
    outside = _file(operator / "plugin.py")
    link = _link(source / "plugin-link.py", outside)
    config = resolve_config(source_dir=source)
    scanner = DetectSecretsScanner(
        config=DetectSecretsScannerConfig(
            options={
                "scan_settings": {
                    "plugins_used": [
                        {"name": "AWSKeyDetector"},
                        {"name": "StandIn", "path": f"file://{link}"},
                    ]
                }
            }
        ),
        context=_context(source, tmp_path, config),
    )

    settings = scanner.config.options.scan_settings.model_dump()

    assert outside.resolve().as_posix() not in repr(settings)
    assert link.as_posix() not in repr(settings)
