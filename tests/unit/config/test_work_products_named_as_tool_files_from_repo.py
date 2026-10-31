"""A repository-written config naming a work product as a tool file.

The scan's own work directory lives under the output directory, outside the
scanned tree, and holds files derived from the repository being scanned
(converter output). A ``file://`` entry in detect-secrets' ``plugins_used``
is kept when the file is outside the scanned tree (``honored_path``), so
these cells measure whether a config the repository wrote can hand the tool
a file the scan derived from that same repository.

The probe test comes first; the control pins the behavior that must not move: an
operator-written option naming the same file. A repository-written entry naming
a path outside both trees is refused (test_tool_config_files_are_the_operators.py
pins that).
"""

import contextlib
import logging
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.path_trust import reset_path_refusal_warnings
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.utils.uv_tool_runner import UVToolRunner


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture(autouse=True)
def _no_uv_probe():
    with patch.object(UVToolRunner, "is_uv_available", return_value=False):
        yield


def _layout(tmp_path: Path) -> dict:
    """A scanned checkout, an output dir outside it, and a work product
    under the work dir derived from the checkout."""
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "out"
    work = output / ASH_WORK_DIR_NAME
    product = work / "converted" / "collector.py"
    product.parent.mkdir(parents=True)
    product.write_text("# derived from the scanned repository\n")
    return {"source": source, "output": output, "work": work, "product": product}


def _repo_config(source: Path, body: str) -> None:
    (source / ".ash" / ".ash.yaml").write_text(f"project_name: scanned\n{body}")


def _scanner_settings(layout: dict, scanner_config) -> dict:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    config = resolve_config(source_dir=layout["source"])
    scanner = DetectSecretsScanner(
        config=scanner_config
        if scanner_config is not None
        else config.get_plugin_config("scanner", "detect-secrets"),
        context=PluginContext(
            source_dir=layout["source"],
            output_dir=layout["output"],
            work_dir=layout["work"],
            config=config,
        ),
    )
    return scanner.config.options.scan_settings.model_dump()


def _plugin_paths(settings: dict) -> list:
    return [p.get("path") for p in settings["plugins_used"] if p.get("path")]


@pytest.mark.unit
def test_a_repository_config_cannot_name_a_work_product_as_a_plugin(tmp_path):
    """The probe: the repository's own config names a file the scan derived
    from that repository, under the work dir, as a detect-secrets plugin by
    an absolute ``file://`` path. The entry must not reach the tool."""
    layout = _layout(tmp_path)
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        "      scan_settings:\n"
        "        plugins_used:\n"
        "          - name: StandIn\n"
        f"            path: file://{layout['product'].as_posix()}\n",
    )
    settings = _scanner_settings(layout, scanner_config=None)
    assert not any(
        layout["product"].as_posix() in (path or "") for path in _plugin_paths(settings)
    ), settings["plugins_used"]


@pytest.mark.unit
def test_a_repository_baseline_cannot_name_a_work_product_as_a_plugin(tmp_path):
    """The repository's config names only its own baseline file, and the
    baseline's plugins_used names the work product. Entries loaded from a
    baseline are file content, not the operator's own write, so the same
    refusal applies to them."""
    import json

    layout = _layout(tmp_path)
    baseline = layout["source"] / ".secrets.baseline"
    baseline.write_text(
        json.dumps(
            {
                "version": "1.5.0",
                "plugins_used": [
                    {
                        "name": "StandIn",
                        "path": f"file://{layout['product'].as_posix()}",
                    }
                ],
                "results": {},
            }
        )
    )
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        f"      baseline_file: {baseline.as_posix()}\n",
    )
    settings = _scanner_settings(layout, scanner_config=None)
    assert not any(
        layout["product"].as_posix() in (path or "") for path in _plugin_paths(settings)
    ), settings["plugins_used"]


@pytest.mark.unit
def test_an_operator_option_naming_the_same_work_product_is_kept(tmp_path):
    """Control: the operator's own configuration (not the repository's file)
    naming the same path keeps today's answer."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    settings = _scanner_settings(
        layout,
        scanner_config=DetectSecretsScannerConfig(
            options={
                "scan_settings": {
                    "plugins_used": [
                        {
                            "name": "StandIn",
                            "path": f"file://{layout['product'].as_posix()}",
                        }
                    ]
                }
            }
        ),
    )
    assert any(
        layout["product"].as_posix() in (path or "") for path in _plugin_paths(settings)
    ), settings["plugins_used"]


@pytest.mark.unit
def test_a_repository_entry_reaching_the_work_dir_through_a_link_is_refused(tmp_path):
    """Spelling probe: the repository entry names an in-tree path whose link
    points into the work dir. The check resolves links before judging, so the
    link lands under the work dir and is refused like the direct spelling."""
    layout = _layout(tmp_path)
    link = layout["source"] / "team.py"
    link.symlink_to(layout["product"])
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        "      scan_settings:\n"
        "        plugins_used:\n"
        "          - name: StandIn\n"
        f"            path: file://{link.as_posix()}\n",
    )
    settings = _scanner_settings(layout, scanner_config=None)
    assert not any(
        layout["product"].as_posix() in (path or "") for path in _plugin_paths(settings)
    ), settings["plugins_used"]


def _checkov_argv(
    layout: dict, scanner_config=None, config_overrides=None, config_path=None
) -> list:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
    )

    config = resolve_config(
        config_path=config_path,
        source_dir=layout["source"],
        config_overrides=config_overrides,
    )
    scanner = CheckovScanner(
        config=scanner_config
        if scanner_config is not None
        else config.get_plugin_config("scanner", "checkov"),
        context=PluginContext(
            source_dir=layout["source"],
            output_dir=layout["output"],
            work_dir=layout["work"],
            config=config,
        ),
    )
    return scanner._resolve_arguments(
        layout["source"], layout["output"] / "results.sarif"
    )


@pytest.mark.unit
def test_a_repository_config_cannot_name_a_work_product_as_checkovs_config(tmp_path):
    """The repository's config names the work product, outside the scanned
    tree, as checkov's config file. The entry must not reach the tool."""
    layout = _layout(tmp_path)
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  checkov:\n"
        "    options:\n"
        f"      config_file: {layout['product'].as_posix()}\n",
    )
    argv = _checkov_argv(layout)
    assert not any(layout["product"].as_posix() in a for a in argv), argv


@pytest.mark.unit
def test_a_missing_checkov_config_takes_no_discovered_replacement(tmp_path):
    """The configured checkov config file is not on disk, and the checkout
    carries a config checkov would discover. Nothing takes its place."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / ".checkov.yaml").write_text("")
    absent = tmp_path / "gone" / "checkov.yaml"
    log_path = tmp_path / "emitted.log"
    with _emitted_warnings(log_path):
        argv = _checkov_argv(
            layout,
            scanner_config=CheckovScannerConfig(
                options={"config_file": absent.as_posix()}
            ),
        )
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert "--config-file" not in argv, argv
    assert any("does not exist" in line and "in its place" in line for line in lines), (
        lines
    )


@pytest.mark.unit
def test_an_operator_option_naming_the_work_product_reaches_checkov(tmp_path):
    """Control: the operator's own configuration naming the same path keeps
    today's answer."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    argv = _checkov_argv(
        layout,
        scanner_config=CheckovScannerConfig(
            options={"config_file": layout["product"].as_posix()}
        ),
    )
    assert argv[argv.index("--config-file") + 1] == layout["product"].as_posix()


@pytest.mark.unit
def test_a_missing_configured_checkov_config_ignores_a_link_candidate_leaving_the_tree(
    tmp_path,
):
    """The configured checkov config file is not on disk, and the checkout
    carries a ``.checkov.yaml`` that is a link to a file outside the scanned
    tree, the one shape discovery would hand over. The missing configured
    value still takes no replacement: no ``--config-file`` is passed and no
    argument names the link's target."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    outside = tmp_path / "outside" / "checkov.yaml"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_text("")
    (layout["source"] / ".checkov.yaml").symlink_to(outside)

    argv = _checkov_argv(
        layout,
        scanner_config=CheckovScannerConfig(
            options={"config_file": (tmp_path / "gone" / "checkov.yaml").as_posix()}
        ),
    )

    assert "--config-file" not in argv, argv
    assert not any(outside.as_posix() in a for a in argv), argv


@pytest.mark.unit
def test_a_refused_configured_checkov_config_ignores_a_link_candidate_leaving_the_tree(
    tmp_path,
):
    """The repository's config names the work product as checkov's config
    file, and the checkout carries a ``.checkov.yaml`` linking out of the
    scanned tree. The refused configured value still takes no replacement:
    neither the work product nor the link's target reaches the tool."""
    layout = _layout(tmp_path)
    outside = tmp_path / "outside" / "checkov.yaml"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_text("")
    (layout["source"] / ".checkov.yaml").symlink_to(outside)
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  checkov:\n"
        "    options:\n"
        f"      config_file: {layout['product'].as_posix()}\n",
    )

    argv = _checkov_argv(layout)

    assert "--config-file" not in argv, argv
    assert not any(
        outside.as_posix() in a or layout["product"].as_posix() in a for a in argv
    ), argv


@pytest.mark.unit
def test_an_honored_configured_checkov_config_draws_no_refusal_warning(tmp_path):
    """An operator-configured config file outside the scanned tree is handed
    to checkov once, and no warning says it was not used. A refusal warning
    on an honored value would misreport the handed-over config as dropped."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    honored = tmp_path / "operator" / "checkov.yaml"
    honored.parent.mkdir(parents=True, exist_ok=True)
    honored.write_text("")

    log_path = tmp_path / "emitted.log"
    with _emitted_warnings(log_path):
        argv = _checkov_argv(
            layout,
            scanner_config=CheckovScannerConfig(
                options={"config_file": honored.as_posix()}
            ),
        )
    lines = log_path.read_text(encoding="utf-8").splitlines()

    assert argv.count("--config-file") == 1, argv
    assert argv[argv.index("--config-file") + 1] == honored.as_posix(), argv
    assert not any("was not used" in line for line in lines), lines


def _ferret_found(layout: dict, scanner_config=None):
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScanScanner,
    )

    config = resolve_config(source_dir=layout["source"])
    scanner = FerretScanScanner(
        config=scanner_config
        if scanner_config is not None
        else config.get_plugin_config("scanner", "ferret-scan"),
        context=PluginContext(
            source_dir=layout["source"],
            output_dir=layout["output"],
            work_dir=layout["work"],
            config=config,
        ),
    )
    return scanner._find_config_file(scanner.config.options.config_file)


@pytest.mark.unit
def test_a_repository_config_cannot_name_a_work_product_as_ferrets_config(tmp_path):
    """The repository's config names the work product as ferret-scan's config
    file. The entry must not reach the tool; the bundled default is used."""
    layout = _layout(tmp_path)
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  ferret-scan:\n"
        "    options:\n"
        f"      config_file: {layout['product'].as_posix()}\n",
    )
    found = _ferret_found(layout)
    assert found != layout["product"].resolve(), found


@pytest.mark.unit
def test_a_discovered_ferret_config_linking_to_a_work_product_is_refused(tmp_path):
    """The checkout carries a ferret config by name that is a link to the work
    product. Discovery's find is the checkout's write, so the resolved target
    under the work directory must not reach the tool."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / "ferret.yaml").symlink_to(layout["product"])
    found = _ferret_found(layout)
    assert found != layout["product"].resolve(), found


@pytest.mark.unit
def test_a_discovered_dot_ferret_config_linking_to_a_work_product_is_refused(tmp_path):
    """The dot-spelled candidate: the checkout carries .ferret.yaml as a link
    to the work product, and the scanner's own selection must refuse it."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / ".ferret.yaml").symlink_to(layout["product"])
    found = _ferret_found(layout)
    assert found != layout["product"].resolve(), found


@pytest.mark.unit
def test_an_operator_option_naming_the_work_product_reaches_ferret(tmp_path):
    """Control: the operator's own configuration naming the same path keeps
    today's answer."""
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    found = _ferret_found(
        layout,
        scanner_config=FerretScannerConfig(
            options={"config_file": layout["product"].as_posix()}
        ),
    )
    assert found == layout["product"].resolve(), found


def _trivy_passed_path(
    layout: dict, scanner_config=None, method: str = "_secret_config_file"
) -> str:
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
    )

    config = resolve_config(source_dir=layout["source"])
    scanner = TrivyRepoScanner(
        config=scanner_config
        if scanner_config is not None
        else config.get_plugin_config("scanner", "trivy-repo"),
        context=PluginContext(
            source_dir=layout["source"],
            output_dir=layout["output"],
            work_dir=layout["work"],
            config=config,
        ),
    )
    scanner.results_dir = layout["output"] / "scanners" / "trivy-repo"
    return getattr(scanner, method)()


@pytest.fixture
def _no_trivy_env(monkeypatch):
    monkeypatch.delenv("TRIVY_SECRET_CONFIG", raising=False)
    monkeypatch.delenv("TRIVY_IGNOREFILE", raising=False)


@pytest.mark.unit
def test_a_repository_config_cannot_name_a_work_product_as_trivys_input(
    tmp_path, _no_trivy_env
):
    """The repository's config names the work product as the secret-rules file
    trivy reads. The entry must not reach the tool; the file ASH writes into
    the results directory is used."""
    layout = _layout(tmp_path)
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  trivy-repo:\n"
        "    options:\n"
        f"      secret_config_file: {layout['product'].as_posix()}\n",
    )
    passed = _trivy_passed_path(layout)
    assert passed != layout["product"].as_posix(), passed


@pytest.mark.unit
def test_an_operator_environment_value_naming_the_work_product_reaches_trivy(
    tmp_path, _no_trivy_env, monkeypatch
):
    """Control: the environment variable is the operator's own write, so a
    value naming the same path keeps today's answer."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    monkeypatch.setenv("TRIVY_SECRET_CONFIG", layout["product"].as_posix())
    passed = _trivy_passed_path(layout)
    assert passed == layout["product"].as_posix(), passed


@pytest.mark.unit
def test_an_operator_option_naming_the_work_product_reaches_trivy(
    tmp_path, _no_trivy_env
):
    """Control: a scanner configuration the embedding caller built is the
    operator's own write, as for syft, bandit, checkov and grype, so an option
    naming the same path keeps today's answer even when the scanned tree holds a
    config file of its own. The repository's entry for the same option is
    refused (test_a_repository_config_cannot_name_a_work_product_as_trivys_input)."""
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    passed = _trivy_passed_path(
        layout,
        scanner_config=TrivyRepoScannerConfig(
            options={"secret_config_file": layout["product"].as_posix()}
        ),
    )
    assert passed == layout["product"].as_posix(), passed


def _bandit_scanner(layout: dict, scanner_config=None):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
    )

    config = resolve_config(source_dir=layout["source"])
    return BanditScanner(
        config=scanner_config
        if scanner_config is not None
        else config.get_plugin_config("scanner", "bandit"),
        context=PluginContext(
            source_dir=layout["source"],
            output_dir=layout["output"],
            work_dir=layout["work"],
            config=config,
        ),
    )


def _construction_args(scanner) -> list:
    return [(a.key, a.value) for a in scanner.args.extra_args]


def _bandit_args(layout: dict, scanner_config=None) -> list:
    return _construction_args(_bandit_scanner(layout, scanner_config))


def _bandit_scan_argv(scanner, layout: dict) -> list:
    """The argv bandit would run with for a scan of the source directory.

    bandit's empty ``--ini`` is not among the construction-time arguments: the
    scan writes it (``_execute_scan``), in a directory made for that run.
    """
    final_args, _, _ = scanner._execute_scan(layout["source"], "source", [])
    return [str(arg) for arg in final_args]


def _only_per_run_empty_ini(argv: list, layout: dict) -> str:
    """The one ``--ini`` a scan passes: the file ASH writes for that run.

    It is named ``bandit-empty.ini``, sits in a directory made for the scanner
    run (``ash-tool-config-*``), outside the output directory and the scanned
    tree, and sets nothing.
    """
    from automated_security_helper.utils.tool_config_dir import (
        TOOL_CONFIG_DIR_PREFIX,
    )

    values = [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == "--ini"]
    assert len(values) == 1, argv
    passed = Path(values[0])
    assert passed.name == "bandit-empty.ini", values
    assert passed.parent.name.startswith(TOOL_CONFIG_DIR_PREFIX), values
    parents = passed.resolve().parents
    assert layout["output"].resolve() not in parents, values
    assert layout["source"].resolve() not in parents, values
    assert passed.read_text(encoding="utf-8") == "[bandit]\n", values
    return values[0]


def _only_neutral_value(args: list, key: str, layout: dict, name: str) -> str:
    """The one value passed for *key*, which is the neutral file ASH writes
    (*name*, under the scanner's results directory, outside the scanned tree)."""
    values = [value for k, value in args if k == key]
    assert len(values) == 1, args
    passed = Path(values[0])
    assert passed.name == name, values
    assert layout["output"] in passed.parents, values
    assert layout["source"] not in passed.parents, values
    return values[0]


@pytest.mark.unit
def test_a_missing_bandit_config_takes_no_discovered_replacement(tmp_path):
    """Control for the missing arm: the configured file is not on disk and the
    checkout carries a config bandit would discover. Nothing takes its place:
    bandit gets the empty ini file ASH writes, and the warning says so."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / "bandit.yaml").write_text("")
    absent = tmp_path / "gone" / "bandit.yaml"
    log_path = tmp_path / "emitted.log"
    with _emitted_warnings(log_path):
        scanner = _bandit_scanner(
            layout,
            scanner_config=BanditScannerConfig(
                options={"config_file": absent.as_posix()}
            ),
        )
    args = _construction_args(scanner)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert not any(key == "--configfile" for key, _ in args), args
    assert not any(key == "--ini" for key, _ in args), args
    argv = _bandit_scan_argv(scanner, layout)
    assert "--configfile" not in argv, argv
    assert not any(
        (layout["source"] / "bandit.yaml").as_posix() in value for value in argv
    ), argv
    _only_per_run_empty_ini(argv, layout)
    assert any("does not exist" in line and "in its place" in line for line in lines), (
        lines
    )


@pytest.mark.unit
def test_a_discovered_bandit_config_linking_to_a_work_product_is_refused(tmp_path):
    """The checkout carries a bandit config by name that is a link to the work
    product. The resolved target under the work directory must not reach the
    tool, and no other candidate exists, so no config is passed."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / "bandit.yaml").symlink_to(layout["product"])
    args = _bandit_args(layout)
    assert not any(layout["product"].as_posix() in str(value) for _, value in args), (
        args
    )
    assert not any(key in ("--configfile", "--ini") for key, _ in args), args


@pytest.mark.unit
def test_an_operator_option_naming_the_work_product_reaches_bandit(tmp_path):
    """Control: the operator's own configuration naming the same path keeps
    today's answer."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    args = _bandit_args(
        layout,
        scanner_config=BanditScannerConfig(
            options={"config_file": layout["product"].as_posix()}
        ),
    )
    assert ("--configfile", layout["product"].as_posix()) in args, args


def _layout_with_output_above_source(tmp_path: Path) -> dict:
    """An output directory that holds the scanned checkout, as with
    ``--output-dir /ci/ws --source-dir /ci/ws/repo``."""
    output = tmp_path / "ws"
    source = output / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n")
    work = output / ASH_WORK_DIR_NAME
    product = work / "converted" / "bandit.yaml"
    product.parent.mkdir(parents=True)
    product.write_text("")
    return {"source": source, "output": output, "work": work, "product": product}


@pytest.mark.unit
def test_a_repository_config_under_the_work_dir_stays_refused_with_output_above_source(
    tmp_path,
):
    """Control for the cell above: with the same layout, a repository-written
    entry naming a file under the work directory, which sits outside the
    checkout, is still a derived product and does not reach the tool."""
    layout = _layout_with_output_above_source(tmp_path)
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  bandit:\n"
        "    options:\n"
        f"      config_file: {layout['product'].as_posix()}\n",
    )
    args = _bandit_args(layout)
    assert not any(layout["product"].as_posix() in str(value) for _, value in args), (
        args
    )


@pytest.mark.unit
def test_a_file_under_the_output_dir_but_outside_the_tree_stays_refused(tmp_path):
    """Second control: the output directory holds the scanned checkout, and the
    repository's config names a file under that output directory which sits
    outside both the checkout and the work directory. The containing output
    root still refuses it: only files inside the scanned tree are exempt."""
    layout = _layout_with_output_above_source(tmp_path)
    derived = layout["output"] / "reports" / "bandit.yaml"
    derived.parent.mkdir(parents=True)
    derived.write_text("")
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  bandit:\n"
        "    options:\n"
        f"      config_file: {derived.as_posix()}\n",
    )
    args = _bandit_args(layout)
    assert not any(derived.as_posix() in str(value) for _, value in args), args


def _grype_scanner(layout: dict, scanner_config=None):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
    )

    config = resolve_config(source_dir=layout["source"])
    return GrypeScanner(
        config=scanner_config
        if scanner_config is not None
        else config.get_plugin_config("scanner", "grype"),
        context=PluginContext(
            source_dir=layout["source"],
            output_dir=layout["output"],
            work_dir=layout["work"],
            config=config,
        ),
    )


def _grype_config_arg(layout: dict, scanner_config=None):
    scanner = _grype_scanner(layout, scanner_config)
    values = [a.value for a in scanner.args.extra_args if a.key == "--config"]
    return values[0] if values else None


@pytest.mark.unit
def test_an_honored_configured_grype_config_is_the_only_config_handed_over(tmp_path):
    """An operator-configured config file outside the scanned tree is handed
    to grype exactly once; a config the checkout carries by name does not
    ride along with it."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / ".grype.yaml").write_text("")
    honored = tmp_path / "operator" / "grype.yaml"
    honored.parent.mkdir(parents=True, exist_ok=True)
    honored.write_text("")

    scanner = _grype_scanner(
        layout,
        scanner_config=GrypeScannerConfig(options={"config_file": honored.as_posix()}),
    )

    values = [a.value for a in scanner.args.extra_args if a.key == "--config"]
    assert len(values) == 1, values
    assert values[0] in {honored.as_posix(), honored.resolve().as_posix()}, values


def _is_the_neutral_file(layout: dict, passed, name: str) -> None:
    """*passed* is the empty config file ASH writes (*name*) under the scanner's
    results directory, outside the scanned tree."""
    assert passed is not None
    path = Path(passed)
    assert path.name == name, passed
    assert layout["output"] in path.parents, passed
    assert layout["source"] not in path.parents, passed


@pytest.mark.unit
def test_a_missing_grype_config_takes_no_discovered_replacement(tmp_path):
    """The configured grype config file is not on disk and the checkout carries
    a config grype would discover. Nothing takes its place: the empty config
    file ASH writes is passed, and the warning says so."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / ".grype.yaml").write_text("")
    absent = tmp_path / "gone" / "grype.yaml"
    log_path = tmp_path / "emitted.log"
    with _emitted_warnings(log_path):
        passed = _grype_config_arg(
            layout,
            scanner_config=GrypeScannerConfig(
                options={"config_file": absent.as_posix()}
            ),
        )
    lines = log_path.read_text(encoding="utf-8").splitlines()
    _is_the_neutral_file(layout, passed, "grype-config-empty.yaml")
    assert any("does not exist" in line and "in its place" in line for line in lines), (
        lines
    )


@pytest.mark.unit
def test_a_discovered_grype_config_linking_to_a_work_product_is_refused(tmp_path):
    """The checkout carries a grype config by name that is a link to the work
    product. The resolved target under the work directory must not reach the
    tool."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / ".grype.yaml").symlink_to(layout["product"])
    assert _grype_config_arg(layout) is None


@pytest.mark.unit
def test_an_operator_option_naming_the_work_product_reaches_grype(tmp_path):
    """Control: the operator's own configuration naming the same path keeps
    today's answer."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    passed = _grype_config_arg(
        layout,
        scanner_config=GrypeScannerConfig(
            options={"config_file": layout["product"].as_posix()}
        ),
    )
    assert passed == layout["product"].resolve().as_posix(), passed


def _record_grype_parses(monkeypatch) -> list:
    """Wrap the two places the scanner reads a grype config's content,
    ``GrypeScanner._output_restricting_keys`` and the module's
    ``_declared_grype_db_bound`` (which reads the config's ``db`` section), so
    every path either is given is recorded, then call the real function. The
    production path runs with an observation point, not a stub. The second
    function is given no path when no config was selected, and that call is not
    a read."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        grype_scanner,
    )

    real = grype_scanner.GrypeScanner._output_restricting_keys
    real_bound = grype_scanner._declared_grype_db_bound
    seen: list = []

    def recording(config_path):
        seen.append(str(config_path))
        return real(config_path)

    def recording_bound(environ, grype_config, values=(), *, shown=None):
        if grype_config is not None:
            seen.append(str(grype_config))
        return real_bound(environ, grype_config, values, shown=shown)

    monkeypatch.setattr(
        grype_scanner.GrypeScanner, "_output_restricting_keys", staticmethod(recording)
    )
    monkeypatch.setattr(grype_scanner, "_declared_grype_db_bound", recording_bound)
    return seen


@pytest.mark.unit
def test_grype_never_parses_a_discovered_config_it_refused(tmp_path, monkeypatch):
    """Load-order pin: the derived-product check runs before the config file is
    opened. A discovered grype config that links to a work product is refused,
    and the file is not read at all, so a restricting-keys warning can never
    come from a work product the scan refused."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    candidate = layout["source"] / ".grype.yaml"
    candidate.symlink_to(layout["product"])
    parsed = _record_grype_parses(monkeypatch)
    assert _grype_config_arg(layout) is None
    needles = {
        layout["product"].as_posix(),
        layout["product"].resolve().as_posix(),
        candidate.as_posix(),
    }
    assert not any(needle in seen for seen in parsed for needle in needles), parsed
    assert parsed == [], parsed


def _syft_scanner(layout: dict, scanner_config=None):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScanner,
    )

    config = resolve_config(source_dir=layout["source"])
    return SyftScanner(
        config=scanner_config
        if scanner_config is not None
        else config.get_plugin_config("scanner", "syft"),
        context=PluginContext(
            source_dir=layout["source"],
            output_dir=layout["output"],
            work_dir=layout["work"],
            config=config,
        ),
    )


def _syft_config_arg(layout: dict, scanner_config=None):
    scanner = _syft_scanner(layout, scanner_config)
    values = [a.value for a in scanner.args.extra_args if a.key == "--config"]
    return values[0] if values else None


def _no_built_argument_names(scanner, path: Path, layout: dict | None = None) -> None:
    """No argument the scanner built carries *path* under either spelling. With
    no *layout*, no ``--config`` is built at all; with one, the only ``--config``
    is the empty file ASH writes under the results directory."""
    spellings = {path.as_posix(), path.resolve().as_posix()}
    built = [(a.key, str(a.value)) for a in scanner.args.extra_args]
    assert all(value not in spellings for _, value in built), built
    if layout is None:
        assert all(key != "--config" for key, _ in built), built
    else:
        _only_neutral_value(built, "--config", layout, "syft-config-empty.yaml")


@pytest.mark.unit
def test_a_missing_syft_config_takes_no_discovered_replacement(tmp_path):
    """The configured syft config file is not on disk and the checkout carries
    a config syft would discover. Nothing takes its place: the empty config file
    ASH writes is passed, and the warning says so."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / ".syft.yaml").write_text("")
    absent = tmp_path / "gone" / "syft.yaml"
    log_path = tmp_path / "emitted.log"
    with _emitted_warnings(log_path):
        passed = _syft_config_arg(
            layout,
            scanner_config=SyftScannerConfig(
                options={"config_file": absent.as_posix()}
            ),
        )
    lines = log_path.read_text(encoding="utf-8").splitlines()
    _is_the_neutral_file(layout, passed, "syft-config-empty.yaml")
    assert any("does not exist" in line and "in its place" in line for line in lines), (
        lines
    )


@pytest.mark.unit
def test_a_discovered_syft_config_linking_to_a_work_product_is_refused(tmp_path):
    """The checkout carries a syft config by name that is a link to the work
    product. The resolved target under the work directory must not reach the
    tool."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / ".syft.yaml").symlink_to(layout["product"])
    assert _syft_config_arg(layout) is None


@pytest.mark.unit
def test_an_operator_option_naming_the_work_product_reaches_syft(tmp_path):
    """Control: the operator's own configuration naming the same path keeps
    today's answer."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    passed = _syft_config_arg(
        layout,
        scanner_config=SyftScannerConfig(
            options={"config_file": layout["product"].as_posix()}
        ),
    )
    assert passed == layout["product"].resolve().as_posix(), passed


@pytest.mark.unit
def test_a_configured_syft_config_not_written_by_the_operator_is_dropped(
    tmp_path, monkeypatch
):
    """The refused-configured arm, driven directly: the configured value names
    a work product, its origin is recorded as the repository's (the operator
    did not write it), and a checkout config that discovery would otherwise
    pick sits beside it. No built argument names the dropped file under any
    spelling and the only ``--config`` is the empty file ASH writes, whatever
    the loader's validation of the document does."""
    from automated_security_helper.config import operator_only_options
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / ".syft.yaml").write_text("")
    monkeypatch.setattr(
        operator_only_options, "operator_wrote_value", lambda *args, **kwargs: False
    )
    scanner = _syft_scanner(
        layout,
        scanner_config=SyftScannerConfig(
            options={"config_file": layout["product"].as_posix()}
        ),
    )
    _no_built_argument_names(scanner, layout["product"], layout)


@pytest.mark.skipif(
    os.name != "posix" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs a file the process cannot read",
)
@pytest.mark.unit
def test_a_dropped_configured_input_is_never_opened(tmp_path, monkeypatch, request):
    """The drop is decided from the file's place and origin, never from its
    content: with the configured work product unreadable, the drop still
    completes, no built argument names the file, and the only ``--config`` is
    the empty file ASH writes. Anything that opened the dropped input would
    crash here instead of completing."""
    from automated_security_helper.config import operator_only_options
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / ".syft.yaml").write_text("")
    monkeypatch.setattr(
        operator_only_options, "operator_wrote_value", lambda *args, **kwargs: False
    )
    layout["product"].chmod(0)
    request.addfinalizer(lambda: layout["product"].chmod(0o600))

    scanner = _syft_scanner(
        layout,
        scanner_config=SyftScannerConfig(
            options={"config_file": layout["product"].as_posix()}
        ),
    )

    _no_built_argument_names(scanner, layout["product"], layout)


@pytest.mark.unit
def test_without_a_configured_input_no_argument_names_the_work_product(tmp_path):
    """The must-not twin: nothing is configured and the checkout carries no
    discoverable config, so the same absence assertions hold with the drop
    arm never taken. The absences above are the drop's doing, not the
    harness's."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")

    scanner = _syft_scanner(layout)

    _no_built_argument_names(scanner, layout["product"])


@pytest.mark.unit
def test_an_honored_configured_syft_config_is_the_only_config_handed_over(tmp_path):
    """An operator-configured config file outside the scanned tree is handed
    to syft exactly once; a config the checkout carries by name does not ride
    along with it."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / ".syft.yaml").write_text("")
    honored = tmp_path / "operator" / "syft.yaml"
    honored.parent.mkdir(parents=True, exist_ok=True)
    honored.write_text("")

    scanner = _syft_scanner(
        layout,
        scanner_config=SyftScannerConfig(options={"config_file": honored.as_posix()}),
    )

    values = [a.value for a in scanner.args.extra_args if a.key == "--config"]
    assert len(values) == 1, values
    assert values[0] in {honored.as_posix(), honored.resolve().as_posix()}, values


@pytest.mark.unit
def test_the_neutral_files_are_written_when_arguments_resolve_not_when_built(
    tmp_path,
):
    """Building a scanner whose configured file is missing writes nothing into
    the output directory; resolving its arguments writes the empty file the
    argument names, and the file sets nothing: an empty mapping for syft and
    grype. Bandit's empty ``[bandit]`` ini file is written per scan, in a
    directory made for that run, so building adds no ``--ini`` and the scan's
    argument list carries the one file."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
        BanditScannerConfig,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScannerConfig,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    absent = (tmp_path / "gone" / "config").as_posix()
    context = PluginContext(
        source_dir=layout["source"],
        output_dir=layout["output"],
        work_dir=layout["work"],
        config=resolve_config(source_dir=layout["source"]),
    )
    cases = [
        (
            _syft_scanner(layout, SyftScannerConfig(options={"config_file": absent})),
            "--config",
            "{}\n",
        ),
        (
            _grype_scanner(layout, GrypeScannerConfig(options={"config_file": absent})),
            "--config",
            "{}\n",
        ),
    ]
    for scanner, key, content in cases:
        named = [a.value for a in scanner.args.extra_args if a.key == key]
        assert len(named) == 1, (scanner, named)
        neutral = Path(named[0])
        assert not neutral.exists(), neutral

        scanner._resolve_arguments(target=layout["source"])

        assert neutral.read_text(encoding="utf-8") == content, neutral

    # bandit's empty ini is not an argument of the built scanner at all: the
    # scan writes it, in a directory made for that run, when it resolves the
    # argument list (bandit_scanner._execute_scan).
    bandit = BanditScanner(
        config=BanditScannerConfig(options={"config_file": absent}),
        context=context,
    )
    assert not [a for a in bandit.args.extra_args if a.key == "--ini"], (
        bandit.args.extra_args
    )
    assert not list(layout["output"].rglob("bandit-empty.ini"))

    argv = _bandit_scan_argv(bandit, layout)

    _only_per_run_empty_ini(argv, layout)
    assert not list(layout["output"].rglob("bandit-empty.ini"))
    assert not [a for a in bandit.args.extra_args if a.key == "--ini"], (
        bandit.args.extra_args
    )


@contextlib.contextmanager
def _emitted_warnings(log_path: Path):
    """ASH's logger writing WARNING records to *log_path* through the ash.log
    formatter, so the cells below assert the EMITTED text, not the record."""
    from automated_security_helper.utils.log import (
        ASH_LOGGER,
        LogFileHandler,
        TextFileFormatter,
    )

    handler = LogFileHandler(log_path.as_posix())
    handler.setLevel(logging.WARNING)
    handler.setFormatter(
        TextFileFormatter(
            fmt="%(asctime)s\t%(levelname)s\t%(filename)s:%(lineno)d\t%(message)s "
        )
    )
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)
        handler.close()


def _plugin_entry_config(written: str) -> str:
    """A repo config whose detect-secrets entry writes *written* as the path:
    a literal ``file://`` path, or a whole-scalar ``${VAR}`` reference (the
    loader interpolates a reference only when it is the entire scalar)."""
    return (
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        "      scan_settings:\n"
        "        plugins_used:\n"
        "          - name: StandIn\n"
        f"            path: {written}\n"
    )


@pytest.mark.unit
def test_an_env_chosen_work_product_entry_is_shown_not_named(tmp_path, monkeypatch):
    """The repository's config names the work product through an environment
    reference. The entry must not reach the tool, and the environment's value
    is in no emitted line: the warning names the option and the file that
    wrote it (config/tool_config_trust.py), never the value."""
    layout = _layout(tmp_path)
    value = layout["product"].as_posix()
    monkeypatch.setenv("ASH_STANDIN_PLUGIN", f"file://{value}")
    _repo_config(layout["source"], _plugin_entry_config("${ASH_STANDIN_PLUGIN}"))
    log_path = tmp_path / "emitted.log"
    with _emitted_warnings(log_path):
        settings = _scanner_settings(layout, scanner_config=None)
    assert not any(value in (path or "") for path in _plugin_paths(settings)), settings[
        "plugins_used"
    ]
    lines = log_path.read_text(encoding="utf-8").splitlines()
    warning = [line for line in lines if "Ignoring" in line]
    assert warning, lines
    assert all(value not in line for line in lines), lines


@pytest.mark.unit
def test_an_env_chosen_in_tree_entry_is_shown_not_named(tmp_path, monkeypatch):
    """The in-tree pair: an environment reference resolving to a file inside
    the scanned tree is refused, and the value is in no emitted line."""
    layout = _layout(tmp_path)
    inside = layout["source"] / "team_plugin.py"
    inside.write_text("")
    value = inside.as_posix()
    monkeypatch.setenv("ASH_STANDIN_INTREE", f"file://{value}")
    _repo_config(layout["source"], _plugin_entry_config("${ASH_STANDIN_INTREE}"))
    log_path = tmp_path / "emitted.log"
    with _emitted_warnings(log_path):
        settings = _scanner_settings(layout, scanner_config=None)
    assert not any(value in (path or "") for path in _plugin_paths(settings)), settings[
        "plugins_used"
    ]
    lines = log_path.read_text(encoding="utf-8").splitlines()
    warning = [line for line in lines if "Ignoring" in line]
    assert warning, lines
    assert all(value not in line for line in lines), lines


@pytest.mark.unit
def test_an_env_chosen_link_is_shown_without_its_resolved_target(tmp_path, monkeypatch):
    """Resolution can change the spelling: the environment's value is a link
    into the work directory, so the resolved path shares no text with the
    value. Neither the value nor the resolved target is in any emitted line."""
    layout = _layout(tmp_path)
    link = layout["source"] / "team.py"
    link.symlink_to(layout["product"])
    value = link.as_posix()
    monkeypatch.setenv("ASH_STANDIN_LINK", f"file://{value}")
    _repo_config(layout["source"], _plugin_entry_config("${ASH_STANDIN_LINK}"))
    log_path = tmp_path / "emitted.log"
    with _emitted_warnings(log_path):
        settings = _scanner_settings(layout, scanner_config=None)
    assert not any(
        layout["product"].as_posix() in (path or "") for path in _plugin_paths(settings)
    ), settings["plugins_used"]
    lines = log_path.read_text(encoding="utf-8").splitlines()
    warning = [line for line in lines if "Ignoring" in line]
    assert warning, lines
    assert all(value not in line for line in lines), lines
    assert all(layout["product"].as_posix() not in line for line in lines), lines


def _baseline_json() -> str:
    """A baseline whose one plugin entry is the distinctive marker: loading
    replaces the scan settings with exactly this entry, while a refused
    baseline leaves the default plugin set, which never holds it."""
    import json

    return json.dumps(
        {
            "version": "1.5.0",
            "plugins_used": [{"name": "StandIn"}],
            "results": {},
        }
    )


def _plugin_names(options) -> list:
    return [plugin.name for plugin in options.scan_settings.plugins_used]


def _detect_secrets_built(layout: dict, scanner_config=None):
    """A detect-secrets scanner built over *layout*, from the caller's typed
    configuration or the scanned tree's resolved section."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    config = resolve_config(source_dir=layout["source"])
    return DetectSecretsScanner(
        config=scanner_config
        if scanner_config is not None
        else config.get_plugin_config("scanner", "detect-secrets"),
        context=PluginContext(
            source_dir=layout["source"],
            output_dir=layout["output"],
            work_dir=layout["work"],
            config=config,
        ),
    )


def _detect_secrets_options(layout: dict, scanner_config=None):
    return _detect_secrets_built(layout, scanner_config).config.options


@pytest.mark.unit
def test_a_missing_baseline_takes_no_checkout_candidate(tmp_path):
    """The configured baseline is not on disk, and the checkout carries a
    baseline by its conventional name. The checkout's baseline does not replace
    the configured one: the scan runs without a baseline, the option stays on
    the config as written, and the warning says so."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / ".secrets.baseline").write_text(_baseline_json())
    absent = tmp_path / "gone" / "absent.baseline"
    log_path = tmp_path / "emitted.log"
    with _emitted_warnings(log_path):
        scanner = DetectSecretsScanner(
            config=DetectSecretsScannerConfig(
                options={"baseline_file": absent.as_posix()}
            ),
            context=PluginContext(
                source_dir=layout["source"],
                output_dir=layout["output"],
                work_dir=layout["work"],
                config=resolve_config(source_dir=layout["source"]),
            ),
        )
    options = scanner.config.options
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert Path(options.baseline_file) == absent, options.baseline_file
    assert not scanner._baseline_in_use()
    assert "StandIn" not in _plugin_names(options), _plugin_names(options)
    assert any("does not exist" in line and "in its place" in line for line in lines), (
        lines
    )


@pytest.mark.usefixtures("no_tool_probes")
@pytest.mark.integration
def test_a_refused_option_baseline_is_never_opened_by_the_scan(tmp_path, monkeypatch):
    """The refused baseline is not read at the scan either: the scan runs
    without a baseline and reports the planted finding, and the path the scan
    would open is never asked for."""
    layout = _layout(tmp_path)
    (layout["source"] / "settings.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{_PLANTED_KEY}'\n"
    )
    derived = layout["work"] / "derived.baseline"
    derived.write_text(_baseline_json())
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        f"      baseline_file: {derived.as_posix()}\n",
    )
    scanner = _detect_secrets_scanner(layout)
    asked = []
    original = scanner._baseline_file_path

    def _spy():
        asked.append(True)
        return original()

    monkeypatch.setattr(scanner, "_baseline_file_path", _spy)
    report = scanner.scan(target=layout["source"], target_type="source")
    assert asked == [], "the scan asked for the refused baseline's path"
    assert [r.ruleId for r in report.runs[0].results] == ["SECRET-AWS-ACCESS-KEY"]


@pytest.mark.unit
def test_an_operator_option_naming_the_work_product_baseline_is_loaded(tmp_path):
    """Control: the operator's own configuration naming the same baseline
    keeps today's answer."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    derived = layout["work"] / "derived.baseline"
    derived.write_text(_baseline_json())
    scanner = _detect_secrets_built(
        layout,
        scanner_config=DetectSecretsScannerConfig(
            options={"baseline_file": derived.as_posix()}
        ),
    )
    options = scanner.config.options
    # The option keeps the value as written, and the scan loaded that
    # baseline (its marker plugin is in the scan settings).
    assert str(options.baseline_file) == derived.as_posix(), options.baseline_file
    assert _plugin_names(options) == ["StandIn"], _plugin_names(options)


def _named_baseline_json(plugin_name: str) -> str:
    """A baseline whose one plugin entry carries *plugin_name*, so a cell can
    tell which of two same-named files was loaded."""
    import json

    return json.dumps(
        {
            "version": "1.5.0",
            "plugins_used": [{"name": plugin_name}],
            "results": {},
        }
    )


@pytest.mark.unit
def test_a_relative_baseline_option_names_the_scanned_trees_file(tmp_path, monkeypatch):
    """The option as the scan will read it: a relative baseline_file value
    names the scanned tree's file, not a same-named file in the directory the
    process happens to run in."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    honest = layout["source"] / "team.baseline"
    honest.write_text(_named_baseline_json("MarkerA"))
    rundir = tmp_path / "rundir"
    rundir.mkdir()
    (rundir / "team.baseline").write_text(_named_baseline_json("MarkerB"))
    monkeypatch.chdir(rundir)
    scanner = _detect_secrets_built(
        layout,
        scanner_config=DetectSecretsScannerConfig(
            options={"baseline_file": "team.baseline"}
        ),
    )
    options = scanner.config.options
    # The scan loaded the scanned tree's file (MarkerA), not the same-named
    # one in the working directory (MarkerB), and the option keeps the
    # relative value as written.
    assert _plugin_names(options) == ["MarkerA"], _plugin_names(options)
    assert str(options.baseline_file) == "team.baseline", options.baseline_file


@pytest.mark.unit
def test_a_discovered_baseline_is_found_in_the_scanned_tree_not_the_cwd(
    tmp_path, monkeypatch
):
    """Discovery of the bare ``.secrets.baseline`` name looks in the scanned
    tree: the one in the directory the process runs in is not the scan's."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    (layout["source"] / ".secrets.baseline").write_text(_named_baseline_json("MarkerA"))
    rundir = tmp_path / "rundir"
    rundir.mkdir()
    (rundir / ".secrets.baseline").write_text(_named_baseline_json("MarkerB"))
    monkeypatch.chdir(rundir)
    scanner = _detect_secrets_built(layout)
    options = scanner.config.options
    # The scan loaded the scanned tree's discovered file (MarkerA), not the
    # working directory's (MarkerB), and with nothing configured the option
    # stays unset.
    assert _plugin_names(options) == ["MarkerA"], _plugin_names(options)
    assert options.baseline_file is None, options.baseline_file


@pytest.mark.unit
def test_a_relative_repo_baseline_reaching_a_work_product_from_the_cwd_is_refused(
    tmp_path, monkeypatch
):
    """The repository writes a relative baseline_file. From the directory the
    process runs in (the work dir here) it names a derived product; from the
    scanned tree it names nothing. The product must not be loaded: the name is
    read from the scanned tree, where no file answers to it."""
    layout = _layout(tmp_path)
    derived = layout["work"] / "derived.baseline"
    derived.write_text(_named_baseline_json("MarkerProduct"))
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        "      baseline_file: derived.baseline\n",
    )
    monkeypatch.chdir(layout["work"])
    options = _detect_secrets_options(layout)
    assert "MarkerProduct" not in _plugin_names(options), _plugin_names(options)
    assert (
        options.baseline_file is None
        or Path(options.baseline_file) != derived.resolve()
    ), options.baseline_file


@pytest.mark.unit
def test_a_discovered_baseline_linking_to_a_work_product_is_refused(
    tmp_path, monkeypatch
):
    """The checkout carries a baseline by name that is a link to the work
    product. The resolved target under the work directory must not be
    loaded, and no other candidate exists, so no baseline applies."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    derived = layout["work"] / "derived.baseline"
    derived.write_text(_baseline_json())
    (layout["source"] / ".secrets.baseline").symlink_to(derived)
    monkeypatch.chdir(layout["source"])
    options = _detect_secrets_options(layout)
    assert options.baseline_file is None, options.baseline_file
    assert "StandIn" not in _plugin_names(options), _plugin_names(options)


# ---------------------------------------------------------------------------
# Which sources count as the operator's own for a scanner option
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_config_override_naming_the_work_product_reaches_checkov(tmp_path):
    """The operator's --config-overrides is the operator's own write. A
    repository config file is in the chain, so the resolved value is judged
    against the operator's view of the configuration; that view holds the
    override, and the path reaches checkov. The override is not dropped with
    a warning that calls it the repository's."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    product = layout["product"].as_posix()
    argv = _checkov_argv(
        layout,
        config_overrides=[f"scanners.checkov.options.config_file={product}"],
    )
    assert "--config-file" in argv, argv
    assert argv[argv.index("--config-file") + 1] == product, argv


@pytest.mark.unit
def test_a_repository_value_beside_an_operator_override_stays_refused(tmp_path):
    """Control: the operator overrides one scanner option; the repository's
    file sets another to a work product. The override does not make the
    repository's value the operator's."""
    layout = _layout(tmp_path)
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        "      scan_settings:\n"
        "        filters_used:\n"
        f"          - path: file://{layout['product'].as_posix()}::keep\n",
    )
    config = resolve_config(
        source_dir=layout["source"],
        config_overrides=["scanners.checkov.options.config_file=elsewhere.yaml"],
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    scanner = DetectSecretsScanner(
        config=config.get_plugin_config("scanner", "detect-secrets"),
        context=PluginContext(
            source_dir=layout["source"],
            output_dir=layout["output"],
            work_dir=layout["work"],
            config=config,
        ),
    )
    assert not any(
        layout["product"].as_posix() in (item.path or "")
        for item in scanner.config.options.scan_settings.filters_used
    ), scanner.config.options.scan_settings.filters_used


def _filter_paths(settings: dict) -> list:
    return [f.get("path") for f in settings["filters_used"] if f.get("path")]


@pytest.mark.unit
def test_a_repository_config_cannot_name_a_work_product_as_a_filter(tmp_path):
    """filters_used entries go through the same refusal as plugins_used.
    The entry is the repository's write and sits under the work directory,
    so it is refused."""
    layout = _layout(tmp_path)
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        "      scan_settings:\n"
        "        filters_used:\n"
        f"          - path: file://{layout['product'].as_posix()}::keep\n",
    )
    settings = _scanner_settings(layout, scanner_config=None)
    assert not any(
        layout["product"].as_posix() in (path or "") for path in _filter_paths(settings)
    ), settings["filters_used"]


@pytest.mark.unit
def test_an_operator_filter_naming_the_work_product_is_kept(tmp_path):
    """Control: the operator's own configuration naming the same filter file
    keeps today's answer. Expected: GREEN before and after (the typed config is
    the caller's own object)."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScannerConfig,
    )

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    settings = _scanner_settings(
        layout,
        scanner_config=DetectSecretsScannerConfig(
            options={
                "scan_settings": {
                    "filters_used": [
                        {"path": f"file://{layout['product'].as_posix()}::keep"}
                    ]
                }
            }
        ),
    )
    assert any(
        layout["product"].as_posix() in (path or "") for path in _filter_paths(settings)
    ), settings["filters_used"]


class _SectionsConfig:
    """A stand-in configuration: get_plugin_config answers from a mapping, and
    _operator_reporters is the operator's view (another stand-in)."""

    def __init__(self, sections, operator=None):
        self._sections = sections
        self._operator_reporters = operator

    def get_plugin_config(self, plugin_type, plugin_name):
        return self._sections.get(plugin_name)


@pytest.mark.unit
def test_a_value_the_resolved_walk_cannot_find_is_not_the_operators():
    """A refusal gate fails closed. The resolved section has no
    options.scan_settings.plugins_used place for the walk to read, so the value
    is not shown to be the operator's. A miss is never counted as the
    operator's."""
    from automated_security_helper.config.operator_only_options import (
        operator_wrote_value,
    )

    resolved = _SectionsConfig(
        {"detect-secrets": {"options": {"scan_settings": {}}}},
        operator=_SectionsConfig({"detect-secrets": {"options": {}}}),
    )
    assert not operator_wrote_value(
        resolved,
        "scanner",
        "detect-secrets",
        ("options", "scan_settings", "plugins_used", "path"),
        "file:///x/plugin.py",
    )


@pytest.mark.unit
def test_a_value_both_views_hold_is_the_operators():
    """Control: the same value at the same place in the resolved section and in
    the operator's view is the operator's."""
    from automated_security_helper.config.operator_only_options import (
        operator_wrote_value,
    )

    section = {"options": {"config_file": "/x/c.yaml"}}
    resolved = _SectionsConfig(
        {"checkov": section}, operator=_SectionsConfig({"checkov": section})
    )
    assert operator_wrote_value(
        resolved, "scanner", "checkov", ("options", "config_file"), "/x/c.yaml"
    )


@pytest.mark.unit
def test_a_value_only_the_resolved_section_holds_is_not_the_operators():
    """Control: the resolved section holds a value the operator's view does
    not, so it came from a repository file."""
    from automated_security_helper.config.operator_only_options import (
        operator_wrote_value,
    )

    resolved = _SectionsConfig(
        {"checkov": {"options": {"config_file": "/x/c.yaml"}}},
        operator=_SectionsConfig({"checkov": {"options": {"config_file": None}}}),
    )
    assert not operator_wrote_value(
        resolved, "scanner", "checkov", ("options", "config_file"), "/x/c.yaml"
    )


@pytest.mark.unit
def test_a_value_the_caller_supplied_is_the_operators_when_the_caller_says_so():
    """A scanner built from a configuration object the embedding caller made
    (not read from the resolved configuration) says so explicitly, and its
    values are the operator's whether or not the resolved section holds them."""
    from automated_security_helper.config.operator_only_options import (
        operator_wrote_value,
    )

    resolved = _SectionsConfig(
        {"checkov": {"options": {"config_file": None}}},
        operator=_SectionsConfig({"checkov": {"options": {"config_file": None}}}),
    )
    assert operator_wrote_value(
        resolved,
        "scanner",
        "checkov",
        ("options", "config_file"),
        "/x/own.yaml",
        config_from_context=False,
    )


@pytest.mark.unit
def test_a_repository_trivy_ignore_file_naming_a_work_product_is_refused(
    tmp_path, _no_trivy_env
):
    """The ignore file option takes the same derived-directory refusal as the
    secret config. The scanner passes the output and work directories, so a
    repository value naming either is refused."""
    layout = _layout(tmp_path)
    _repo_config(
        layout["source"],
        "scanners:\n"
        "  trivy-repo:\n"
        "    options:\n"
        f"      ignore_file: {layout['product'].as_posix()}\n",
    )
    passed = _trivy_passed_path(layout, method="_ignore_file")
    assert passed != layout["product"].as_posix(), passed


def _detect_secrets_scanner(layout: dict):
    """A detect-secrets scanner built from the scanned tree's resolved config."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    config = resolve_config(source_dir=layout["source"])
    return DetectSecretsScanner(
        config=config.get_plugin_config("scanner", "detect-secrets"),
        context=PluginContext(
            source_dir=layout["source"],
            output_dir=layout["output"],
            work_dir=layout["work"],
            config=config,
        ),
    )


# Assembled at runtime so this file holds no contiguous key-shaped literal:
# ASH scans its own repository with this scanner.
_PLANTED_KEY = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002


@pytest.mark.unit
def test_a_typed_object_carrying_the_resolved_sections_value_is_still_judged():
    """A configuration object the caller built can be loaded from the resolved
    section (``model_validate`` of ``get_plugin_config``, or another plugin's
    own ``config`` re-wrapped), so the object's Python type is not provenance:
    a value the resolved section holds that the operator's view does not came
    from a repository file, whatever object carried it here."""
    from automated_security_helper.config.operator_only_options import (
        operator_wrote_value,
    )

    resolved = _SectionsConfig(
        {"checkov": {"options": {"config_file": "/x/c.yaml"}}},
        operator=_SectionsConfig({"checkov": {"options": {"config_file": None}}}),
    )
    assert not operator_wrote_value(
        resolved,
        "scanner",
        "checkov",
        ("options", "config_file"),
        "/x/c.yaml",
        config_from_context=False,
    )


@pytest.mark.unit
def test_a_scanner_value_any_recorded_view_holds_is_the_operators():
    """The recorded scanner views are a list: the trusted base, that base with
    the scanners overrides, and the operator's chain files' sections. A value
    only the last view holds is still the operator's."""
    from automated_security_helper.config.operator_only_options import (
        operator_wrote_value,
    )

    narrow = _SectionsConfig({"checkov": {"options": {"config_file": None}}})
    resolved = _SectionsConfig(
        {"checkov": {"options": {"config_file": "/x/own.yaml"}}},
        operator=narrow,
    )
    files_view = _SectionsConfig(
        {"checkov": {"options": {"config_file": "/x/own.yaml"}}}
    )
    resolved._operator_scanner_views = [narrow, files_view]
    assert operator_wrote_value(
        resolved, "scanner", "checkov", ("options", "config_file"), "/x/own.yaml"
    )


@pytest.mark.unit
def test_a_reporter_judgment_never_reads_the_scanner_views():
    """The scanner views hold scanners sections only, so a reporter or
    converter judgment reads the recorded operator configuration itself. Both
    attribute spellings are set so a revision that routes reporter judgments
    through a recorded view list under either name is refused."""
    from automated_security_helper.config.operator_only_options import (
        operator_wrote_value,
    )

    resolved = _SectionsConfig(
        {"aws-security-hub": {"options": {"findings_scope": "/x/scope"}}},
        operator=_SectionsConfig({"aws-security-hub": {"options": {}}}),
    )
    holder = _SectionsConfig(
        {"aws-security-hub": {"options": {"findings_scope": "/x/scope"}}}
    )
    for spelling in ("_operator_scanner_view", "_operator_scanner_views"):
        setattr(resolved, spelling, [holder])
    assert not operator_wrote_value(
        resolved,
        "reporter",
        "aws-security-hub",
        ("options", "findings_scope"),
        "/x/scope",
    )


def _plugin_context(tmp_path):
    """The smallest context a plugin's setup accepts, for the provenance cells."""
    return PluginContext(source_dir=tmp_path / "src", output_dir=tmp_path / "out")


@pytest.mark.unit
def test_a_plugin_built_from_a_dict_section_reads_as_the_contexts(tmp_path):
    from automated_security_helper.base.plugin_base import PluginBase

    plugin = PluginBase(context=_plugin_context(tmp_path), config={"name": "checkov"})
    assert plugin._config_from_context is True


@pytest.mark.unit
def test_a_plugin_built_from_a_typed_object_reads_as_caller_built(tmp_path):
    from automated_security_helper.base.plugin_base import PluginBase
    from automated_security_helper.base.plugin_config import PluginConfigBase

    plugin = PluginBase(
        context=_plugin_context(tmp_path), config=PluginConfigBase(name="checkov")
    )
    assert plugin._config_from_context is False


@pytest.mark.unit
def test_a_callers_declaration_wins_over_the_config_objects_type(tmp_path):
    """A caller that knows the provenance states it, and the declaration is
    consumed by the constructor, never kept as a model field."""
    from automated_security_helper.base.plugin_base import PluginBase
    from automated_security_helper.base.plugin_config import PluginConfigBase

    declared_context = PluginBase(
        context=_plugin_context(tmp_path),
        config=PluginConfigBase(name="checkov"),
        config_from_context=True,
    )
    assert declared_context._config_from_context is True
    declared_own = PluginBase(
        context=_plugin_context(tmp_path),
        config={"name": "checkov"},
        config_from_context=False,
    )
    assert declared_own._config_from_context is False
    assert "config_from_context" not in declared_own.model_dump()


@pytest.mark.unit
def test_a_plugin_model_validate_builds_read_the_configs_provenance(tmp_path):
    """``model_validate`` of a mapping runs the model's own constructor
    (pydantic's custom-init route), so the provenance reads the same as a
    direct construction."""
    from automated_security_helper.base.plugin_base import PluginBase
    from automated_security_helper.base.plugin_config import PluginConfigBase

    from_dict = PluginBase.model_validate(
        {"context": _plugin_context(tmp_path), "config": {"name": "checkov"}}
    )
    assert from_dict._config_from_context is True
    from_typed = PluginBase.model_validate(
        {
            "context": _plugin_context(tmp_path),
            "config": PluginConfigBase(name="checkov"),
        }
    )
    assert from_typed._config_from_context is False


@pytest.mark.unit
def test_a_plugin_made_without_the_constructor_reads_as_the_contexts():
    """``model_construct`` bypasses the constructor, so the provenance is the
    default: read from the context, the stricter judgment."""
    from automated_security_helper.base.plugin_base import PluginBase

    plugin = PluginBase.model_construct()
    assert plugin._config_from_context is True


def _operator_file_scanner_view(config, document, operator_file):
    """The files view built from one operator chain file whose own document is
    *document*: a chain of that one file, nothing the repository's."""
    from automated_security_helper.config.resolve_config import (
        _with_operator_chain_scanners,
    )

    return _with_operator_chain_scanners(
        config, [operator_file], [], {Path(operator_file).resolve(): document}, ()
    )


@pytest.mark.unit
def test_an_operator_file_section_spelled_another_way_folds_onto_the_scanners_key(
    tmp_path,
):
    """A section an operator file spells another way lands on the section the
    scanner reads, not beside it: the lookup for the dump's own key answers
    with the file's values merged in. The file's spelling is a CASE variant
    of the dump's key: the plain merge joins only the "-"/"_" twins of a key,
    so only the fold (``section_fold_key``) can land this spelling on the
    dump's key, and a walk without the fold leaves it as a key of its own,
    which the dump-key lookup answers without the file's values."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    config = resolve_config(source_dir=layout["source"])
    dump_keys = config.scanners.model_dump(by_alias=True)
    (dump_key,) = [
        key for key in dump_keys if key in ("detect-secrets", "detect_secrets")
    ]
    case_variant = dump_key.title()
    assert case_variant != dump_key
    files_view = _operator_file_scanner_view(
        config,
        {
            "scanners": {
                case_variant: {"options": {"scan_settings": {"marker_entry": "held"}}}
            }
        },
        tmp_path / "outside" / "operator.yaml",
    )
    assert files_view is not None
    section = files_view.get_plugin_config("scanner", dump_key)
    assert section["options"]["scan_settings"]["marker_entry"] == "held"


@pytest.mark.unit
def test_a_caller_built_value_matching_a_respelled_section_path_is_judged():
    """A typed model normalizes the doubled separator a file wrote, and the
    spelling difference is not provenance: the resolved section holds the
    same path, so the value is judged by the operator's view, which does
    not hold it."""
    from automated_security_helper.config.operator_only_options import (
        operator_wrote_value,
    )

    resolved = _SectionsConfig(
        {"checkov": {"options": {"config_file": "/out//derived.yaml"}}},
        operator=_SectionsConfig({"checkov": {"options": {"config_file": None}}}),
    )
    assert not operator_wrote_value(
        resolved,
        "scanner",
        "checkov",
        ("options", "config_file"),
        "/out/derived.yaml",
        config_from_context=False,
    )


@pytest.mark.unit
def test_a_value_the_section_spells_with_a_doubled_separator_is_the_operators():
    """The context arm reads the same membership: a value the resolved
    section holds under another spelling of one path is still judged by the
    operator's view, so the operator's own write stays honored."""
    from automated_security_helper.config.operator_only_options import (
        operator_wrote_value,
    )

    resolved = _SectionsConfig(
        {"checkov": {"options": {"config_file": "/x//c.yaml"}}},
        operator=_SectionsConfig(
            {"checkov": {"options": {"config_file": "/x/c.yaml"}}}
        ),
    )
    assert operator_wrote_value(
        resolved, "scanner", "checkov", ("options", "config_file"), "/x/c.yaml"
    )


@pytest.mark.unit
def test_a_parent_segment_is_never_folded_in_an_ownership_comparison():
    """The comparison folds only what a typed path model folds (doubled
    separators and "." segments). A ".." segment stays: the tool is handed
    the resolved real path, which follows a link before it applies "..", so
    the two spellings can name different files."""
    from automated_security_helper.config.operator_only_options import _holds

    assert not _holds("/out/sub/../derived.yaml", ["/out/derived.yaml"])
    assert _holds("/out//derived.yaml", ["/out/derived.yaml"])
    assert _holds("/out/./derived.yaml", ["/out/derived.yaml"])


@pytest.mark.unit
def test_a_bare_name_and_its_dot_relative_spelling_are_one_value():
    """Either side being path-shaped is enough to compare by the one folding
    rule, so a bare name and its "./" spelling meet in both directions."""
    from automated_security_helper.config.operator_only_options import _holds

    assert _holds("a.yaml", ["./a.yaml"])
    assert _holds("./a.yaml", ["a.yaml"])
    assert not _holds("a.yaml", ["b.yaml"])


@pytest.mark.unit
def test_a_url_shaped_value_folds_only_past_its_scheme():
    """``file:///a/b`` is the absolute ``/a/b`` and ``file://a/b`` is ``a/b``
    relative to the source directory: two files. The folding that collapses a
    doubled separator never reads the ``//`` after the scheme as one."""
    from automated_security_helper.config.operator_only_options import _holds

    assert not _holds("file:///a/b", ["file://a/b"])
    assert not _holds("file://a/b", ["file:///a/b"])
    assert not _holds("file:///a/b", ["a/b"])
    assert _holds("file:///a//b", ["file:///a/b"])
    assert _holds("file:///a/./b", ["file:///a/b"])
    assert _holds("file://a/./b", ["file://a/b"])
    assert not _holds("file:///a/b", ["http:///a/b"])


@pytest.mark.unit
def test_a_drive_letter_doubled_separator_is_not_a_url_scheme():
    """``C://dir/a.yaml`` is a path with a doubled separator, not a URL: an
    RFC 3986 scheme here is two or more characters, which leaves a single
    drive letter out. The value folds as the typed path model folds it, so
    the operator's own spelling keeps matching."""
    from automated_security_helper.config.operator_only_options import _holds

    assert _holds("C://dir/a.yaml", ["C:/dir/a.yaml"])
    assert _holds("C:/dir/a.yaml", ["C://dir/a.yaml"])


@pytest.mark.unit
def test_a_separator_past_the_first_segment_does_not_stop_the_fold():
    """A ``://`` past the first segment is not a scheme prefix: the value is
    a path, and the fold covers the whole of it, so the two spellings of one
    path still meet."""
    from automated_security_helper.config.operator_only_options import _holds

    assert _holds("./x/y://z", ["x/y://z"])
    assert _holds("x/y://z", ["./x/y://z"])


@pytest.mark.unit
def test_a_path_typed_field_holding_a_url_is_judged_by_its_collapsed_text():
    """A ``Path``-typed field has already collapsed the separator after the
    scheme (``file:///a/b`` reads back as ``file:/a/b``), so its text folds
    whole and meets the collapsed spelling. The raw ``scheme://`` spelling
    keeps its separator and stays a different value."""
    from pathlib import PurePath

    from automated_security_helper.config.operator_only_options import _holds

    typed_text = os.fspath(PurePath("file:///a/b"))
    assert typed_text == "file:/a/b"
    assert _holds(typed_text, ["file:/./a/b"])
    assert not _holds("file:///a/b", [typed_text])


@pytest.mark.unit
def test_a_scanner_override_in_the_repositorys_spelling_lands_on_the_trusted_key():
    """The scan's own apply resolved an override against the resolved
    configuration, whose spelling of a section the repository chose, and the
    trusted base can spell the same undeclared section another way. The
    replay onto the operator's view respells the override onto the trusted
    base's own key; unrespelled, the trusted base refuses the repository's
    spelling of its section and the operator's value never reaches the
    view."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.resolve_config import (
        _with_scanner_overrides,
        apply_config_overrides,
    )

    trusted = AshConfig.model_validate(
        {"scanners": {"my-scanner": {"enabled": True, "options": {}}}}
    )
    repository = AshConfig.model_validate(
        {"scanners": {"My-Scanner": {"enabled": True, "options": {}}}}
    )
    resolved = apply_config_overrides(repository, ["scanners.My-Scanner.enabled=true"])
    out = _with_scanner_overrides(
        trusted,
        ["scanners.My-Scanner.options.config_file=/x/own.yaml"],
        resolved,
    )
    section = out.get_plugin_config("scanner", "my-scanner")
    assert section["options"].get("config_file") == "/x/own.yaml", section


@pytest.mark.unit
def test_the_scanner_sections_record_is_the_inputs_and_the_input_is_left_alone():
    """The record of the scanner sections the document held is set on the
    rebuilt model, from the input's own sections, and the input keeps none."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.resolve_config import apply_config_overrides

    config = AshConfig.model_validate({"project_name": "t"})
    its_sections = tuple(config.model_dump()["scanners"])

    rebuilt = apply_config_overrides(config, ["scanners.created-one.enabled=true"])

    assert config._scanners_before_overrides is None
    assert rebuilt._scanners_before_overrides == its_sections
    assert "created-one" in rebuilt.model_dump()["scanners"], (
        "control: the override made its own section"
    )
    assert "created-one" not in rebuilt._scanners_before_overrides


@pytest.mark.unit
def test_a_second_application_keeps_the_first_applications_scanner_record():
    """A scanner section an override created is not a section the document
    held: a rebuilt model sent through a second application keeps its first
    application's record, and copies of it carry the record."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.resolve_config import apply_config_overrides

    config = AshConfig.model_validate({"project_name": "t"})
    its_sections = tuple(config.model_dump()["scanners"])

    first = apply_config_overrides(config, ["scanners.created-one.enabled=true"])
    second = apply_config_overrides(first, ["scanners.created-two.enabled=true"])

    assert "created-one" in second.model_dump()["scanners"], (
        "control: the first application's section is in the document"
    )
    assert first._scanners_before_overrides == its_sections
    assert second._scanners_before_overrides == its_sections
    assert "created-one" not in second._scanners_before_overrides
    assert first.model_copy()._scanners_before_overrides == its_sections
    assert first.model_copy(deep=True)._scanners_before_overrides == its_sections


@pytest.mark.unit
def test_the_trusted_fold_has_no_record_to_read_for_another_section():
    """The fold reads the before-overrides record of the section it is given.
    A section that has none is refused, not folded against another section's
    record."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.resolve_config import (
        _folded_onto_trusted,
        apply_config_overrides,
    )

    trusted = AshConfig.model_validate({"project_name": "t"})
    resolved = apply_config_overrides(trusted, ["reporters.created-one.enabled=true"])

    with pytest.raises(AttributeError):
        _folded_onto_trusted(
            trusted,
            ["converters.created-one.enabled=true"],
            resolved,
            section="converters",  # type: ignore[arg-type]
        )
    assert _folded_onto_trusted(
        trusted, ["scanners.created-one.enabled=true"], resolved, section="scanners"
    ) == ["scanners.created-one.enabled=true"]


@pytest.mark.unit
def test_a_plugin_built_without_validation_keeps_a_declared_provenance():
    """``model_construct`` skips the constructor, so it consumes the
    declaration itself: never kept as a field, checked as a real boolean."""
    from automated_security_helper.base.plugin_base import PluginBase

    built = PluginBase.model_construct(config_from_context=False)
    assert built._config_from_context is False
    assert "config_from_context" not in (built.__pydantic_extra__ or {})
    with pytest.raises(TypeError):
        PluginBase.model_construct(config_from_context="false")


def _checkov_built_without_validation(layout: dict, **declaration):
    """A checkov scanner made by ``model_construct`` around a typed
    configuration naming the derived product, whose post-init hook judges the
    configured path while the model is being built."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
        CheckovScannerConfig,
    )

    config = resolve_config(source_dir=layout["source"])
    scanner = CheckovScanner.model_construct(
        config=CheckovScannerConfig(
            options={"config_file": layout["product"].as_posix()}
        ),
        context=PluginContext(
            source_dir=layout["source"],
            output_dir=layout["output"],
            work_dir=layout["work"],
            config=config,
        ),
        **declaration,
    )
    return scanner._resolve_arguments(
        layout["source"], layout["output"] / "results.sarif"
    )


@pytest.mark.unit
def test_a_scanner_built_without_validation_judges_its_path_by_the_declaration(
    tmp_path,
):
    """The declaration must be in force while the scanner's post-init hook
    reads its configured paths, not set afterwards: a scanner declared as
    built from the caller's own configuration keeps a path that configuration
    names."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    argv = _checkov_built_without_validation(layout, config_from_context=False)
    assert argv[argv.index("--config-file") + 1] == layout["product"].as_posix(), argv


@pytest.mark.unit
def test_a_scanner_built_without_validation_and_declaring_nothing_is_judged(
    tmp_path,
):
    """Control: with no declaration, or one saying the configuration came from
    the context, the path the resolved section does not hold is not the
    operator's and is not handed to the tool."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    for declaration in ({}, {"config_from_context": True}):
        argv = _checkov_built_without_validation(layout, **declaration)
        assert not any(layout["product"].as_posix() in a for a in argv), (
            declaration,
            argv,
        )


@pytest.mark.unit
def test_a_plugin_built_without_validation_ignores_an_enclosing_construction():
    """With no declaration the provenance is the context's, the stricter
    judgment, even when the call is made while an enclosing plugin's
    construction has declared the opposite."""
    from automated_security_helper.base.plugin_base import (
        _CONFIG_FROM_CONTEXT,
        PluginBase,
    )

    token = _CONFIG_FROM_CONTEXT.set(False)
    try:
        built = PluginBase.model_construct()
        assert _CONFIG_FROM_CONTEXT.get() is False
    finally:
        _CONFIG_FROM_CONTEXT.reset(token)
    assert built._config_from_context is True


@pytest.mark.unit
def test_a_plugin_provenance_declaration_must_be_a_boolean(tmp_path):
    """``bool("false")`` is True, so a coerced string would declare the
    opposite of its text: only a real boolean declares provenance."""
    from automated_security_helper.base.plugin_base import PluginBase

    with pytest.raises(TypeError):
        PluginBase(
            context=_plugin_context(tmp_path),
            config={"name": "checkov"},
            config_from_context="false",
        )


@pytest.mark.unit
def test_a_files_view_hides_a_value_only_the_resolved_configuration_read(
    tmp_path, caplog
):
    """A value only an outer chain file's scanners section read from the
    environment is recorded on the resolved configuration, never on the
    trusted view the files view is built over: the view redacts with the
    union, so its debug line hides the value either way."""
    from automated_security_helper.config.resolve_config import (
        _with_operator_chain_scanners,
    )
    from automated_security_helper.utils.error_text import config_environment_values
    from automated_security_helper.utils.log import ASH_LOGGER

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    trusted = resolve_config(source_dir=layout["source"])
    resolved = resolve_config(source_dir=layout["source"])
    resolved._environment_values = ["held-resolved-value-7w2"]
    operator_file = tmp_path / "outside" / "operator.yaml"
    files_view = _with_operator_chain_scanners(
        trusted,
        [operator_file],
        [],
        {
            operator_file.resolve(): {
                "scanners": {
                    "detect-secrets": {
                        "options": {
                            "scan_settings": {"marker_entry": "held-resolved-value-7w2"}
                        }
                    }
                }
            }
        },
        (),
        environment_values=config_environment_values(resolved),
    )
    assert files_view is not None
    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        found = files_view.get_plugin_config("scanner", "detect-secrets")
    assert found["options"]["scan_settings"]["marker_entry"], found
    assert "Found config for scanner plugin" in caplog.text
    assert "held-resolved-value-7w2" not in caplog.text


@pytest.mark.unit
def test_a_files_view_answers_only_scanner_sections(tmp_path):
    """The files view holds scanners sections only, so any other plugin type
    reads as not found rather than reaching for a segment the view lacks."""
    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    config = resolve_config(source_dir=layout["source"])
    files_view = _operator_file_scanner_view(
        config,
        {"scanners": {"detect-secrets": {"options": {}}}},
        tmp_path / "outside" / "operator.yaml",
    )
    assert files_view is not None
    assert files_view.get_plugin_config("reporter", "csv") is None


@pytest.mark.unit
def test_a_files_view_debug_line_hides_an_environment_read_value(tmp_path, caplog):
    """The files view's section lookup logs the section under --debug, redacted
    with the configuration's environment-read values: an outer chain file can
    hold an env-substituted value, and the line must not print it."""
    from automated_security_helper.utils.log import ASH_LOGGER

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    config = resolve_config(source_dir=layout["source"])
    config._environment_values = ["held-environment-value-9q4"]
    files_view = _operator_file_scanner_view(
        config,
        {
            "scanners": {
                "detect-secrets": {
                    "options": {
                        "scan_settings": {"marker_entry": "held-environment-value-9q4"}
                    }
                }
            }
        },
        tmp_path / "outside" / "operator.yaml",
    )
    assert files_view is not None
    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        found = files_view.get_plugin_config("scanner", "detect-secrets")
    assert found["options"]["scan_settings"]["marker_entry"], found
    assert "Found config for scanner plugin" in caplog.text
    assert "held-environment-value-9q4" not in caplog.text


@pytest.mark.unit
def test_a_scanner_override_that_does_not_replay_warns_only_when_it_sets_a_path(
    tmp_path, caplog
):
    """When the list does not apply as a whole onto the operator's view, the
    overrides replay one at a time: a failing entry drops only itself, and the
    warning fires only for one that sets a path, since a configured path is
    what this view feeds. The failing entry is one the scan's own apply
    accepted: the repository's resolved configuration holds no such section,
    so an override spelling one another way creates it there, while the
    operator's file holds the section under its own spelling and refuses the
    respelling."""
    from automated_security_helper.config.resolve_config import (
        _with_scanner_overrides,
        apply_config_overrides,
    )
    from automated_security_helper.utils.log import ASH_LOGGER

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    resolved = resolve_config(source_dir=layout["source"])
    trusted = apply_config_overrides(resolved, ["scanners.my-scanner.enabled=true"])
    path_override = "scanners.My-Scanner.options.config_file=/x/own.yaml"
    apply_config_overrides(resolved, [path_override])
    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        out = _with_scanner_overrides(
            trusted,
            [
                path_override,
                "scanners.detect-secrets.options.max_worker_output_mib=7",
            ],
            resolved,
        )
    assert "not judged the operator's" in caplog.text
    section = out.get_plugin_config("scanner", "detect-secrets")
    assert section["options"]["max_worker_output_mib"] == 7
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        _with_scanner_overrides(
            trusted,
            ["scanners.My-Scanner.options.max_worker_output_mib=9"],
            resolved,
        )
    assert "not judged the operator's" not in caplog.text


@pytest.mark.unit
def test_a_scanner_override_that_sets_no_path_and_does_not_replay_is_logged_at_debug(
    tmp_path, caplog
):
    """A dropped override that sets no path is not warned, but the drop is not
    silent either: it is logged at debug level, since the scan's own apply has
    already accepted it and reports nothing about the replay. The failing entry
    is built as in the warning cell above: the operator's file holds the
    section under its own spelling and refuses the respelling."""
    from automated_security_helper.config.resolve_config import (
        _with_scanner_overrides,
        apply_config_overrides,
    )
    from automated_security_helper.utils.log import ASH_LOGGER

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    resolved = resolve_config(source_dir=layout["source"])
    trusted = apply_config_overrides(resolved, ["scanners.my-scanner.enabled=true"])
    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        _with_scanner_overrides(
            trusted,
            ["scanners.My-Scanner.options.max_worker_output_mib=9"],
            resolved,
        )
    assert "sets no path does not apply to the operator's own" in caplog.text
    assert "not judged the operator's" not in caplog.text


@pytest.mark.unit
def test_scanner_overrides_valid_only_together_all_land_on_the_operators_view(
    tmp_path, monkeypatch
):
    """The scan's own apply takes the whole override list at once, so the
    operator's view applies it the same way first: an entry the merged
    document needs a later entry for is not validated alone and dropped. Here
    the first entry is refused by itself and accepted with the second."""
    from automated_security_helper.config import resolve_config as module
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    config = resolve_config(source_dir=layout["source"])
    first = "scanners.detect-secrets.options.max_worker_output_mib=7"
    second = "scanners.detect-secrets.enabled=false"
    real = module.apply_config_overrides
    calls = []

    def needs_both(view, overrides):
        calls.append(list(overrides))
        if overrides == [first]:
            raise ASHConfigValidationError("valid only with the second entry")
        return real(view, overrides)

    monkeypatch.setattr(module, "apply_config_overrides", needs_both)
    out = module._with_scanner_overrides(config, [first, second], config)

    section = out.get_plugin_config("scanner", "detect-secrets")
    assert section["options"]["max_worker_output_mib"] == 7, section
    assert calls == [[first, second]], calls


@pytest.mark.unit
def test_one_unrelated_failure_does_not_drop_overrides_valid_only_together(
    tmp_path, monkeypatch
):
    """When the whole list fails, each override is left out in turn: the one
    whose removal makes the rest validate is dropped, and two entries that
    validate only together both land. Applying the survivors one at a time
    would refuse each of them alone and drop all three. The pair's
    both-or-neither rule is stood in for by the apply, which is replaced."""
    from automated_security_helper.config import resolve_config as module
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    config = resolve_config(source_dir=layout["source"])
    first = "scanners.detect-secrets.options.max_worker_output_mib=7"
    second = "scanners.detect-secrets.enabled=false"
    unrelated = "scanners.detect-secrets.options.max_worker_output_mib=8"
    real = module.apply_config_overrides

    def fake_apply(view, overrides):
        if unrelated in overrides:
            raise ASHConfigValidationError("the unrelated entry never validates")
        if (first in overrides) != (second in overrides):
            raise ASHConfigValidationError("valid only with the other entry")
        return real(view, [o for o in overrides if o != unrelated])

    monkeypatch.setattr(module, "apply_config_overrides", fake_apply)
    out = module._with_scanner_overrides(config, [first, unrelated, second], config)

    section = out.get_plugin_config("scanner", "detect-secrets")
    assert section["options"]["max_worker_output_mib"] == 7, section
    assert section.get("enabled") is False, section


@pytest.mark.unit
def test_independent_failures_still_fall_back_to_applying_one_at_a_time(
    tmp_path, monkeypatch
):
    """No single removal repairs a list with two independent failures, so the
    last resort keeps the entries that do validate and drops only the two."""
    from automated_security_helper.config import resolve_config as module
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    layout = _layout(tmp_path)
    _repo_config(layout["source"], "")
    config = resolve_config(source_dir=layout["source"])
    good = "scanners.detect-secrets.options.max_worker_output_mib=7"
    bad_one = "scanners.detect-secrets.options.max_worker_output_mib=8"
    bad_two = "scanners.detect-secrets.options.max_worker_output_mib=9"
    real = module.apply_config_overrides

    def fake_apply(view, overrides):
        if bad_one in overrides or bad_two in overrides:
            raise ASHConfigValidationError("an independent failure")
        return real(view, overrides)

    monkeypatch.setattr(module, "apply_config_overrides", fake_apply)
    out = module._with_scanner_overrides(config, [bad_one, good, bad_two], config)

    section = out.get_plugin_config("scanner", "detect-secrets")
    assert section["options"]["max_worker_output_mib"] == 7, section
