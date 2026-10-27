# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner's DEBUG lines name no value the config read from the environment.

``--debug`` raises the console level, so a DEBUG line reaches the console and
anything that captures it (CI logs); a scan's file logs stay at INFO
(run_ash_scan's ``_setup_logger`` passes ``get_logger`` no file log level), so
WARNINGs land in ash.log too. A config option can come from the environment
(``${VAR}``), so the lines here are redacted with the config's environment
values (``AshConfig._environment_values``) before they are written, whether
they name such an option or the whole config that holds it, as error_text
redacts an exception's text.
"""

import logging
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils.log import ASH_LOGGER

CANARY_DIR = "ENVCANARY-5e2b"


@pytest.fixture
def debug_logged():
    lines = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _context(tmp_path, value: str) -> PluginContext:
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir(exist_ok=True)
    config = AshConfig(project_name="debug-lines")
    config._environment_values = [value]
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )


def _no_value(lines, control: str) -> None:
    text = "\n".join(lines)
    assert control in text, f"the control: {control!r} was logged:\n{text}"
    assert CANARY_DIR not in text, text


def test_detect_secrets_baseline_lookup(tmp_path, debug_logged):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
        DetectSecretsScannerConfigOptions,
    )

    value = f"/nonexistent/{CANARY_DIR}/.secrets.baseline"
    scanner = DetectSecretsScanner(
        context=_context(tmp_path, value),
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=value)
        ),
    )
    debug_logged.clear()

    scanner._process_config_options()

    _no_value(debug_logged, "Possible baseline file paths")


def test_detect_secrets_scan_config_lines(tmp_path, debug_logged, monkeypatch):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )

    value = f"/nonexistent/{CANARY_DIR}/.secrets.baseline"
    ctx = _context(tmp_path, value)
    (ctx.source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    config = module.DetectSecretsScannerConfig(
        options=module.DetectSecretsScannerConfigOptions(baseline_file=value)
    )
    scanner = module.DetectSecretsScanner(context=ctx, config=config)
    scanner.dependencies_satisfied = True
    # The real _pre_scan runs: the config dumps are its DEBUG lines (scan()'s
    # own copy of them was a duplicate and is gone), so this cell asserts the
    # dump the scan path actually logs. Only the dependency check is replaced:
    # the real one starts a version probe, which the suite's tool guard
    # (rightly) fails.
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)

    def _stop():
        raise RuntimeError("detect-secrets not loaded in this test")

    monkeypatch.setattr(module, "_detect_secrets_api", _stop)
    debug_logged.clear()

    # Stopped once the lines are logged: scan() reports the stub as its failure.
    with pytest.raises(ScannerError, match="detect-secrets not loaded"):
        scanner.scan(target=ctx.source_dir, target_type="source", config=config)

    _no_value(debug_logged, "self.config:")


def test_detect_secrets_default_settings_dump(tmp_path, debug_logged, monkeypatch):
    """The default-settings dump names no env-derived scan_settings value.

    With ``plugins_used`` left empty, ``_process_config_options`` fills in the
    default plugin set and dumps the whole scan_settings model at DEBUG. A
    configured filter survives that dump as given, and its ``keyword_exclude``
    can come from the environment. The branch runs once, when the scanner's
    construction processes its config options, so the dump is asserted on the
    construction-time log and nothing is cleared first.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
        DetectSecretsScannerConfigOptions,
        DetectSecretsScanSettings,
        DetectSecretsScanSettingsFiltersUsed,
    )

    value = f"keyword-{CANARY_DIR}"
    # The baseline lookup checks .secrets.baseline paths against the working
    # directory, so a baseline there would replace the configured settings.
    monkeypatch.chdir(tmp_path)
    DetectSecretsScanner(
        context=_context(tmp_path, value),
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(
                scan_settings=DetectSecretsScanSettings(
                    filters_used=[
                        DetectSecretsScanSettingsFiltersUsed(
                            path="detect_secrets.filters.heuristic.is_likely_id_string",
                            keyword_exclude=value,
                        )
                    ]
                )
            )
        ),
    )

    _no_value(debug_logged, "Default settings identified")


def test_detect_secrets_scan_settings_dump(tmp_path, debug_logged, monkeypatch):
    """scan()'s settings line before the worker names no env-derived value.

    The dict logged there is the one handed to ``transient_settings``, built
    from the configured scan_settings, so a filter's env-derived
    ``keyword_exclude`` reaches it as given. The worker is stubbed to stop the
    scan once the line is logged.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )

    value = f"keyword-{CANARY_DIR}"
    ctx = _context(tmp_path, value)
    monkeypatch.chdir(tmp_path)
    (ctx.source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    config = module.DetectSecretsScannerConfig(
        options=module.DetectSecretsScannerConfigOptions(
            scan_settings=module.DetectSecretsScanSettings(
                plugins_used=[
                    module.DetectSecretsScanSettingsPluginsUsed(name="AWSKeyDetector")
                ],
                filters_used=[
                    module.DetectSecretsScanSettingsFiltersUsed(
                        path="detect_secrets.filters.heuristic.is_likely_id_string",
                        keyword_exclude=value,
                    )
                ],
            )
        )
    )
    scanner = module.DetectSecretsScanner(context=ctx, config=config)
    scanner.dependencies_satisfied = True
    monkeypatch.setattr(scanner, "_pre_scan", lambda **_kwargs: True)

    def _stop(**_kwargs):
        raise RuntimeError("stopped after the settings line")

    monkeypatch.setattr(scanner, "_scan_in_worker", _stop)
    debug_logged.clear()

    # Stopped once the line is logged: scan() reports the stub as its failure.
    with pytest.raises(ScannerError, match="stopped after the settings line"):
        scanner.scan(target=ctx.source_dir, target_type="source", config=config)

    _no_value(debug_logged, "Settings: ")


def test_detect_secrets_invalid_exclude_pattern_warning(
    tmp_path, debug_logged, monkeypatch
):
    """The invalid-exclude-pattern WARNING names no env-derived pattern.

    An exclude pattern that does not compile is quoted back in a WARNING, which
    reaches the console and ash.log at their default levels, and the pattern can
    come from the environment. The pattern raises a bad character range ("[" opens
    a set whose "Y-5" runs backwards), so the scan proceeds past the extraction,
    and the worker is stubbed to stop it there. The error's own text quotes only
    that three-character fragment; the whole-fragment case is the next cell's.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )

    value = f"[{CANARY_DIR}"
    ctx = _context(tmp_path, value)
    monkeypatch.chdir(tmp_path)
    (ctx.source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    config = module.DetectSecretsScannerConfig(
        options=module.DetectSecretsScannerConfigOptions(
            scan_settings=module.DetectSecretsScanSettings(
                plugins_used=[
                    module.DetectSecretsScanSettingsPluginsUsed(name="AWSKeyDetector")
                ],
                filters_used=[
                    module.DetectSecretsScanSettingsFiltersUsed(
                        path="detect_secrets.filters.regex.should_exclude_file",
                        pattern=[value],
                    )
                ],
            )
        )
    )
    scanner = module.DetectSecretsScanner(context=ctx, config=config)
    scanner.dependencies_satisfied = True
    monkeypatch.setattr(scanner, "_pre_scan", lambda **_kwargs: True)

    def _stop(**_kwargs):
        raise RuntimeError("stopped after the warning")

    monkeypatch.setattr(scanner, "_scan_in_worker", _stop)
    debug_logged.clear()

    with pytest.raises(ScannerError, match="stopped after the warning"):
        scanner.scan(target=ctx.source_dir, target_type="source", config=config)

    _no_value(debug_logged, "Invalid exclude pattern")


def test_detect_secrets_invalid_pattern_error_quotes_no_fragment(
    tmp_path, debug_logged, monkeypatch
):
    """The invalid-exclude-pattern WARNING quotes no fragment of the pattern.

    re.error's own message quotes a piece of the pattern, and a bad group name
    quotes the whole name - a fragment of the configured value, which
    whole-value redaction cannot match. When the pattern holds a configured
    value, the warning gives the entry index and the error's position instead
    of the error's own text.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )

    value = f"(?P<{CANARY_DIR}>x)"
    ctx = _context(tmp_path, value)
    # Into tmp_path, as the cells above, so the run does not depend on the
    # directory pytest starts in. A .secrets.baseline planted there was
    # measured not to change this cell: the configured filters still compile
    # the pattern.
    monkeypatch.chdir(tmp_path)
    (ctx.source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    config = module.DetectSecretsScannerConfig(
        options=module.DetectSecretsScannerConfigOptions(
            scan_settings=module.DetectSecretsScanSettings(
                plugins_used=[
                    module.DetectSecretsScanSettingsPluginsUsed(name="AWSKeyDetector")
                ],
                filters_used=[
                    module.DetectSecretsScanSettingsFiltersUsed(
                        path="detect_secrets.filters.regex.should_exclude_file",
                        pattern=[value],
                    )
                ],
            )
        )
    )
    scanner = module.DetectSecretsScanner(context=ctx, config=config)
    scanner.dependencies_satisfied = True
    monkeypatch.setattr(scanner, "_pre_scan", lambda **_kwargs: True)

    def _stop(**_kwargs):
        raise RuntimeError("stopped after the warning")

    monkeypatch.setattr(scanner, "_scan_in_worker", _stop)
    debug_logged.clear()

    with pytest.raises(ScannerError, match="stopped after the warning"):
        scanner.scan(target=ctx.source_dir, target_type="source", config=config)

    # _no_value asserts the warning was logged, so this finds it.
    _no_value(debug_logged, "Invalid exclude pattern")
    line = next(line for line in debug_logged if "Invalid exclude pattern" in line)
    # The warning still says which entry failed and where.
    assert "entry 0" in line, line
    assert "position 4" in line, line


def test_detect_secrets_scan_config_dumps_show_env_value_as_written(
    tmp_path, debug_logged, monkeypatch
):
    """scan()'s config dumps show an env-read option as the reference written.

    The dumps go through the as-written view
    (``ScannerPluginBase._config_as_written``), as _pre_scan's dumps do: each
    value the scan config read from the environment shows as the reference its
    file wrote (``${ASH_FE3_BASE}``), never the value and never a replacement
    for it.
    """
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )

    value = "base-67.file"
    monkeypatch.setenv("ASH_FE3_BASE", value)
    profile = tmp_path / "fe3.ash.yaml"
    profile.write_text(
        "project_name: fe3\n"
        "scanners:\n"
        "  detect-secrets:\n"
        "    enabled: true\n"
        "    options:\n"
        "      baseline_file: ${ASH_FE3_BASE}\n",
        encoding="utf-8",
    )
    scan_config = load_config_file_for_run(profile)[1]
    monkeypatch.chdir(tmp_path)
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir()
    (tmp_path / "source" / "app.py").write_text("print('x')\n", encoding="utf-8")
    ctx = PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=scan_config,
    )
    config = scan_config.scanners.detect_secrets
    # The control: the load read the reference as the value.
    assert str(config.options.baseline_file) == value
    scanner = module.DetectSecretsScanner(context=ctx, config=config)
    scanner.dependencies_satisfied = True
    # The real _pre_scan runs: the dumps are its DEBUG lines (scan()'s own
    # copy was a duplicate and is gone). Only the dependency check is
    # replaced: the real one starts a version probe, which the suite's tool
    # guard (rightly) fails.
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    debug_logged.clear()

    # Stopped once the lines are logged. The configured baseline does not
    # exist and the scan runs without one, so the stop is the first step
    # inside the try, which reports the scan failed.
    def _stop(*_args, **_kwargs):
        raise RuntimeError("stopped after the dumps")

    monkeypatch.setattr(scanner, "_resolve_arguments", _stop)
    with pytest.raises(ScannerError, match="DetectSecretsScanner failed"):
        scanner.scan(target=ctx.source_dir, target_type="source", config=config)

    dumps = [
        line
        for line in debug_logged
        if line.partition("\t")[2].startswith(("self.config: ", "config: "))
    ]
    assert len(dumps) == 2, debug_logged
    for line in dumps:
        assert "${ASH_FE3_BASE}" in line, line
        assert value not in line, line


def test_detect_secrets_scan_config_dumps_show_a_refused_baseline_as_written(
    tmp_path, debug_logged, monkeypatch
):
    """scan()'s config dumps show a refused baseline option as it was written.

    The scanned repository's own config names a baseline under the scan's work
    directory, so the scanner refuses it (it is derived from the scanned
    repository and the option is not the operator's own). The refusal is decided
    where the baseline is used; the config model keeps the option, so the dumps
    do not show ``None`` in its place. The option is a literal: the refusal
    applies to a value the repository's config wrote, and a ``${...}`` reference
    would only add the environment to the cell. The file name carries no digit,
    so the environment-value redaction of the surrounding text cannot touch it.
    """
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )

    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / "app.py").write_text("print('x')\n", encoding="utf-8")
    output = tmp_path / "out"
    work = output / ASH_WORK_DIR_NAME
    work.mkdir(parents=True)
    derived = work / "derived.baseline"
    derived.write_text('{"version": "1.5.0", "results": {}}', encoding="utf-8")
    (source / ".ash" / ".ash.yaml").write_text(
        "project_name: scanned\n"
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        f"      baseline_file: {derived.as_posix()}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    ash_config = resolve_config(source_dir=source)
    ctx = PluginContext(
        source_dir=source, output_dir=output, work_dir=work, config=ash_config
    )
    config = ash_config.get_plugin_config("scanner", "detect-secrets")
    scanner = module.DetectSecretsScanner(context=ctx, config=config)
    scanner.dependencies_satisfied = True
    # The control: the scanner refused the option, so the scan reads no baseline.
    assert not scanner._baseline_in_use()
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    debug_logged.clear()

    def _stop(*_args, **_kwargs):
        raise RuntimeError("stopped after the dumps")

    monkeypatch.setattr(scanner, "_resolve_arguments", _stop)
    with pytest.raises(ScannerError, match="DetectSecretsScanner failed"):
        scanner.scan(target=ctx.source_dir, target_type="source", config=config)

    dumps = [
        line
        for line in debug_logged
        if line.partition("\t")[2].startswith(("self.config: ", "config: "))
    ]
    assert len(dumps) == 2, debug_logged
    for line in dumps:
        assert "derived.baseline" in line, line
        assert "baseline_file: None" not in line, line


def test_detect_secrets_scan_config_dumps_show_a_refused_env_baseline_as_written(
    tmp_path, debug_logged, monkeypatch
):
    """The refused baseline written as an environment reference shows as written.

    The scanned repository's own config names its baseline as a ``${...}``
    reference that resolves to a file under the scan's work directory, so the
    scanner refuses it (derived from the scanned repository, and not the
    operator's own). The refusal is decided where the baseline is used; the
    dumps show the reference the file wrote, never the resolved path and never
    ``None`` in its place. The names carry no digit, so the environment-value
    redaction of the surrounding text cannot touch them.
    """
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )

    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    (source / "app.py").write_text("print('x')\n", encoding="utf-8")
    output = tmp_path / "out"
    work = output / ASH_WORK_DIR_NAME
    work.mkdir(parents=True)
    derived = work / "derived.baseline"
    derived.write_text('{"version": "1.5.0", "results": {}}', encoding="utf-8")
    monkeypatch.setenv("ASH_PROBE_DERIVED", derived.as_posix())
    (source / ".ash" / ".ash.yaml").write_text(
        "project_name: scanned\n"
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        "      baseline_file: ${ASH_PROBE_DERIVED}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    ash_config = resolve_config(source_dir=source)
    ctx = PluginContext(
        source_dir=source, output_dir=output, work_dir=work, config=ash_config
    )
    config = ash_config.get_plugin_config("scanner", "detect-secrets")
    # The control: the load read the reference as the path.
    assert config["options"]["baseline_file"] == derived.as_posix()
    scanner = module.DetectSecretsScanner(context=ctx, config=config)
    scanner.dependencies_satisfied = True
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    debug_logged.clear()

    def _stop(*_args, **_kwargs):
        raise RuntimeError("stopped after the dumps")

    monkeypatch.setattr(scanner, "_resolve_arguments", _stop)
    with pytest.raises(ScannerError, match="DetectSecretsScanner failed"):
        scanner.scan(target=ctx.source_dir, target_type="source", config=config)
    # The control: the scanner refused the option, so the scan reads no baseline.
    assert not scanner._baseline_in_use()

    dumps = [
        line
        for line in debug_logged
        if line.partition("\t")[2].startswith(("self.config: ", "config: "))
    ]
    assert len(dumps) == 2, debug_logged
    for line in dumps:
        assert "${ASH_PROBE_DERIVED}" in line, line
        assert "derived.baseline" not in line, line
        assert "baseline_file: None" not in line, line


@pytest.mark.parametrize(
    "limit,token",
    [
        pytest.param(1000000, "'1000000' s", id="large"),
        pytest.param(7.5, "'7.5' s", id="fraction"),
    ],
)
def test_detect_secrets_timeout_warning_prints_its_limit_whole(
    tmp_path, debug_logged, monkeypatch, limit, token
):
    """The worker-timeout WARNING quotes its limit whole, never '1e+06'.

    The quoted token is what lets a limit read from the environment be
    redacted: a short number is replaced only where a line quotes it whole.
    ``:g`` would write a limit of a million or more as '1e+06', so the token
    is written with ``utils.error_text.limit_text``.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )
    from automated_security_helper.utils import subprocess_utils

    ctx = _context(tmp_path, "unused-canary-value")
    monkeypatch.chdir(tmp_path)
    scanner = module.DetectSecretsScanner(
        context=ctx, config=module.DetectSecretsScannerConfig()
    )
    secrets_collection_cls, _, _ = module._detect_secrets_api()
    scanner._secrets_collection = secrets_collection_cls()
    scanner._secrets_collection.root = ctx.source_dir
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        lambda **_kwargs: {"timed_out": True},
    )
    work_dir = tmp_path / "worker-dir"
    work_dir.mkdir()
    debug_logged.clear()

    scanned = scanner._scan_in_worker(
        baseline=None,
        scan_paths=[str(ctx.source_dir / "app.py")],
        scan_settings_dict={"plugins_used": [{"name": "AWSKeyDetector"}]},
        work_dir=work_dir,
        scan_timeout=limit,
    )

    assert scanned is None
    text = "\n".join(debug_logged)
    assert "timed out after" in text, text
    assert f"timed out after {token}" in text, text
    assert "1e+06" not in text, text


def test_grype_db_settings_read(tmp_path, debug_logged):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
        GrypeScannerConfigOptions,
    )

    unreadable = tmp_path / CANARY_DIR / "grype.yaml"
    unreadable.parent.mkdir()
    unreadable.write_text("db: [unclosed\n", encoding="utf-8")
    value = unreadable.as_posix()
    scanner = GrypeScanner(
        context=_context(tmp_path, value),
        config=GrypeScannerConfig(
            options=GrypeScannerConfigOptions(config_file=value, offline=False)
        ),
    )
    scanner._scanner_offline = lambda: False
    debug_logged.clear()

    scanner._process_config_options()

    _no_value(debug_logged, "for db settings")


def test_the_executor_config_line(tmp_path, debug_logged):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScannerConfig,
        DetectSecretsScannerConfigOptions,
    )
    from tests.unit.core.phases.test_scanner_executor_lifecycle import (
        _make_executor,
        _make_scanner,
        _targets,
    )

    value = f"/nonexistent/{CANARY_DIR}/.secrets.baseline"
    ctx = _context(tmp_path, value)
    (ctx.source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    scanner = _make_scanner(ctx, scripted_result={"status": "ok"})
    scanner.config = DetectSecretsScannerConfig(
        options=DetectSecretsScannerConfigOptions(baseline_file=Path(value))
    )

    _make_executor(ctx)._execute_scanner("scripted", scanner, _targets(ctx))

    _no_value(debug_logged, "scanner_plugin.config")


def test_bandit_excluded_paths_lines(tmp_path, debug_logged):
    """The exclude DEBUG and the no-form WARNING name no env-derived entry.

    The path carries a comma, so it has no bandit --exclude form and the
    WARNING fires beside the DEBUG for the same configured entry.
    """
    from automated_security_helper.models.core import IgnorePathWithReason
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
        BanditScannerConfig,
        BanditScannerConfigOptions,
    )

    path_value = f"src,{CANARY_DIR}"
    reason_value = f"reason-{CANARY_DIR}"
    ctx = _context(tmp_path, path_value)
    ctx.config._environment_values.append(reason_value)
    scanner = BanditScanner(
        context=ctx,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                excluded_paths=[
                    IgnorePathWithReason(path=path_value, reason=reason_value)
                ]
            )
        ),
    )
    debug_logged.clear()

    scanner._configured_excludes(ctx.source_dir, warn=True)

    _no_value(debug_logged, "excluded from")
    _no_value(debug_logged, "has no bandit")


#: Where a path value sits: a value under the home directory no longer
#: matches once a line writes it with ~, so it has to be redacted first.
WHERE = ["elsewhere", "under HOME"]


def _path_value(where: str, tail: str) -> str:
    if where == "elsewhere":
        return f"/scans/{CANARY_DIR}/{tail}"
    return (Path.home() / CANARY_DIR / tail).as_posix()


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("tool", ["checkov", "syft"])
def test_tool_exclude_lines(tmp_path, debug_logged, tool, where):
    from automated_security_helper.models.core import IgnorePathWithReason

    path_value = _path_value(where, "vendored")
    reason_value = f"reason-{CANARY_DIR}"
    ctx = _context(tmp_path, path_value)
    ctx.config._environment_values.append(reason_value)
    entry = IgnorePathWithReason(path=path_value, reason=reason_value)
    if tool == "checkov":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
            CheckovScanner,
            CheckovScannerConfig,
            CheckovScannerConfigOptions,
        )

        scanner = CheckovScanner(
            context=ctx,
            config=CheckovScannerConfig(
                options=CheckovScannerConfigOptions(skip_path=[entry])
            ),
        )
    else:
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
            SyftScanner,
            SyftScannerConfig,
            SyftScannerConfigOptions,
        )

        scanner = SyftScanner(
            context=ctx,
            config=SyftScannerConfig(options=SyftScannerConfigOptions(exclude=[entry])),
        )
    debug_logged.clear()

    scanner._process_config_options()

    _no_value(debug_logged, "excluded from")


@pytest.mark.parametrize("where", WHERE)
def test_pre_scan_config_dumps(tmp_path, debug_logged, monkeypatch, where):
    """_pre_scan's two whole-config DEBUG dumps, the executor-dump class."""
    from automated_security_helper.models.core import IgnorePathWithReason
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
        BanditScannerConfig,
        BanditScannerConfigOptions,
    )

    value = _path_value(where, "vendored")
    ctx = _context(tmp_path, value)
    (ctx.source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    scanner = BanditScanner(
        context=ctx,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                excluded_paths=[IgnorePathWithReason(path=value, reason="vendored")]
            )
        ),
    )
    scanner.results_dir = ctx.output_dir / "scanners" / "bandit"
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    debug_logged.clear()

    assert (
        scanner._pre_scan(
            target=ctx.source_dir, target_type="source", config=scanner.config
        )
        is True
    )

    _no_value(debug_logged, "self.config:")
    _no_value(debug_logged, "config: {")


@pytest.mark.parametrize("where", WHERE)
def test_grype_restricting_config_warning(tmp_path, debug_logged, monkeypatch, where):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
        GrypeScannerConfigOptions,
    )

    config_dir = (tmp_path if where == "elsewhere" else Path.home()) / CANARY_DIR
    config_dir.mkdir()
    grype_config = config_dir / "grype.yaml"
    grype_config.write_text("output: table\n", encoding="utf-8")
    try:
        value = grype_config.as_posix()
        scanner = GrypeScanner(
            context=_context(tmp_path, value),
            config=GrypeScannerConfig(
                options=GrypeScannerConfigOptions(config_file=value, offline=True)
            ),
        )
        monkeypatch.setattr(
            GrypeScanner,
            "_output_restricting_keys",
            staticmethod(lambda p: ["output"]),
        )
        debug_logged.clear()

        scanner._process_config_options()

        _no_value(debug_logged, "restricts which")
    finally:
        # Under HOME, the test's own HOME must be left as it was found.
        grype_config.unlink()
        config_dir.rmdir()


def test_grype_lines_redact_a_config_path_written_with_dot_segments(
    tmp_path, debug_logged, monkeypatch
):
    """A configured path with a "./" segment.

    grype names the config through Path(), which collapses "a/./b" to "a/b",
    a spelling the configured value is not part of. Both lines that name it,
    the restricting-config WARNING and the db-bound DEBUG, are checked.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
        GrypeScannerConfigOptions,
    )

    config_dir = tmp_path / CANARY_DIR
    config_dir.mkdir()
    (config_dir / "grype.yaml").write_text("{invalid yaml: [", encoding="utf-8")
    value = f"{tmp_path.as_posix()}/./{CANARY_DIR}/grype.yaml"
    scanner = GrypeScanner(
        context=_context(tmp_path, value),
        config=GrypeScannerConfig(
            options=GrypeScannerConfigOptions(config_file=value, offline=False)
        ),
    )
    monkeypatch.setattr(
        GrypeScanner, "_output_restricting_keys", staticmethod(lambda p: ["output"])
    )
    monkeypatch.setattr(GrypeScanner, "_scanner_offline", lambda self: False)
    debug_logged.clear()

    scanner._process_config_options()

    # The controls: both lines were logged.
    _no_value(debug_logged, "restricts which")
    _no_value(debug_logged, "for db settings")


@pytest.mark.parametrize("where", WHERE)
def test_grype_db_bound_debug_names_the_config_as_configured(
    tmp_path, debug_logged, monkeypatch, where
):
    """A symlink in the configured path must not defeat the redaction.

    The db-bound helper logs the config it could not read. Resolving the path
    first changes its spelling, and redact_values can only find the spelling
    the config (and so _environment_values) carries.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
        GrypeScannerConfigOptions,
    )

    real_dir = tmp_path / "grype-real-target"
    real_dir.mkdir()
    real_config = real_dir / "grype.yaml"
    real_config.write_text("{invalid yaml: [", encoding="utf-8")
    link = (tmp_path if where == "elsewhere" else Path.home()) / (
        f"{CANARY_DIR}-grype.yaml"
    )
    link.symlink_to(real_config)
    try:
        value = link.as_posix()
        scanner = GrypeScanner(
            context=_context(tmp_path, value),
            config=GrypeScannerConfig(
                options=GrypeScannerConfigOptions(config_file=value, offline=False)
            ),
        )
        monkeypatch.setattr(GrypeScanner, "_scanner_offline", lambda self: False)
        debug_logged.clear()

        scanner._process_config_options()

        line = next(line for line in debug_logged if "for db settings" in line)
        assert "grype-real-target" not in line, line
        assert CANARY_DIR not in line, line
    finally:
        # Under HOME, the test's own HOME must be left as it was found.
        link.unlink()


def _timeout_scanner(tmp_path, monkeypatch, value: str):
    """A detect-secrets scanner ready to drive _scan_in_worker's timeout path."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )
    from automated_security_helper.utils import subprocess_utils

    ctx = _context(tmp_path, value)
    scanner = module.DetectSecretsScanner(
        context=ctx, config=module.DetectSecretsScannerConfig()
    )
    secrets_collection_cls, _, _ = module._detect_secrets_api()
    scanner._secrets_collection = secrets_collection_cls()
    scanner._secrets_collection.root = ctx.source_dir
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        lambda **kwargs: {"timed_out": True},
    )
    work_dir = tmp_path / "worker-dir"
    work_dir.mkdir(exist_ok=True)
    return scanner, work_dir


def test_a_timeout_warning_names_the_option_for_an_env_typed_limit(
    tmp_path, monkeypatch
):
    """A scan_timeout the model typed from the environment never reaches the
    WARNING as a number.

    An environment value "067" loads as 67 (the lax model types it), and the
    message prints Python's spelling, which the redaction needle -- the text
    as the environment wrote it -- never matches. So where an environment
    value types to the limit, the message names the option instead of any
    number. The redaction stays what it is; no needle is matched against
    converted spellings.
    """
    scanner, work_dir = _timeout_scanner(tmp_path, monkeypatch, "067")

    out = scanner._scan_in_worker(
        baseline=None,
        scan_paths=[],
        scan_settings_dict={"plugins_used": [{"name": "AWSKeyDetector"}]},
        work_dir=work_dir,
        scan_timeout=67.0,
    )

    assert out is None
    text = "\n".join(scanner.errors)
    assert "timed out" in text, text
    assert "the configured scan_timeout" in text, text
    assert "67" not in text, text


def _without_embedded_paths(text: str, tmp_path) -> str:
    """Logged lines carry absolute paths and traceback locations -- the
    quoted command's interpreter under the venv, the package's own files,
    the tmp dir, "line N" -- and a short canary can appear inside any of
    them (a worktree or venv dir name, a line number), so value-absence
    checks run with those spans masked. A value echoed on its own is
    outside every masked span and still fails the check."""
    import re
    import sys
    from pathlib import Path

    import automated_security_helper as _ash

    for spelling in (
        str(tmp_path),
        tmp_path.as_posix(),
        sys.executable,
        sys.prefix,
        str(Path(_ash.__file__).parent),
    ):
        if spelling:
            text = text.replace(spelling, "<path>")
    return re.sub(r"line \d+", "line <n>", text)


def test_the_runner_s_own_timeout_line_names_the_option_for_an_env_typed_limit(
    tmp_path, monkeypatch, debug_logged
):
    """The worker runs through the real runner
    (``run_command_with_output_handling``), whose own ERROR line for a
    timeout quotes the limit too. The scanner hands the runner its
    environment values, so an env-typed limit is named there as well and the
    number the environment gave never reaches that line. The runner's start
    is the one thing replaced: it raises the timeout a worker outliving the
    limit would, so nothing is started."""
    import subprocess

    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )
    from automated_security_helper.utils import subprocess_utils

    def _times_out(args, **kwargs):
        raise subprocess.TimeoutExpired(args, kwargs.get("timeout"))

    ctx = _context(tmp_path, "067")
    scanner = module.DetectSecretsScanner(
        context=ctx, config=module.DetectSecretsScannerConfig()
    )
    secrets_collection_cls, _, _ = module._detect_secrets_api()
    scanner._secrets_collection = secrets_collection_cls()
    scanner._secrets_collection.root = ctx.source_dir
    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _times_out)
    work_dir = tmp_path / "worker-dir"
    work_dir.mkdir()
    debug_logged.clear()

    out = scanner._scan_in_worker(
        baseline=None,
        scan_paths=[],
        scan_settings_dict={"plugins_used": [{"name": "AWSKeyDetector"}]},
        work_dir=work_dir,
        scan_timeout=67.0,
    )

    assert out is None
    runner_lines = [line for line in debug_logged if "Command timed out" in line]
    # The control: the real runner logged its own timeout line.
    assert runner_lines, debug_logged
    for line in runner_lines:
        assert "the configured scan_timeout" in line, line
        assert "67" not in _without_embedded_paths(line, tmp_path), line


def test_the_timeout_limit_token_names_the_option_only_for_an_env_typed_limit(
    tmp_path, monkeypatch
):
    """The one shared token both timeout messages print.

    detect-secrets' WARNING and the base class's ScannerError both go through
    it, so the two cannot drift: an env-typed limit becomes the option's name,
    any other limit stays the quoted whole number (limit_text)."""
    scanner, _ = _timeout_scanner(tmp_path, monkeypatch, "067")
    assert scanner._timeout_limit_token(67.0) == "the configured scan_timeout"

    plain, _ = _timeout_scanner(tmp_path, monkeypatch, f"/x/{CANARY_DIR}")
    assert plain._timeout_limit_token(67.0) == "'67' s"


def test_pre_scan_dump_shows_an_env_written_option_as_written(
    tmp_path, debug_logged, monkeypatch
):
    """The real _pre_scan, with an option written as an environment reference:
    the dump shows the reference, not the value.

    Through the real base-class path rather than a patched-away _pre_scan:
    the config is loaded from a file whose ``patch`` reads the value from the
    environment, which is what records the reference the as-written dump
    renders.
    """
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    value = f"/nonexistent/{CANARY_DIR}/.secrets.baseline"
    monkeypatch.setenv("ASH_PROBE_BASELINE", value)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir(exist_ok=True)
    (tmp_path / "source" / "app.py").write_text("print('x')\n", encoding="utf-8")
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        "project_name: debug-lines\n"
        "scanners:\n"
        "  detect-secrets:\n"
        "    options: {}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /scanners/detect-secrets/options/baseline_file\n"
        "    value: ${ASH_PROBE_BASELINE}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    ash_config = resolve_config(config_file)
    scanner_config = ash_config.scanners.detect_secrets
    assert scanner_config.options.baseline_file == value, (
        "the control: the run reads the environment's value"
    )
    ctx = PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=ash_config,
    )
    scanner = DetectSecretsScanner(context=ctx, config=scanner_config)
    # The real dependency check starts a version probe, which the suite's
    # tool guard (rightly) fails; the dumps are what this cell measures.
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    debug_logged.clear()

    assert scanner._pre_scan(
        target=ctx.source_dir, target_type="source", config=scanner_config
    )

    dumps = [line for line in debug_logged if "self.config:" in line]
    assert dumps, debug_logged
    text = "\n".join(dumps)
    assert "${ASH_PROBE_BASELINE}" in text, text
    assert CANARY_DIR not in text, text


def test_an_env_reference_at_scan_timeout_is_refused_by_the_file_load(
    tmp_path, monkeypatch
):
    """Measured for the record: a config FILE cannot source a BUILTIN
    section's scan_timeout from the environment. The field hands env-resolved
    text to its own validation (ScannerOptionsBase names it in
    _env_scalar_typed_fields), and the file load validates strictly, so the
    load refuses the reference naming the variable. An external plugin's
    section in the same file is kept unvalidated and its own model is lax, so
    the env-typed-scan_timeout leak is live on that route, and the
    timeout-message token (pinned by the cells above) is its guard."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.setenv("ASH_PROBE_TIMEOUT", "31744")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        "project_name: debug-lines\n"
        "scanners:\n"
        "  detect-secrets:\n"
        "    options: {}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /scanners/detect-secrets/options/scan_timeout\n"
        "    value: ${ASH_PROBE_TIMEOUT}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(Exception) as refused:
        resolve_config(config_file)

    text = str(refused.value)
    assert "scan_timeout" in text, text
    assert "ASH_PROBE_TIMEOUT" in text, text
    # The refusal must not echo the resolved text, which came from the
    # environment. Path spellings are stripped first: a tmp path can carry
    # any short token.
    for spelling in (str(config_file), config_file.as_posix(), str(tmp_path)):
        text = text.replace(spelling, "")
    assert "31744" not in text, text


@pytest.mark.parametrize(
    ("logger_level", "handler_level", "dumped"),
    [
        pytest.param(logging.INFO, logging.INFO, False, id="info-logger-info-handler"),
        pytest.param(5, logging.INFO, False, id="trace-logger-info-handler"),
        pytest.param(logging.INFO, logging.DEBUG, True, id="info-logger-debug-handler"),
        pytest.param(
            logging.DEBUG, logging.DEBUG, True, id="debug-logger-debug-handler"
        ),
    ],
)
def test_pre_scan_builds_the_dumps_only_when_a_handler_takes_them(
    tmp_path, monkeypatch, logger_level, handler_level, dumped
):
    """The dumps' work is gated on the predicate that decides their delivery.

    _pre_scan runs on every scan of every scanner, so the model_dump, deepcopy
    and as-written rewrite behind the two DEBUG dumps run only when a DEBUG
    line would reach a handler. _plugin_log logs through the logger's _log,
    which skips the logger's own level, so the handlers' levels decide: a
    DEBUG handler under an INFO logger gets the dumps, and under a TRACE
    logger with only an INFO handler the dumps are not built at all (the CLI
    runs its logger at TRACE with its file handlers at INFO).
    """
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )

    ctx = _context(tmp_path, f"/x/{CANARY_DIR}")
    (ctx.source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    config = module.DetectSecretsScannerConfig()
    scanner = module.DetectSecretsScanner(context=ctx, config=config)
    # The real dependency check starts a version probe, which the suite's
    # tool guard (rightly) fails; the dump work is what this cell counts.
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    calls = []
    real = ScannerPluginBase._config_as_written

    def _counted(self, dumped):
        calls.append(1)
        return real(self, dumped)

    monkeypatch.setattr(ScannerPluginBase, "_config_as_written", _counted)
    received = []

    class _Collect(logging.Handler):
        def emit(self, record):
            received.append(record.getMessage())

    # The handler set is the test's own: whatever the suite attached to the
    # logger would otherwise decide the answer.
    monkeypatch.setattr(ASH_LOGGER, "handlers", [_Collect(level=handler_level)])
    monkeypatch.setattr(ASH_LOGGER, "propagate", False)
    previous = ASH_LOGGER.level
    try:
        ASH_LOGGER.setLevel(logger_level)
        assert scanner._pre_scan(
            target=ctx.source_dir, target_type="source", config=config
        )
    finally:
        ASH_LOGGER.setLevel(previous)

    assert bool(calls) is dumped, calls
    assert any("self.config:" in line for line in received) is dumped, received
