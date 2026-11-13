"""Behavior tests for :class:`BanditScanner`'s config, dependency and hook paths.

bandit is not installed here and is normally run through ``uv tool``, so the
whole ``validate_plugin_dependencies`` decision tree and the config-file
discovery in ``_process_config_options`` were unexecuted.

The UV mixin hooks (``_validate_uv_tool_availability``,
``_get_tool_installation_info``, ``_install_uv_tool``) and the module-level
``get_uv_tool_command`` are the seams. The hooks are replaced with lambdas of
the real arity. The resolver is replaced with ``lambda command, **kwargs``: the
scanner passes it the ``from_spec`` keyword, and a stub that names only
``command`` raised on that call, so the stubs accept the keyword rather than
pin its name; the resolver's own arguments are pinned by
``test_resolver_is_asked_about_the_scanners_own_command``. The verified-binary
route is pinned in test_bandit_scanner_exclusions_reach_bandit.py, whose
verifier stubs record their calls. No test here shells out to bandit, and none
is skipped when bandit is absent.

One block is deliberately not covered: ``configure()``'s ``except Exception``
arm. ``self.config = config`` is a plain attribute assignment on a model without
validate_assignment -- verified by assigning a str, an int and a bare object,
all of which succeed -- so nothing inside that try can raise and the handler is
dead code.
"""

import logging
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.path_trust import in_scanned_tree
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners import bandit_scanner
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
    bandit_excluded_path_globs,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Message,
    Message1,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.log import ASH_LOGGER

# With only the mixin hooks patched, a scanner that passed its check would ask uv for
# bandit's version (``uv tool run --from 'bandit[sarif,toml]...' bandit --version``),
# which starts bandit wherever uv can reach it, so the probes answer without a process
# (tests/unit/conftest.py).
pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    context.work_dir.mkdir(parents=True)
    return context


@pytest.fixture
def scanner(plugin_context):
    return BanditScanner(context=plugin_context, config=BanditScannerConfig())


def exclude_tokens(scanner):
    return [a.key for a in scanner.args.extra_args if a.key.startswith("--exclude=")]


def extra_arg_values(scanner, key):
    return [a.value for a in scanner.args.extra_args if a.key == key]


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_scanner_wires_bandit_through_uv(scanner):
    assert scanner.command == "bandit"
    assert scanner.tool_type == ScannerToolType.SAST
    assert scanner.use_uv_tool is True
    assert scanner.args.format_arg == "--format"
    assert scanner.args.format_arg_value == "sarif"
    assert scanner.args.output_arg == "--output"
    assert "--recursive" in [a.key for a in scanner.args.extra_args]


def test_bandit_needs_the_sarif_and_toml_extras(scanner):
    """SARIF output and TOML config each require a bandit extra."""
    assert scanner._get_tool_package_extras() == ["sarif", "toml"]


def test_version_constraint_comes_from_config(plugin_context):
    scanner = BanditScanner(
        context=plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(tool_version=">=1.8.0,<2.0.0")
        ),
    )
    assert scanner._get_tool_version_constraint() == ">=1.8.0,<2.0.0"


@pytest.mark.parametrize(
    "level, verbose_expected",
    [(logging.DEBUG, True), (logging.INFO, False), (logging.WARNING, False)],
)
def test_verbose_flag_is_added_only_at_debug_level(
    plugin_context, monkeypatch, level, verbose_expected
):
    monkeypatch.setattr(ASH_LOGGER, "level", level)

    scanner = BanditScanner(context=plugin_context, config=BanditScannerConfig())

    keys = [a.key for a in scanner.args.extra_args]
    assert ("--verbose" in keys) is verbose_expected, (
        f"at {logging.getLevelName(level)} expected verbose={verbose_expected}; got {keys}"
    )


def test_bandit_treats_exit_code_one_as_success(scanner):
    """bandit exits 1 when it finds something, which is not a scanner failure."""
    assert scanner.success_exit_codes == {0, 1}
    assert scanner.empty_target_log_level == logging.VERBOSE


# ---------------------------------------------------------------------------
# configure()
# ---------------------------------------------------------------------------


def test_configure_replaces_the_config(scanner):
    replacement = BanditScannerConfig(
        options=BanditScannerConfigOptions(confidence_level="high")
    )

    scanner.configure(config=replacement)

    assert scanner.config is replacement
    assert scanner.config.options.confidence_level == "high"


def test_configure_with_none_leaves_the_existing_config(scanner):
    original = scanner.config

    scanner.configure(config=None)

    assert scanner.config is original


# ---------------------------------------------------------------------------
# validate_plugin_dependencies decision tree
# ---------------------------------------------------------------------------


def test_uv_missing_and_bandit_absent_fails_validation(scanner, monkeypatch, caplog):
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: False
    )
    monkeypatch.setattr(
        bandit_scanner, "get_uv_tool_command", lambda command, **kwargs: None
    )

    with caplog.at_level(logging.ERROR):
        assert scanner.validate_plugin_dependencies() is False

    assert scanner.use_uv_tool is True, "no direct fallback was found, so uv stays on"
    assert any("UV is not available" in record.message for record in caplog.records)


@pytest.mark.parametrize(
    "source, expected_log",
    [("uv", "already installed via UV tool"), ("pre_installed", "Using pre-installed")],
)
def test_available_tool_is_accepted_from_either_source(
    scanner, monkeypatch, caplog, source, expected_log
):
    """A tool reported available is used, and its provenance is logged."""
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: True
    )
    monkeypatch.setattr(
        BanditScanner,
        "_get_tool_installation_info",
        lambda self: {
            "available": True,
            "preferred_source": source,
            "pre_installed_path": "bandit-stub",
        },
    )

    with caplog.at_level(logging.INFO):
        assert scanner.validate_plugin_dependencies() is True

    assert scanner.dependencies_satisfied is True
    assert any(expected_log in record.message for record in caplog.records), (
        f"expected a log naming source {source!r}; got {[r.message for r in caplog.records]}"
    )


def test_unavailable_tool_triggers_installation_and_succeeds(
    scanner, monkeypatch, caplog
):
    """A missing tool is installed via uv, with the configured timeout."""
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: True
    )
    monkeypatch.setattr(
        BanditScanner, "_get_tool_installation_info", lambda self: {"available": False}
    )
    install_calls = []

    def _install(self, timeout, retry_config):
        install_calls.append({"timeout": timeout, "retry_config": retry_config})
        return True

    monkeypatch.setattr(BanditScanner, "_install_uv_tool", _install)

    with caplog.at_level(logging.INFO):
        assert scanner.validate_plugin_dependencies() is True

    assert scanner.dependencies_satisfied is True
    assert len(install_calls) == 1
    assert install_calls[0]["timeout"] == scanner.config.options.install_timeout
    assert install_calls[0]["retry_config"]["max_retries"] == 3
    assert any("Successfully installed bandit" in r.message for r in caplog.records)


def test_configured_install_timeout_is_honored(plugin_context, monkeypatch):
    """The install timeout comes from config, not the 300s literal fallback."""
    scanner = BanditScanner(
        context=plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(install_timeout=45)
        ),
    )
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: True
    )
    monkeypatch.setattr(
        BanditScanner, "_get_tool_installation_info", lambda self: {"available": False}
    )
    seen = {}

    def _install(self, timeout, retry_config):
        seen["timeout"] = timeout
        return True

    monkeypatch.setattr(BanditScanner, "_install_uv_tool", _install)

    scanner.validate_plugin_dependencies()

    assert seen["timeout"] == 45


def test_failed_installation_falls_back_to_the_resolver(scanner, monkeypatch, caplog):
    """When uv install fails, the direct-binary resolver gets the last word."""
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: True
    )
    monkeypatch.setattr(
        BanditScanner, "_get_tool_installation_info", lambda self: {"available": False}
    )
    monkeypatch.setattr(
        BanditScanner, "_install_uv_tool", lambda self, timeout, retry_config: False
    )
    monkeypatch.setattr(
        bandit_scanner, "get_uv_tool_command", lambda command, **kwargs: None
    )

    with caplog.at_level(logging.WARNING):
        assert scanner.validate_plugin_dependencies() is False

    assert any(
        "UV tool installation failed for bandit" in r.message for r in caplog.records
    )


def test_resolver_is_asked_about_the_scanners_own_command(scanner, monkeypatch):
    """The resolver must be queried for 'bandit', not some other tool name, and
    under the scan's own ``--from`` spec (the extras and the version range): a
    bare ``bandit`` resolves a different environment, and a stub that threw
    the keywords away could not tell."""
    monkeypatch.setattr(
        BanditScanner, "_validate_uv_tool_availability", lambda self: False
    )
    asked = []

    def _resolver(command, **kwargs):
        asked.append((command, kwargs))

    monkeypatch.setattr(bandit_scanner, "get_uv_tool_command", _resolver)

    scanner.validate_plugin_dependencies()

    assert [command for command, _ in asked] == ["bandit"]
    ((_, kwargs),) = asked
    assert "from_spec" in kwargs, kwargs
    assert kwargs["from_spec"].startswith("bandit[sarif,toml]"), kwargs
    assert ">=1.7.8" in kwargs["from_spec"], kwargs


@pytest.mark.parametrize("offline", [True, False], ids=["offline", "online"])
@pytest.mark.parametrize("route", ["uv-absent", "install-failed"])
def test_the_resolver_is_handed_the_scanners_offline_mode(
    scanner, monkeypatch, route, offline
):
    """Both resolver calls pass the scanner's own offline reading.

    Read from ASH_OFFLINE here, as ``_is_offline_mode`` reads it. Without the
    keyword the resolver followed ASH's global mode alone: a scanner held
    offline on its own was probed online, and the resolver's memo filed that
    answer under the mode the probe ran in, not the one the scanner is in.
    """
    if route == "uv-absent":
        monkeypatch.setattr(
            BanditScanner, "_validate_uv_tool_availability", lambda self: False
        )
    else:
        monkeypatch.setattr(
            BanditScanner, "_validate_uv_tool_availability", lambda self: True
        )
        monkeypatch.setattr(
            BanditScanner,
            "_get_tool_installation_info",
            lambda self: {"available": False},
        )
        monkeypatch.setattr(
            BanditScanner,
            "_install_uv_tool",
            lambda self, timeout, retry_config: False,
        )
    monkeypatch.setenv("ASH_OFFLINE", "YES" if offline else "NO")
    asked = []

    def _resolver(command, **kwargs):
        asked.append(kwargs)

    monkeypatch.setattr(bandit_scanner, "get_uv_tool_command", _resolver)

    scanner.validate_plugin_dependencies()

    assert [kwargs.get("offline") for kwargs in asked] == [offline]


# ---------------------------------------------------------------------------
# Config file selection
# ---------------------------------------------------------------------------


def test_nonexistent_configured_config_file_warns_and_passes_an_empty_ini(
    plugin_context, tmp_path, caplog
):
    """A configured path that is not on disk is reported, not passed to bandit.
    Bandit searches for a ``.bandit`` file itself when it is given no ini, so it
    gets the empty one ASH writes instead."""
    missing = tmp_path / "nowhere" / "bandit.yaml"

    with caplog.at_level(logging.WARNING):
        scanner = BanditScanner(
            context=plugin_context,
            config=BanditScannerConfig(
                options=BanditScannerConfigOptions(config_file=missing)
            ),
        )

    assert any(
        "Configured bandit config file does not exist" in r.message
        for r in caplog.records
    ), f"expected a missing-config warning; got {[r.message for r in caplog.records]}"
    argv = _scan_argv(scanner, plugin_context)
    assert "--configfile" not in argv
    ini = _value_after(argv, "--ini")
    assert len(ini) == 1, ini
    assert ini[0].endswith("bandit-empty.ini"), ini
    assert str(missing) not in ini[0], ini


def _scan_argv(scanner, plugin_context):
    """The argv the scanner would run bandit with for a scan of the source dir."""
    final_args, _, _ = scanner._execute_scan(plugin_context.source_dir, "source", [])
    return [str(arg) for arg in final_args]


def _value_after(argv, flag):
    return [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == flag]


def test_dot_bandit_config_file_is_passed_as_ini(plugin_context, tmp_path):
    """A file literally named .bandit is ini-format, so it uses --ini."""
    config_file = tmp_path / ".bandit"
    config_file.write_text("[bandit]\nexclude = /test\n", encoding="utf-8")

    scanner = BanditScanner(
        context=plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(config_file=config_file)
        ),
    )

    argv = _scan_argv(scanner, plugin_context)
    assert _value_after(argv, "--ini") == [config_file.as_posix()]
    assert extra_arg_values(scanner, "--configfile") == []


def test_processing_the_options_again_builds_each_flag_once(plugin_context, tmp_path):
    """Construction processes the options once; a second call (configure(),
    or a caller that processes them again) appended another --ini,
    --confidence-level, --severity-level and --exclude token beside the first.
    The option arguments now start again from the base ones on every call."""
    config_file = tmp_path / ".bandit"
    config_file.write_text("[bandit]\nexclude = /test\n", encoding="utf-8")
    scanner = BanditScanner(
        context=plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                config_file=config_file, confidence_level="low"
            )
        ),
    )
    once = [(arg.key, arg.value) for arg in scanner.args.extra_args]

    scanner._process_config_options()

    assert [(arg.key, arg.value) for arg in scanner.args.extra_args] == once
    keys = [arg.key for arg in scanner.args.extra_args]
    assert keys.count("--ini") == 1
    assert keys.count("--confidence-level") == 1
    assert keys.count("--severity-level") == 1
    assert sum(key.startswith("--exclude=") for key in keys) == 1
    argv = _scan_argv(scanner, plugin_context)
    assert _value_after(argv, "--ini") == [config_file.as_posix()]

    # Rebuilt from the base, not deduplicated by key: a version that kept the
    # first --confidence-level it saw would also build each flag once, and
    # keep the stale value after configure() with another.
    scanner.configure(
        BanditScannerConfig(
            options=BanditScannerConfigOptions(
                config_file=config_file, confidence_level="high"
            )
        )
    )
    assert extra_arg_values(scanner, "--confidence-level") == ["high"]


@pytest.mark.parametrize("filename", ["bandit.yaml", "bandit.toml", "custom.yaml"])
def test_other_config_filenames_are_passed_as_configfile(
    plugin_context, tmp_path, filename
):
    """Anything not named .bandit goes through --configfile, beside the empty --ini."""
    config_file = tmp_path / filename
    config_file.write_text("skips: []\n", encoding="utf-8")

    scanner = BanditScanner(
        context=plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(config_file=config_file)
        ),
    )

    assert extra_arg_values(scanner, "--configfile") == [config_file.as_posix()]
    # Beside it, the one --ini is ASH's empty file, which ends bandit's own
    # .bandit search (bandit_scanner.BanditScannerConfigOptions.config_file).
    argv = _scan_argv(scanner, plugin_context)
    (ini,) = _value_after(argv, "--ini")
    assert Path(ini).read_text(encoding="utf-8") == "[bandit]\n"


@pytest.mark.parametrize(
    "relative_path",
    [
        ".bandit",
        ".ash/.bandit",
        "bandit.yaml",
        ".ash/bandit.yaml",
        "bandit.toml",
        ".ash/bandit.toml",
    ],
)
def test_a_config_file_in_the_source_directory_is_not_used(
    plugin_context, relative_path
):
    """The repository being scanned does not choose bandit's config.

    ASH used to pass the first of these it found. Now none is passed, and bandit
    gets an empty --ini written outside the scanned tree, so it does not read a
    .bandit under the target on its own either.
    """
    in_tree = plugin_context.source_dir / relative_path
    in_tree.parent.mkdir(parents=True, exist_ok=True)
    in_tree.write_text("[bandit]\nskips = B602\n", encoding="utf-8")

    scanner = BanditScanner(context=plugin_context, config=BanditScannerConfig())
    argv = _scan_argv(scanner, plugin_context)

    assert in_tree.as_posix() not in " ".join(argv)
    assert "--configfile" not in argv
    (ini,) = _value_after(argv, "--ini")
    assert not in_scanned_tree(ini, plugin_context.source_dir)
    assert Path(ini).parent != Path(scanner.results_dir)
    assert Path(ini).read_text(encoding="utf-8") == "[bandit]\n"


def test_no_config_file_anywhere_passes_only_the_empty_ini(scanner, plugin_context):
    """With nothing configured bandit gets no --configfile and ASH's empty --ini,
    so it runs on its defaults and does not look for a .bandit itself."""
    argv = _scan_argv(scanner, plugin_context)
    assert "--configfile" not in argv
    (ini,) = _value_after(argv, "--ini")
    assert Path(ini).read_text(encoding="utf-8") == "[bandit]\n"


def test_a_directory_named_like_a_config_file_is_not_used(plugin_context):
    """A directory named .bandit in the tree chooses nothing: no --configfile,
    and the one --ini is ASH's empty file, not the decoy."""
    decoy = plugin_context.source_dir / ".bandit"
    decoy.mkdir()

    scanner = BanditScanner(context=plugin_context, config=BanditScannerConfig())

    argv = _scan_argv(scanner, plugin_context)
    assert decoy.as_posix() not in " ".join(argv)
    assert "--configfile" not in argv
    (ini,) = _value_after(argv, "--ini")
    assert Path(ini).read_text(encoding="utf-8") == "[bandit]\n"


# ---------------------------------------------------------------------------
# Other config options
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("confidence", ["all", "low", "medium", "high"])
def test_confidence_level_is_passed_through(plugin_context, confidence):
    scanner = BanditScanner(
        context=plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(confidence_level=confidence)
        ),
    )

    assert extra_arg_values(scanner, "--confidence-level") == [confidence]
    # Severity filtering is ASH's job, so bandit is always asked for everything.
    assert extra_arg_values(scanner, "--severity-level") == ["all"]


def test_no_additional_formats_adds_no_format_flag(scanner):
    assert extra_arg_values(scanner, "--format") == []


@pytest.mark.parametrize("ignore_nosec, expected", [(True, True), (False, False)])
def test_ignore_nosec_flag_tracks_the_option(plugin_context, ignore_nosec, expected):
    scanner = BanditScanner(
        context=plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(ignore_nosec=ignore_nosec)
        ),
    )

    keys = [a.key for a in scanner.args.extra_args]
    assert ("--ignore-nosec" in keys) is expected


def test_excluded_paths_are_folded_into_the_exclude_token(plugin_context):
    """User exclusions join the known ignore paths in one --exclude value."""
    scanner = BanditScanner(
        context=plugin_context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                excluded_paths=[
                    IgnorePathWithReason(path="vendor", reason="third party code")
                ]
            )
        ),
    )

    tokens = exclude_tokens(scanner)
    assert len(tokens) == 1
    value = tokens[0][len("--exclude=") :]
    entries = value.split(",")
    # Anchored at the source directory, as each scan anchors them at its
    # target (they were "**/vendor/**" and "<known>/**").
    anchor = Path(plugin_context.source_dir).as_posix()
    for entry in bandit_excluded_path_globs(anchor, "vendor"):
        assert entry in entries
    # The built-in ignore list is still present alongside the user's entry.
    for known in KNOWN_IGNORE_PATHS:
        for entry in bandit_excluded_path_globs(anchor, known):
            assert entry in entries


# ---------------------------------------------------------------------------
# _execute_scan
# ---------------------------------------------------------------------------


def test_execute_scan_returns_argv_and_the_results_path(scanner):
    final_args, results_file, extra = scanner._execute_scan(
        target=scanner.context.source_dir,
        target_type="source",
        global_ignore_paths=[],
    )

    assert results_file == Path(scanner.results_dir) / "source" / "bandit.sarif"
    assert results_file.parent.is_dir(), "the results directory must be created"
    assert extra is None
    assert final_args[0] == "bandit"
    assert "--format" in final_args
    assert final_args[final_args.index("--format") + 1] == "sarif"
    assert scanner.context.source_dir.as_posix() in final_args


def test_execute_scan_writes_converted_results_to_their_own_directory(scanner):
    _, results_file, _ = scanner._execute_scan(
        target=scanner.context.work_dir,
        target_type="converted",
        global_ignore_paths=[],
    )

    assert results_file == Path(scanner.results_dir) / "converted" / "bandit.sarif"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="bandit's walk does not join paths with '/' on Windows, so the scanner "
    "adds no ignored-path entries to --exclude there (_ignore_excludes)",
)
def test_global_ignore_paths_reach_the_exclude_argument(scanner):
    """Globally ignored paths are excluded from the bandit invocation.

    Translated to the bandit glob that skips exactly the ignored directory's
    files (``bandit_exclude_globs``: ``generated/**`` becomes
    ``<target>/generated/*``), anchored at the target as bandit's walk spells it.
    """
    source = scanner.context.source_dir
    (source / "generated").mkdir()
    (source / "generated" / "x.py").write_text("x = 1\n", encoding="utf-8")
    (source / "app.py").write_text("y = 2\n", encoding="utf-8")

    final_args, _, _ = scanner._execute_scan(
        target=source,
        target_type="source",
        global_ignore_paths=[
            IgnorePathWithReason(path="generated/**", reason="build output")
        ],
    )

    exclude = [a for a in final_args if a.startswith("--exclude=")]
    assert len(exclude) == 1, f"expected one --exclude token in argv: {final_args}"
    entries = exclude[0][len("--exclude=") :].split(",")
    assert f"{source.as_posix()}/generated/*" in entries
    assert not any(entry.endswith("app.py") for entry in entries)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="bandit's walk does not join paths with '/' on Windows, so the scanner "
    "adds no ignored-path entries to --exclude there (_ignore_excludes)",
)
def test_the_exclude_argument_is_assembled_at_resolution(scanner):
    """One --exclude in argv, built for the scan, and the options left alone.

    It used to be built once at construction, and the scan's global ignore paths
    were merged into ``excluded_paths`` where nothing read them again.
    """
    source = scanner.context.source_dir
    (source / "generated").mkdir()
    (source / "generated" / "x.py").write_text("x = 1\n", encoding="utf-8")
    seen_during_resolution = {}
    real_resolve = type(scanner)._resolve_arguments

    def _capture(self, target, results_file=None):
        seen_during_resolution["paths"] = [
            p.path for p in self.config.options.excluded_paths
        ]
        return real_resolve(self, target=target, results_file=results_file)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(BanditScanner, "_resolve_arguments", _capture)
        final_args, _, _ = scanner._execute_scan(
            target=source,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="generated/**", reason="build output")
            ],
        )

    assert seen_during_resolution["paths"] == []
    argv_excludes = [a for a in final_args if a.startswith("--exclude=")]
    assert len(argv_excludes) == 1
    assert f"{source.as_posix()}/generated/" in argv_excludes[0]
    assert len(exclude_tokens(scanner)) == 1


def test_global_ignore_paths_do_not_accumulate_across_scans(scanner):
    """The merged list is restored afterwards, so repeated scans do not grow it.

    Without the restore, each scan would re-add the previous scan's global
    ignores and the exclude argument would grow without bound.
    """
    original = list(scanner.config.options.excluded_paths)

    for _ in range(3):
        scanner._execute_scan(
            target=scanner.context.source_dir,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="generated", reason="build output")
            ],
        )

    assert [p.path for p in scanner.config.options.excluded_paths] == [
        p.path for p in original
    ], (
        "excluded_paths was left mutated after _execute_scan; global ignores "
        f"leaked: {[p.path for p in scanner.config.options.excluded_paths]}"
    )


def test_excluded_paths_are_restored_even_when_resolution_fails(scanner, monkeypatch):
    """The restore is in a finally block, so an error still unwinds it."""

    def _boom(self, target, results_file=None):
        raise RuntimeError("argument resolution failed")

    monkeypatch.setattr(BanditScanner, "_resolve_arguments", _boom)
    original = list(scanner.config.options.excluded_paths)

    with pytest.raises(RuntimeError, match="argument resolution failed"):
        scanner._execute_scan(
            target=scanner.context.source_dir,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="generated", reason="build output")
            ],
        )

    assert [p.path for p in scanner.config.options.excluded_paths] == [
        p.path for p in original
    ]


# ---------------------------------------------------------------------------
# _post_process_sarif secret masking
# ---------------------------------------------------------------------------


def sarif_with_message(rule_id, text):
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit")),
                results=[
                    Result(
                        ruleId=rule_id,
                        level=Level.error,
                        message=Message(root=Message1(text=text)),
                    )
                ],
            )
        ],
    )


def test_hardcoded_password_findings_are_masked(scanner):
    """A B105 message keeps its shape but the secret body becomes asterisks.

    Asserted on the positive artifact -- the masked token that replaces the
    value -- rather than only on the absence of the original, which would pass
    even if nothing had been masked because nothing was there.
    """
    secret = "abcdefghijklmnop"
    report = sarif_with_message("B105", f"Possible hardcoded password: '{secret}'")

    masked = scanner._post_process_sarif(
        sarif_report=report, final_args=["bandit"], target=scanner.context.source_dir
    )

    text = masked.runs[0].results[0].message.root.text
    assert text.startswith("Possible hardcoded password: '")
    assert text.endswith("'")
    assert "*" * 10 in text, f"no masked run of asterisks in {text!r}"
    assert secret not in text
    # The masked value keeps the original length, so line offsets still line up.
    assert len(text) == len(f"Possible hardcoded password: '{secret}'")


def test_non_password_rules_are_left_untouched(scanner):
    """Masking is scoped to the hardcoded-password rules.

    This is the control for the test above: if the masker rewrote every
    message, that test would pass for the wrong reason.
    """
    text = "Possible hardcoded password: 'abcdefghijklmnop'"
    report = sarif_with_message("B404", text)

    masked = scanner._post_process_sarif(
        sarif_report=report, final_args=["bandit"], target=scanner.context.source_dir
    )

    assert masked.runs[0].results[0].message.root.text == text
    assert "*" not in masked.runs[0].results[0].message.root.text


@pytest.mark.parametrize("rule_id", ["B105", "B106", "B107"])
def test_all_three_hardcoded_password_rules_are_masked(scanner, rule_id):
    report = sarif_with_message(
        rule_id, "Possible hardcoded password: 'abcdefghijklmnop'"
    )

    masked = scanner._post_process_sarif(
        sarif_report=report, final_args=["bandit"], target=scanner.context.source_dir
    )

    assert "*" in masked.runs[0].results[0].message.root.text


def test_post_process_returns_a_report_with_no_results_unchanged(scanner):
    """An empty run is passed through without error."""
    report = SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name="bandit")), results=[])],
    )

    masked = scanner._post_process_sarif(
        sarif_report=report, final_args=["bandit"], target=scanner.context.source_dir
    )

    assert masked.runs[0].results == []
