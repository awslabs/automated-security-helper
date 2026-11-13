"""Behavior tests for :class:`DetectSecretsScanner`.

Unlike the other scanners in this batch, detect-secrets is a Python dependency
and is importable here, so ``validate_plugin_dependencies()`` always returns
True and there is no subprocess to patch. These tests therefore drive the real
scanner over real files and assert on the findings it genuinely produces --
including one end-to-end scan that must turn a planted credential into a SARIF
result. If the SecretsCollection wiring or the result-building loop broke, that
test fails rather than reporting a clean scan.

The planted credential is assembled at runtime from fragments so that no
contiguous key-shaped literal exists in this file: ASH self-scans its own repo
with this very scanner, and a literal here would be reported as a finding
against the repo.

The baseline-discovery paths (".secrets.baseline" and ".ash/.secrets.baseline")
are resolved relative to the process working directory rather than to
source_dir, so every test that exercises discovery chdirs first. That is a real
property of the code, not a test artifact.
"""

import json
import logging
import multiprocessing
import os
import re
import shlex
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.utils.bare_install_names import find_bare_installs
from tests.utils.detect_secrets_worker import (
    capturing_worker_command,
    failing_worker_command,
    read_capture,
)

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import ASH_REPO_URL, ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    detect_secrets_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
    DetectSecretsScanSettings,
    DetectSecretsScanSettingsFiltersUsed,
    DetectSecretsScanSettingsPluginsUsed,
)

# The scanner's dependency check asked uv for detect-secrets' version (``uv tool run
# detect-secrets --version``), so every scan here started the tool wherever uv could
# reach it. The scan itself runs in ASH's worker, so the probes answer without a
# process (tests/unit/conftest.py).
pytestmark = pytest.mark.usefixtures("no_tool_probes")

# Assembled at runtime so this file contains no contiguous key-shaped literal.
# The value is AWS's own documentation placeholder. FLY002 is suppressed on
# purpose: collapsing this into one string is exactly what must not happen, or
# ASH's own detect-secrets self-scan reports this file as a finding.
PLANTED_KEY = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002
EXCLUDE_FILTER_PATH = "detect_secrets.filters.regex.should_exclude_file"


def source_with_planted_key(directory, name="settings.py"):
    path = Path(directory) / name
    path.write_text(f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'\n", encoding="utf-8")
    return path


def baseline_document(plugins=None, filters=None):
    doc = {
        "version": "1.5.0",
        "plugins_used": plugins if plugins is not None else [],
        "filters_used": filters if filters is not None else [],
        "results": {},
        "generated_at": "2026-01-01T00:00:00Z",
    }
    return doc


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
    return DetectSecretsScanner(
        context=plugin_context, config=DetectSecretsScannerConfig()
    )


# ---------------------------------------------------------------------------
# Construction and dependency validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_scanner_metadata_is_wired(scanner):
    assert scanner.command == "detect-secrets"
    assert scanner.tool_type == ScannerToolType.SECRETS
    assert scanner.tool_version, "the installed detect-secrets version must be recorded"


@pytest.mark.unit
def test_dependencies_are_always_satisfied_because_the_import_succeeded(scanner):
    """detect-secrets is used in-process, so the import is the only requirement."""
    assert scanner.validate_plugin_dependencies() is True


_COMMIT = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret


@pytest.mark.unit
def test_missing_library_log_line_prints_a_bracketed_path_as_is(
    plugin_context, monkeypatch, tmp_path
):
    """The logged reason holds a path, which is data and not Rich markup.

    The console handler parses markup, so a checkout path holding ``[bold]``
    loses it, and one holding ``[/]`` raises MarkupError out of the logging
    call, which here is the scanner's constructor.
    """
    import io

    from rich.console import Console
    from rich.logging import RichHandler

    from automated_security_helper.utils import ash_install
    from automated_security_helper.utils.log import ASH_LOGGER

    checkout = tmp_path / "c[bold]d" / "a[" / "]b"
    checkout.mkdir(parents=True)
    # The separator is "\" on Windows, so the path holds "[\]" there.
    assert f"[{os.sep}]" in str(checkout) and "[bold]" in str(checkout)
    monkeypatch.setattr(
        ash_install,
        "_direct_url",
        lambda: {"url": checkout.as_uri(), "dir_info": {"editable": True}},
    )
    monkeypatch.setitem(sys.modules, "detect_secrets", None)
    buffer = io.StringIO()
    handler = RichHandler(
        console=Console(file=buffer, width=400, color_system=None),
        markup=True,
        show_time=False,
        show_path=False,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    saved_handlers, saved_level = list(ASH_LOGGER.handlers), ASH_LOGGER.level
    ASH_LOGGER.handlers = [handler]
    ASH_LOGGER.setLevel(logging.WARNING)
    try:
        DetectSecretsScanner(
            context=plugin_context, config=DetectSecretsScannerConfig()
        )
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.setLevel(saved_level)

    printed = " ".join(buffer.getvalue().split())
    assert "detect-secrets is not importable" in printed, printed
    assert "c[bold]d" in printed and f"a[{os.sep}]b" in printed, printed


@pytest.mark.parametrize(
    "direct_url, reinstall",
    [
        (
            {
                "url": "https://github.com/awslabs/automated-security-helper.git",
                "vcs_info": {"vcs": "git", "commit_id": _COMMIT},
            },
            "git+https://github.com/awslabs/automated-security-helper.git@" + _COMMIT,
        ),
        (
            {"url": "{checkout_url}", "dir_info": {"editable": True}},
            "-e {checkout}",
        ),
        (None, f"git+{ASH_REPO_URL}.git@v{{version}}"),
    ],
    ids=["git-install-pins-its-commit", "editable-names-its-directory", "no-record"],
)
@pytest.mark.unit
def test_missing_library_reason_names_installs_that_resolve_to_ash(
    plugin_context, monkeypatch, tmp_path, direct_url, reinstall
):
    """Without the library, the recorded reason's install advice resolves to ASH.

    PyPI resolves the bare name ``automated-security-helper`` to an unrelated
    project, so "pip install --force-reinstall automated-security-helper" would
    replace ASH with that project. The reinstall names where the running ASH was
    installed from: a git install's commit, an editable install's directory, and
    the release tag only when the install left no record. Installing
    detect-secrets by name is fine.
    """
    from automated_security_helper.utils import ash_install

    # An editable record names a checkout that exists; a recorded path that is
    # gone is not offered as a reinstall source.
    checkout = tmp_path / "ash"
    checkout.mkdir()
    if direct_url is not None and direct_url["url"] == "{checkout_url}":
        direct_url = {**direct_url, "url": checkout.as_uri()}
    monkeypatch.setattr(ash_install, "_direct_url", lambda: direct_url)
    # A None entry in sys.modules makes `from detect_secrets import ...` raise
    # ImportError, which is what an environment without the library does.
    monkeypatch.setitem(sys.modules, "detect_secrets", None)
    scanner = DetectSecretsScanner(
        context=plugin_context, config=DetectSecretsScannerConfig()
    )
    reason = scanner.dependency_unavailable_reason or ""

    assert "detect-secrets is not importable" in reason
    assert find_bare_installs(reason) == []
    # Compared as the words a shell reads, so a quoted Windows path or a quoted
    # interpreter path compares equal to its unquoted value.
    commands = re.findall(r"`([^`]*)`", reason)
    assert len(commands) == 2, reason
    # Both run uv through the interpreter that runs ASH: a bare `pip` in a uv-made
    # environment is some other Python's pip. With -P (3.11 and later) so the
    # cwd's modules do not shadow uv, and --no-config so a uv.toml in the cwd
    # (the scanned repository) does not steer the install (ash_install's hint).
    uv_pip = [
        sys.executable,
        *(["-P"] if sys.version_info >= (3, 11) else []),
        "-m",
        "uv",
        "pip",
        "install",
        "--no-config",
        "--python",
        sys.executable,
    ]
    expected = [
        *uv_pip,
        "--reinstall-package",
        "automated-security-helper",
        *reinstall.format(version=get_ash_version(), checkout="{}").split(" "),
    ]
    expected = [str(checkout) if word == "{}" else word for word in expected]
    assert shlex.split(commands[0]) == expected, reason
    assert shlex.split(commands[1]) == [*uv_pip, "detect-secrets"], reason


@pytest.mark.unit
def test_default_config_enables_every_detect_secrets_plugin(scanner):
    """With no baseline, all detect-secrets plugins are configured."""
    plugins = scanner.config.options.scan_settings.plugins_used

    assert len(plugins) > 10, (
        f"expected the full detect-secrets plugin set, got {len(plugins)}"
    )
    names = {p.name for p in plugins}
    assert "AWSKeyDetector" in names
    assert "Base64HighEntropyString" in names


@pytest.mark.unit
def test_execute_scan_stub_raises_not_implemented(scanner):
    with pytest.raises(NotImplementedError, match="overrides scan"):
        scanner._execute_scan(
            target=scanner.context.source_dir,
            target_type="source",
            global_ignore_paths=[],
        )


# ---------------------------------------------------------------------------
# Baseline discovery
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "baseline_name", [".secrets.baseline", ".ash/.secrets.baseline"]
)
@pytest.mark.unit
def test_baseline_is_discovered_in_the_source_directory(
    plugin_context, tmp_path, monkeypatch, baseline_name
):
    """Both default baseline locations are found, relative to the scanned
    tree and not to the directory the process runs in."""
    monkeypatch.chdir(tmp_path)
    baseline = plugin_context.source_dir / baseline_name
    baseline.parent.mkdir(parents=True, exist_ok=True)
    baseline.write_text(json.dumps(baseline_document()), encoding="utf-8")

    scanner = DetectSecretsScanner(
        context=plugin_context, config=DetectSecretsScannerConfig()
    )

    # The discovered file is what the scan reads; no option was written, so
    # the option stays unset.
    assert scanner.config.options.baseline_file is None
    assert scanner._baseline_in_use() is True
    assert scanner._baseline_file_path() == baseline.resolve()


@pytest.mark.unit
def test_a_baseline_in_the_working_directory_is_not_the_scans(
    plugin_context, tmp_path, monkeypatch
):
    """``ash --source-dir repo`` run from elsewhere reads repo's baseline, not one
    that happens to sit in the working directory."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".secrets.baseline").write_text(
        json.dumps(baseline_document(plugins=[{"name": "AWSKeyDetector"}])),
        encoding="utf-8",
    )

    scanner = DetectSecretsScanner(
        context=plugin_context, config=DetectSecretsScannerConfig()
    )

    assert scanner.config.options.baseline_file is None


@pytest.mark.unit
def test_a_relative_configured_baseline_is_taken_from_the_source_directory(
    plugin_context, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    # A same-named decoy in the working directory, telling the two apart by
    # the one plugin each names.
    (tmp_path / "custom.baseline").write_text(
        json.dumps(baseline_document(plugins=[{"name": "DecoyMarker"}])),
        encoding="utf-8",
    )
    in_source = plugin_context.source_dir / "custom.baseline"
    in_source.write_text(
        json.dumps(baseline_document(plugins=[{"name": "SourceMarker"}])),
        encoding="utf-8",
    )

    scanner = DetectSecretsScanner(
        context=plugin_context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file="custom.baseline")
        ),
    )

    # The scanned tree's file is the one read; the option keeps the value as
    # written (detect_secrets_scanner._baseline_in_use), and the path the scan
    # reads is resolved from the source directory, not the working directory.
    assert scanner._baseline_in_use()
    assert scanner._baseline_file_path() == in_source.resolve()
    assert str(scanner.config.options.baseline_file) == "custom.baseline"
    assert [p.name for p in scanner.config.options.scan_settings.plugins_used] == [
        "SourceMarker"
    ]


@pytest.mark.unit
def test_explicitly_configured_baseline_wins_over_the_defaults(
    plugin_context, tmp_path, monkeypatch
):
    """A configured baseline_file is checked before the conventional names."""
    monkeypatch.chdir(tmp_path)
    (plugin_context.source_dir / ".secrets.baseline").write_text(
        json.dumps(baseline_document()), encoding="utf-8"
    )
    chosen = tmp_path / "custom.baseline"
    chosen.write_text(json.dumps(baseline_document()), encoding="utf-8")

    scanner = DetectSecretsScanner(
        context=plugin_context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=chosen)
        ),
    )

    assert Path(scanner.config.options.baseline_file) == chosen


@pytest.mark.unit
def test_a_found_configured_baseline_leaves_the_option_as_written(
    plugin_context, tmp_path, monkeypatch
):
    """A relative baseline_file is taken from the scanned tree, and the scan
    reads that file, while the option keeps the spelling the operator wrote
    so every dump of the configuration still shows it."""
    monkeypatch.chdir(tmp_path)
    (plugin_context.source_dir / "custom.baseline").write_text(
        json.dumps(baseline_document(plugins=[{"name": "StandIn"}])),
        encoding="utf-8",
    )
    options = DetectSecretsScannerConfigOptions(baseline_file="custom.baseline")
    written = options.baseline_file

    scanner = DetectSecretsScanner(
        context=plugin_context,
        config=DetectSecretsScannerConfig(options=options),
    )

    assert scanner.config.options.baseline_file == written
    assert str(scanner.config.options.baseline_file) == "custom.baseline"
    assert scanner._baseline_in_use() is True
    assert [p.name for p in scanner.config.options.scan_settings.plugins_used] == [
        "StandIn"
    ]


@pytest.mark.unit
def test_no_baseline_anywhere_leaves_baseline_file_unset(
    plugin_context, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)

    scanner = DetectSecretsScanner(
        context=plugin_context, config=DetectSecretsScannerConfig()
    )

    assert scanner.config.options.baseline_file is None


# ---------------------------------------------------------------------------
# Baseline settings propagation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_baseline_plugins_and_filters_are_loaded_into_scan_settings(
    plugin_context, tmp_path, monkeypatch
):
    """SecretsCollection.load_from_baseline only loads results, not settings.

    So the scanner has to propagate plugins_used and filters_used itself, or the
    baseline's configuration silently fails to apply during scanning.
    """
    monkeypatch.chdir(tmp_path)
    (plugin_context.source_dir / ".secrets.baseline").write_text(
        json.dumps(
            baseline_document(
                plugins=[{"name": "AWSKeyDetector"}, {"name": "JwtTokenDetector"}],
                filters=[{"path": EXCLUDE_FILTER_PATH, "pattern": ["^tests/"]}],
            )
        ),
        encoding="utf-8",
    )

    scanner = DetectSecretsScanner(
        context=plugin_context, config=DetectSecretsScannerConfig()
    )

    plugin_names = [p.name for p in scanner.config.options.scan_settings.plugins_used]
    assert plugin_names == ["AWSKeyDetector", "JwtTokenDetector"], (
        f"baseline plugins were not propagated; got {plugin_names}"
    )
    filter_paths = [f.path for f in scanner.config.options.scan_settings.filters_used]
    assert filter_paths == [EXCLUDE_FILTER_PATH]


@pytest.mark.unit
def test_explicit_scan_settings_are_not_overwritten_by_the_baseline(
    plugin_context, tmp_path, monkeypatch
):
    """A user-provided scan_settings takes precedence over the baseline's."""
    monkeypatch.chdir(tmp_path)
    (plugin_context.source_dir / ".secrets.baseline").write_text(
        json.dumps(baseline_document(plugins=[{"name": "AWSKeyDetector"}])),
        encoding="utf-8",
    )

    scanner = DetectSecretsScanner(
        context=plugin_context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(
                scan_settings=DetectSecretsScanSettings(
                    version="1.5.0",
                    plugins_used=[
                        DetectSecretsScanSettingsPluginsUsed(name="JwtTokenDetector")
                    ],
                )
            )
        ),
    )

    plugin_names = [p.name for p in scanner.config.options.scan_settings.plugins_used]
    assert plugin_names == ["JwtTokenDetector"], (
        f"the baseline overwrote explicit scan_settings; got {plugin_names}"
    )


@pytest.mark.unit
def test_baseline_without_plugins_or_filters_falls_back_to_all_plugins(
    plugin_context, tmp_path, monkeypatch
):
    """An empty baseline still leaves the scanner with a usable plugin set."""
    monkeypatch.chdir(tmp_path)
    (plugin_context.source_dir / ".secrets.baseline").write_text(
        json.dumps({"version": "1.5.0", "results": {}}), encoding="utf-8"
    )

    scanner = DetectSecretsScanner(
        context=plugin_context, config=DetectSecretsScannerConfig()
    )

    assert len(scanner.config.options.scan_settings.plugins_used) > 10


@pytest.mark.unit
def test_unreadable_baseline_warns_and_falls_back_to_defaults(
    plugin_context, tmp_path, monkeypatch, caplog
):
    """A corrupt baseline must not take the scanner down with it."""
    monkeypatch.chdir(tmp_path)
    (plugin_context.source_dir / ".secrets.baseline").write_text(
        "{not valid json", encoding="utf-8"
    )

    with caplog.at_level(logging.WARNING):
        scanner = DetectSecretsScanner(
            context=plugin_context, config=DetectSecretsScannerConfig()
        )

    assert any(
        "Failed to read baseline file settings" in record.message
        for record in caplog.records
    ), f"expected a baseline warning; got {[r.message for r in caplog.records]}"
    # The fallback still configures the full plugin set, so scanning still works.
    assert len(scanner.config.options.scan_settings.plugins_used) > 10


@pytest.mark.unit
def test_missing_configured_baseline_warns_and_falls_back(
    plugin_context, tmp_path, monkeypatch, caplog
):
    """A configured baseline that is not on disk is reported, not fatal."""
    monkeypatch.chdir(tmp_path)

    with caplog.at_level(logging.WARNING):
        scanner = DetectSecretsScanner(
            context=plugin_context,
            config=DetectSecretsScannerConfig(
                options=DetectSecretsScannerConfigOptions(
                    baseline_file=tmp_path / "absent.baseline"
                )
            ),
        )

    assert any(
        "does not exist" in record.message and "absent.baseline" in record.message
        for record in caplog.records
    ), f"expected a missing-baseline warning; got {[r.message for r in caplog.records]}"
    messages = [record.message for record in caplog.records]
    assert sum("does not exist" in m for m in messages) == 1, messages
    # The settings load never opened the missing file: no read failure, no
    # [Errno 2], and the scan will run without a baseline.
    assert not any("Failed to read baseline" in m for m in messages), messages
    assert not any("Errno 2" in m for m in messages), messages
    assert not scanner._baseline_in_use()
    # The config model keeps the option as written, for every dump of it.
    assert scanner.config.options.baseline_file == tmp_path / "absent.baseline"
    assert len(scanner.config.options.scan_settings.plugins_used) > 10


@pytest.mark.parametrize(
    "first_pass, flag, other_flag",
    [
        ("missing", "_configured_baseline_missing", "_configured_baseline_refused"),
        ("refused", "_configured_baseline_refused", "_configured_baseline_missing"),
    ],
)
@pytest.mark.unit
def test_processing_options_again_forgets_an_earlier_baseline_decision(
    tmp_path, monkeypatch, first_pass, flag, other_flag
):
    """The decision not to use a configured baseline belongs to one pass over
    the options. A scanner that went through a pass with a missing or a refused
    baseline and is then pointed at a valid one must use that one: a decision
    left over from the earlier pass would keep the new baseline from ever being
    read."""
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    # The repository writes a config of its own. Without one no operator view
    # is recorded, and operator_wrote_value then reads every value as the
    # operator's (config/operator_only_options.py), so a derived work product
    # named by the configured value would not be refused.
    (source / ".ash" / ".ash.yaml").write_text(
        "project_name: repository\n", encoding="utf-8"
    )
    output = tmp_path / "out"
    work = output / ASH_WORK_DIR_NAME
    work.mkdir(parents=True)
    baseline_document_with_marker = json.dumps(
        baseline_document(plugins=[{"name": "StandIn"}])
    )
    if first_pass == "missing":
        first_baseline = tmp_path / "gone" / "absent.baseline"
    else:
        # A work product derived from the scanned repository, named by a value
        # that is not the operator's own, is refused.
        first_baseline = work / "derived.baseline"
        first_baseline.write_text(baseline_document_with_marker, encoding="utf-8")
    # A baseline_file a repository config writes is the operator's choice and
    # is left out at load (config/tool_config_trust.py), so the configured
    # value is handed over directly and declared the context's: the scanner
    # then judges it as a value the repository wrote, which a derived product
    # is refused as, and a missing file is recorded as missing.
    config = resolve_config(source_dir=source)
    scanner = DetectSecretsScanner(
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(
                baseline_file=first_baseline.as_posix()
            )
        ),
        config_from_context=True,
        context=PluginContext(
            source_dir=source, output_dir=output, work_dir=work, config=config
        ),
    )

    # First pass: the decision is recorded, and the marker plugin is not loaded.
    assert getattr(scanner, flag) is True
    assert getattr(scanner, other_flag) is False
    assert not scanner._baseline_in_use()
    assert "StandIn" not in [
        p.name for p in scanner.config.options.scan_settings.plugins_used
    ]

    # Second pass on the same instance, now pointed at a valid baseline and
    # with the scan settings back at their defaults, as a first pass leaves
    # them for the baseline to fill.
    valid_baseline = tmp_path / "valid.baseline"
    valid_baseline.write_text(baseline_document_with_marker, encoding="utf-8")
    scanner.config.options.baseline_file = valid_baseline
    scanner.config.options.scan_settings.plugins_used = []
    scanner.config.options.scan_settings.filters_used = []
    asked = []
    original = scanner._baseline_file_path

    def _spy():
        asked.append(True)
        return original()

    monkeypatch.setattr(scanner, "_baseline_file_path", _spy)
    scanner._process_config_options()

    assert getattr(scanner, flag) is False
    assert getattr(scanner, other_flag) is False
    assert scanner._baseline_in_use() is True
    assert asked, "the valid baseline was never consulted"
    assert [p.name for p in scanner.config.options.scan_settings.plugins_used] == [
        "StandIn"
    ]


# ---------------------------------------------------------------------------
# Exclude-pattern helpers
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_exclude_patterns_are_compiled_from_a_pattern_list():
    patterns = DetectSecretsScanner._get_baseline_exclude_patterns(
        {
            "filters_used": [
                {"path": EXCLUDE_FILTER_PATH, "pattern": [r"^tests/", r"\.lock$"]}
            ]
        }
    )

    assert len(patterns) == 2
    assert patterns[0].search("tests/test_thing.py")
    assert patterns[1].search("uv.lock")
    assert not patterns[0].search("src/app.py")


@pytest.mark.unit
def test_a_single_string_pattern_is_accepted():
    """detect-secrets baselines allow `pattern` to be a bare string."""
    patterns = DetectSecretsScanner._get_baseline_exclude_patterns(
        {"filters_used": [{"path": EXCLUDE_FILTER_PATH, "pattern": r"^docs/"}]}
    )

    assert len(patterns) == 1
    assert patterns[0].search("docs/index.md")


@pytest.mark.unit
def test_filters_other_than_should_exclude_file_are_ignored():
    """Only the file-exclusion filter contributes patterns."""
    patterns = DetectSecretsScanner._get_baseline_exclude_patterns(
        {
            "filters_used": [
                {"path": "detect_secrets.filters.heuristic.is_likely_id_string"},
                {
                    "path": "detect_secrets.filters.regex.should_exclude_secret",
                    "pattern": [r"^ignored$"],
                },
            ]
        }
    )

    assert patterns == []


@pytest.mark.unit
def test_no_filters_used_yields_no_patterns():
    assert DetectSecretsScanner._get_baseline_exclude_patterns({}) == []


@pytest.mark.unit
def test_an_invalid_exclude_pattern_is_warned_about_and_skipped(caplog):
    """One bad regex must not discard the valid patterns beside it."""
    with caplog.at_level(logging.WARNING):
        patterns = DetectSecretsScanner._get_baseline_exclude_patterns(
            {
                "filters_used": [
                    {"path": EXCLUDE_FILTER_PATH, "pattern": ["[unclosed", r"^ok/"]}
                ]
            }
        )

    assert len(patterns) == 1, "the valid pattern should survive"
    assert patterns[0].search("ok/file.py")
    assert any("Invalid exclude pattern" in r.message for r in caplog.records)


@pytest.mark.unit
def test_file_exclusions_filter_the_matching_paths():
    files = ["src/app.py", "tests/test_app.py", "docs/index.md"]

    kept = DetectSecretsScanner._apply_file_exclusions(files, [re.compile(r"^tests/")])

    assert kept == ["src/app.py", "docs/index.md"]


@pytest.mark.unit
def test_no_exclude_patterns_returns_the_list_unchanged():
    files = ["src/app.py", "tests/test_app.py"]

    assert DetectSecretsScanner._apply_file_exclusions(files, []) == files


# ---------------------------------------------------------------------------
# Multiprocessing start method
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_fork_start_method_is_requested_on_linux(monkeypatch):
    """detect-secrets uses multiprocessing.Pool; spawn recurses without a guard."""
    calls = []
    monkeypatch.setattr(detect_secrets_scanner.sys, "platform", "linux")
    monkeypatch.setattr(
        multiprocessing,
        "set_start_method",
        lambda method, force=False: calls.append((method, force)),
    )

    DetectSecretsScanner._ensure_fork_multiprocessing()

    assert calls == [("fork", True)]


@pytest.mark.unit
def test_an_already_set_start_method_is_tolerated(monkeypatch):
    """A RuntimeError from set_start_method means it is already configured."""
    monkeypatch.setattr(detect_secrets_scanner.sys, "platform", "linux")

    def _raise(method, force=False):
        raise RuntimeError("context has already been set")

    monkeypatch.setattr(multiprocessing, "set_start_method", _raise)

    DetectSecretsScanner._ensure_fork_multiprocessing()


@pytest.mark.unit
def test_non_linux_platforms_are_left_alone(monkeypatch):
    calls = []
    monkeypatch.setattr(detect_secrets_scanner.sys, "platform", "darwin")
    monkeypatch.setattr(
        multiprocessing,
        "set_start_method",
        lambda method, force=False: calls.append(method),
    )

    DetectSecretsScanner._ensure_fork_multiprocessing()

    assert calls == []


# ---------------------------------------------------------------------------
# Early exits
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_empty_target_returns_an_empty_report(scanner):
    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert any("empty or doesn't exist" in err for err in scanner.errors)


@pytest.mark.unit
def test_pre_scan_failure_returns_false(scanner):
    source_with_planted_key(scanner.context.work_dir)

    with patch.object(
        DetectSecretsScanner, "_pre_scan", autospec=True, return_value=False
    ):
        result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is False


@pytest.mark.unit
def test_unsatisfied_dependencies_return_false(scanner):
    """The independent post-_pre_scan dependency guard."""
    source_with_planted_key(scanner.context.work_dir)

    with patch.object(
        DetectSecretsScanner, "_pre_scan", autospec=True, return_value=True
    ):
        scanner.dependencies_satisfied = False
        result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is False


@pytest.mark.unit
def test_a_target_of_only_lockfiles_has_nothing_to_scan(scanner):
    """Lockfiles are excluded by name, so a lockfile-only tree is empty."""
    (scanner.context.work_dir / "package-lock.json").write_text(
        json.dumps({"name": "placeholder", "lockfileVersion": 3}), encoding="utf-8"
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert any("no scannable files found" in err for err in scanner.errors)


# ---------------------------------------------------------------------------
# End-to-end scanning
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_a_planted_credential_becomes_a_sarif_result(scanner):
    """A real detect-secrets scan turns a planted key into a SARIF finding.

    This is the anti-"clean scan" assertion for this module, and it runs the
    genuine scanner rather than a double: if the SecretsCollection wiring or the
    result-building loop regressed, the report would come back empty and look
    like a passing scan.
    """
    planted = source_with_planted_key(scanner.context.work_dir)

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    results = report.runs[0].results
    assert len(results) == 1, (
        f"expected exactly one finding for the planted key in {planted.name}, "
        f"got {len(results)}"
    )
    finding = results[0]
    assert finding.ruleId == "SECRET-AWS-ACCESS-KEY", (
        f"rule id should be derived from the detect-secrets type; got {finding.ruleId}"
    )
    # Level/Kind serialize as their string values on this model.
    assert str(getattr(finding.level, "value", finding.level)) == "error"
    assert str(getattr(finding.kind, "value", finding.kind)) == "fail"
    assert "AWS Access Key" in finding.message.root.text
    assert planted.name in finding.message.root.text

    location = finding.locations[0].physicalLocation.root
    assert location.region.startLine == 1
    assert location.region.endLine == 1
    assert planted.name in str(location.artifactLocation.uri)
    assert "AWS Access Key" in location.region.snippet.text

    tags = finding.properties.tags
    assert "detect-secrets" in tags
    assert "secret" in tags
    assert "tool_name::detect-secrets" in tags


@pytest.mark.integration
def test_the_planted_secret_value_is_not_echoed_into_the_finding(scanner):
    """The finding names the secret's type and location, not its value.

    Asserted alongside the positive checks in the test above, which prove the
    message is populated at all -- an empty message would satisfy an
    absence-only assertion for the wrong reason.
    """
    source_with_planted_key(scanner.context.work_dir)

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    finding = report.runs[0].results[0]
    assert finding.message.root.text, "the message must not be empty"
    serialized = report.model_dump_json()
    assert PLANTED_KEY not in serialized, (
        "the raw credential must not be copied into the report"
    )


@pytest.mark.integration
def test_a_clean_target_produces_no_findings_and_exit_code_zero(scanner):
    """A file with no secrets yields an empty run and resets the exit code."""
    (scanner.context.work_dir / "plain.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )
    scanner.exit_code = 1

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert scanner.exit_code == 0, (
        "a scan that found nothing must not leave a non-zero exit code behind"
    )


@pytest.mark.integration
def test_findings_are_written_to_the_results_file(scanner):
    planted = source_with_planted_key(scanner.context.work_dir)

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    results_file = Path(scanner.results_dir) / "converted" / "results_sarif.sarif"
    assert results_file.is_file(), f"{results_file} was not written"
    written = json.loads(results_file.read_text(encoding="utf-8"))
    rule_ids = [r["ruleId"] for r in written["runs"][0]["results"]]
    assert rule_ids == ["SECRET-AWS-ACCESS-KEY"], (
        f"the persisted report must carry the finding; got {written}"
    )
    assert planted.name in json.dumps(written)


@pytest.mark.integration
def test_report_invocation_describes_the_ash_run(scanner):
    source_with_planted_key(scanner.context.work_dir)

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    invocation = report.runs[0].invocations[0]
    assert invocation.commandLine == "ash-detect-secrets-scanner"
    assert "--target" in invocation.arguments
    assert invocation.executionSuccessful is True
    assert report.runs[0].tool.driver.organization == "Yelp"


@pytest.mark.integration
def test_baseline_results_are_loaded_for_a_source_scan(scanner, tmp_path):
    """A source scan seeds the collection from the baseline before scanning.

    Findings already recorded in the baseline are known-and-accepted, so the
    baseline has to be loaded or every audited secret reappears as new.
    """
    planted = source_with_planted_key(scanner.context.source_dir)
    baseline = tmp_path / "custom.baseline"
    baseline.write_text(
        json.dumps(baseline_document(plugins=[{"name": "AWSKeyDetector"}])),
        encoding="utf-8",
    )
    scanner.config.options.baseline_file = baseline

    report = scanner.scan(target=scanner.context.source_dir, target_type="source")

    # The planted key is not in the baseline's results, so it is still reported.
    assert [r.ruleId for r in report.runs[0].results] == ["SECRET-AWS-ACCESS-KEY"]
    assert planted.name in report.runs[0].results[0].message.root.text


@pytest.mark.integration
def test_excluded_files_are_never_handed_to_detect_secrets(scanner, monkeypatch):
    """The exclude patterns are applied to the scan set, not only to findings.

    This is the assertion that actually pins the pre-filter. detect-secrets
    honors should_exclude_file internally too, so a test that only checks the
    finding disappeared passes even when the pre-filter is deleted -- the
    library's own filter catches it downstream. The pre-filter exists to avoid
    the file I/O and entropy work in the first place, and the only place that is
    observable is the argument list handed to scan_files.

    Both directions are asserted: the excluded file is absent and the kept file
    is present, so the test cannot pass by handing over nothing at all.

    The pattern is matched against each file's path relative to the scan root
    (the converted target here), never the absolute path, so pytest's per-test
    tmp directory, which is named after the test, cannot match it.
    """
    # The scan runs in a worker subprocess, so the list handed to scan_files is
    # observed as the worker's request: the worker passes request["paths"] to
    # scan_files unchanged. See tests/utils/detect_secrets_worker.py.
    capture_file = scanner.context.output_dir / "captured-request.json"
    monkeypatch.setattr(
        DetectSecretsScanner,
        "_worker_command",
        staticmethod(capturing_worker_command(capture_file)),
    )

    source_with_planted_key(scanner.context.work_dir, name="skipme_settings.py")
    source_with_planted_key(scanner.context.work_dir, name="keepme_settings.py")
    # A second pattern that can match only the absolute path: the name of the
    # directory pytest made for this test, which holds the scan root. Matched
    # against the absolute path it would exclude every file; the docstring's
    # claim is that it excludes none.
    tmp_component = scanner.context.work_dir.parent.name
    assert tmp_component and tmp_component not in "keepme_settings.py"
    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(
            path=EXCLUDE_FILTER_PATH,
            pattern=[r"skipme_settings\.py$", re.escape(tmp_component)],
        )
    ]

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    captured = read_capture(capture_file)["paths"]
    assert captured, "no files were handed to detect-secrets at all"
    assert not any("skipme_settings.py" in f for f in captured), (
        f"the excluded file was still handed to detect-secrets: {captured}"
    )
    assert any("keepme_settings.py" in f for f in captured), (
        f"the kept file should still be scanned: {captured}"
    )


@pytest.mark.integration
def test_baseline_exclude_patterns_remove_files_before_scanning(scanner, caplog):
    """A planted key inside an excluded file is not reported.

    End-to-end companion to the test above. Note that this outcome is also
    guaranteed by detect-secrets' own should_exclude_file filter, so it does not
    on its own prove the scanner pre-filtered anything.
    """
    source_with_planted_key(scanner.context.work_dir, name="skipme_settings.py")
    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(
            path=EXCLUDE_FILTER_PATH, pattern=[r"skipme_settings\.py$"]
        )
    ]

    with caplog.at_level(logging.DEBUG):
        report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == [], (
        "the planted key sat in an excluded file and must not be reported"
    )


@pytest.mark.integration
def test_a_non_matching_exclude_pattern_leaves_the_finding_in_place(scanner):
    """Control for the exclusion test: the filter must be what silenced it."""
    source_with_planted_key(scanner.context.work_dir, name="skipme_settings.py")
    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(
            path=EXCLUDE_FILTER_PATH, pattern=[r"nothing_matches_this\.py$"]
        )
    ]

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert [r.ruleId for r in report.runs[0].results] == ["SECRET-AWS-ACCESS-KEY"]


@pytest.mark.integration
def test_global_ignore_paths_exclude_files_from_the_scan(scanner):
    """A globally ignored path is dropped from the scan set."""
    source_with_planted_key(scanner.context.work_dir, name="generated_settings.py")

    report = scanner.scan(
        target=scanner.context.work_dir,
        target_type="converted",
        global_ignore_paths=[
            IgnorePathWithReason(path="**/generated_*.py", reason="generated code")
        ],
    )

    assert report.runs[0].results == [], (
        "the planted key was in a globally ignored file and must not be reported"
    )


@pytest.mark.integration
def test_a_global_ignore_path_ending_in_a_slash_drops_the_directory(scanner):
    """``**/generated/`` names a directory, so the key planted in it is not read."""
    directory = Path(scanner.context.work_dir) / "generated"
    directory.mkdir(parents=True, exist_ok=True)
    source_with_planted_key(directory)

    report = scanner.scan(
        target=scanner.context.work_dir,
        target_type="converted",
        global_ignore_paths=[
            IgnorePathWithReason(path="**/generated/", reason="generated code")
        ],
    )

    assert report.runs[0].results == [], (
        "the planted key was below a globally ignored directory"
    )


@pytest.mark.integration
def test_an_ignore_path_for_dot_directories_still_scans_a_dotfile(scanner):
    """``**/.*/`` names what is inside dot-directories, not the dotfiles: a key
    planted in ``.env`` is still found, while one in ``.cache/`` is not read."""
    work = Path(scanner.context.work_dir)
    source_with_planted_key(work, name=".env")
    hidden = work / ".cache"
    hidden.mkdir(parents=True, exist_ok=True)
    source_with_planted_key(hidden, name="settings.py")

    report = scanner.scan(
        target=scanner.context.work_dir,
        target_type="converted",
        global_ignore_paths=[
            IgnorePathWithReason(path="**/.*/", reason="dot-directories")
        ],
    )

    locations = [
        result.locations[0].physicalLocation.root.artifactLocation.uri
        for result in report.runs[0].results
    ]
    assert [Path(uri).name for uri in locations] == [".env"], locations


@pytest.mark.integration
def test_a_non_matching_global_ignore_leaves_the_finding_in_place(scanner):
    """Control for the global-ignore test above."""
    source_with_planted_key(scanner.context.work_dir, name="generated_settings.py")

    report = scanner.scan(
        target=scanner.context.work_dir,
        target_type="converted",
        global_ignore_paths=[
            IgnorePathWithReason(path="**/unrelated_*.py", reason="not this one")
        ],
    )

    assert [r.ruleId for r in report.runs[0].results] == ["SECRET-AWS-ACCESS-KEY"]


@pytest.mark.integration
def test_multiple_secrets_across_files_all_report(scanner, monkeypatch):
    """Every file with a finding contributes to the results list.

    This is the only test here that hands detect-secrets more than one file, so
    it is the only one that takes SecretsCollection.scan_files' multiprocessing
    branch. That branch keys each finding by
    ``os.path.relpath(secret.filename, self.root)``, and root defaults to "",
    which resolves to the process working directory. The single-file branch
    keys by the path it was handed and computes no relative path at all, which
    is why the rest of this module is indifferent to the cwd.

    Two drives have no relative path between them on Windows, so that relpath
    raises ValueError whenever the scanned tree and the cwd sit on different
    drives -- which is the normal arrangement on hosted Windows runners, where
    the temp directory and the checkout are on different drives. Chdir'ing into
    the scan target puts both on one drive by construction and leaves the keys
    as bare filenames on every platform.
    """
    source_with_planted_key(scanner.context.work_dir, name="first.py")
    source_with_planted_key(scanner.context.work_dir, name="second.py")
    monkeypatch.chdir(scanner.context.work_dir)

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert len(report.runs[0].results) == 2
    reported_files = " ".join(r.message.root.text for r in report.runs[0].results)
    assert "first.py" in reported_files
    assert "second.py" in reported_files


@pytest.mark.integration
def test_an_unexpected_failure_is_wrapped_in_scanner_error(scanner, monkeypatch):
    """Errors inside the scan body surface as ScannerError."""
    source_with_planted_key(scanner.context.work_dir)

    # The scan body runs in a worker subprocess; this one raises where the real
    # worker would enter transient_settings. See tests/utils/detect_secrets_worker.py.
    monkeypatch.setattr(
        DetectSecretsScanner,
        "_worker_command",
        staticmethod(failing_worker_command("transient settings failed")),
    )

    with pytest.raises(ScannerError) as excinfo:
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert "DetectSecretsScanner failed" in str(excinfo.value)
    assert "transient settings failed" in str(excinfo.value)


@pytest.mark.unit
def test_the_baseline_read_is_the_file_that_was_checked(tmp_path, monkeypatch):
    """_read_baseline parses only the file the containment check judged: one whose
    device and inode differ when it is opened is refused."""
    import os

    baseline = tmp_path / ".secrets.baseline"
    baseline.write_text(json.dumps(baseline_document()), encoding="utf-8")
    assert DetectSecretsScanner._read_baseline(baseline)["version"]

    real_fstat = os.fstat

    def another_file(fd):
        stat = real_fstat(fd)
        return os.stat_result((stat.st_mode, stat.st_ino + 1, *tuple(stat)[2:]))

    monkeypatch.setattr(os, "fstat", another_file)
    with pytest.raises(OSError, match="changed while it was being read"):
        DetectSecretsScanner._read_baseline(baseline)


@pytest.mark.unit
def test_a_baseline_that_is_not_a_regular_file_is_refused_without_blocking(tmp_path):
    """A FIFO named .secrets.baseline (an extracted archive can hold one) would
    block an open() forever; it is refused before ASH opens it."""
    import os

    fifo = tmp_path / ".secrets.baseline"
    try:
        os.mkfifo(fifo)
    except (AttributeError, OSError):
        pytest.skip("FIFOs are not available here")
    with pytest.raises(OSError, match="not a regular file"):
        DetectSecretsScanner._read_baseline(fifo)
