"""What a shipped scanner says it will serve in one run.

A scanner's can-serve set is static: every category it can report in any run. The
set it serves in one run follows its modes: the trivy scanners the run turns on, the
checkov frameworks it passes, the ferret-scan checks it asks for, the mcp-config
rules it switches on. ``categories_for_run()`` reads each mode option through the
map the option declares, and a scanner whose options declare no map serves its
can-serve set. ``classify_result()`` gives a result the run's category when the run
serves exactly one, and no category otherwise.

The expected sets are the maps' own values applied to the modes each scanner is
given, and the modes are what the scanner actually runs, not what its option says:
the builtin trivy keeps a scanner set other than its default only when the operator
chose it, checkov runs an operator file's frameworks in place of its default
``all`` and leaves the hosted-settings frameworks out of ``all``, and trivy-repo with
no scanners named runs what trivy reads from ``TRIVY_SCANNERS``, then from the
operator's config file, then trivy's own default.

Every scanner is built the way its own tests build it, over an empty scanned tree.
Construction starts no tool, and the unit tests' tool guard (tests/unit/conftest.py)
answers every probe a scanner could make.
"""

from __future__ import annotations

import importlib
import os
from functools import partial
from pathlib import Path
from typing import Any, Callable, Optional, get_args

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckFrameworks,
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_vcs_frameworks import (
    KNOWN_VCS_CONFIGURATION_FRAMEWORKS,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.mcp_config_scanner import (
    McpConfigScanner,
    McpConfigScannerConfig,
    McpConfigScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScannerConfig,
    FerretScannerConfigOptions,
    FerretScanScanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

#: trivy-repo's map. It scans no image, so ``vuln`` serves ``sca`` alone.
_TRIVY_REPO_MAP: dict[str, tuple[str, ...]] = {
    "vuln": ("sca",),
    "misconfig": ("iac",),
    "secret": ("secrets",),
    "license": ("license",),
}

#: Every mcp-config rule switched off and both prefix lists empty, as the scanner's
#: own tests write it.
_EVERY_RULE_OFF: dict[str, Any] = {
    "forbid_privilege_escalation": False,
    "forbid_unpinned_runners": False,
    "forbid_auto_approval": False,
    "require_local": False,
    "remote_url_prefixes": [],
    "allowed_command_prefixes": [],
    "flag_env_secrets": False,
}

#: Results of the shapes a classifier is handed: none at all, an empty SARIF result,
#: and a SARIF result whose tag names another category. The base classifier reads
#: none of them, so a run that serves one category gives each of them that category.
_RESULTS: tuple[object, ...] = (
    None,
    {},
    {
        "ruleId": "any-rule",
        "message": {"text": "a finding"},
        "properties": {"tags": ["category::secrets"]},
    },
)


@pytest.fixture(autouse=True)
def _no_trivy_setting_and_no_offline_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test here inherits a ``TRIVY_`` variable or ``ASH_OFFLINE`` from its shell.

    trivy-repo with no scanners named reads ``TRIVY_SCANNERS`` and the file that
    ``TRIVY_CONFIG`` names, and ``ASH_OFFLINE`` changes the arguments a scanner
    builds, so each test sets what it reads and nothing else reaches it.
    """
    for name in list(os.environ):
        if name.startswith("TRIVY_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


# ---- reading the new names ------------------------------------------------------


def _scan_category() -> Any:
    """``ScanCategory``, reached when a test runs so this module imports without it."""
    enums = importlib.import_module("automated_security_helper.core.enums")
    category = getattr(enums, "ScanCategory", None)
    assert category is not None, "core.enums has no ScanCategory"
    return category


def _categories(*values: str) -> frozenset[Any]:
    """The categories ``values`` name, as members."""
    category = _scan_category()
    return frozenset(category(value) for value in values)


def _named(categories: frozenset[Any]) -> list[str]:
    """``categories`` as sorted values, for a failure message."""
    return sorted(str(category) for category in categories)


def _will_serve(scanner: Any) -> frozenset[Any]:
    """``scanner.categories_for_run()``, held to its type: a frozenset of categories."""
    method = getattr(scanner, "categories_for_run", None)
    assert method is not None, (
        f"{type(scanner).__name__} has no categories_for_run: ScannerPluginBase "
        "does not define it"
    )
    served = method()
    category = _scan_category()
    assert isinstance(served, frozenset), f"categories_for_run() gave {served!r}"
    assert all(isinstance(item, category) for item in served), served
    return served


def _mode_values(scanner: Any, field_name: str) -> Optional[list[str]]:
    """The scanner's own reading of a mode option: map keys, or None for every mode."""
    method = getattr(scanner, "_category_mode_values", None)
    assert method is not None, f"{type(scanner).__name__} has no _category_mode_values"
    return method(field_name)


def _base_mode_values(scanner: Any, field_name: str) -> Optional[list[str]]:
    """ScannerPluginBase's reading of an option, whatever the scanner overrides."""
    method = getattr(ScannerPluginBase, "_category_mode_values", None)
    assert method is not None, "ScannerPluginBase has no _category_mode_values"
    return method(scanner, field_name)


def _declared(scanner: Any) -> tuple[Any, ...]:
    """``scanner.declared_categories()``: what the scanner can serve."""
    method = getattr(scanner, "declared_categories", None)
    assert method is not None, f"{type(scanner).__name__} has no declared_categories"
    return method()


def _classify(scanner: Any, result: object) -> frozenset[Any]:
    """``scanner.classify_result(result)``, held to its type."""
    method = getattr(scanner, "classify_result", None)
    assert method is not None, f"{type(scanner).__name__} has no classify_result"
    classified = method(result)
    assert isinstance(classified, frozenset), f"classify_result() gave {classified!r}"
    return classified


def _over_trivy_repo_map(names: list[str]) -> frozenset[Any]:
    """What trivy-repo's map gives ``names``, each stripped, empty ones dropped."""
    values: list[str] = []
    for name in (raw.strip() for raw in names):
        if not name:
            continue
        assert name in _TRIVY_REPO_MAP, f"the case names no mapped scanner: {name!r}"
        values.extend(_TRIVY_REPO_MAP[name])
    return _categories(*values)


def _flag_values(scanner: CheckovScanner, flag: str) -> list[str]:
    """The values of ``flag`` among the arguments checkov was built with."""
    return [
        arg.value for arg in scanner.args.extra_args if arg.key == flag and arg.value
    ]


def _checkov_framework_map_keys() -> set[str]:
    """The keys of checkov's ``frameworks`` map, read through ``category_map``."""
    facets = importlib.import_module(
        "automated_security_helper.base.scanner_operational_facets"
    )
    reader = getattr(facets, "category_map", None)
    assert reader is not None, "base.scanner_operational_facets has no category_map"
    keys = set(reader(CheckovScannerConfigOptions, "frameworks"))
    assert keys, "checkov's frameworks option carries no map"
    return keys


# ---- building the scanners --------------------------------------------------------


def _context(tmp_path: Path, config: AshConfig) -> PluginContext:
    """A context over an empty scanned tree, with the output directory beside it."""
    source = tmp_path / "src"
    output = tmp_path / "out"
    work = output / "converted"
    for directory in (source, output, work):
        directory.mkdir(parents=True, exist_ok=True)
    return PluginContext(
        source_dir=source, output_dir=output, work_dir=work, config=config
    )


def _trivy(
    tmp_path: Path, *, provenance: Optional[str] = None, **options: Any
) -> TrivyScanner:
    """The builtin trivy, built as test_trivy_scanner.py builds it.

    The scanner judges a ``scanners`` other than its default as it is built, so where
    the config came from is recorded first: "operator" is a config built from no
    file in the scanned tree, "tree" one built from the tree's ``.ash.yaml``.
    """
    options.setdefault("offline", False)
    context = _context(tmp_path, AshConfig())
    if provenance is not None:
        in_tree = (
            [] if provenance == "operator" else [Path(context.source_dir) / ".ash.yaml"]
        )
        record_provenance(
            context.config, in_tree=in_tree, trusted=AshConfig(), config_overrides=[]
        )
    return TrivyScanner(
        context=context,
        config=TrivyScannerConfig(
            enabled=True, options=TrivyScannerConfigOptions(**options)
        ),
        config_from_context=True,
    )


def _trivy_repo(tmp_path: Path, **options: Any) -> TrivyRepoScanner:
    """trivy-repo, built as test_trivy_base_bounds_and_operator_settings.py builds it."""
    options.setdefault("ignore_unfixed", False)
    return TrivyRepoScanner(
        context=_context(tmp_path, get_default_config()),
        config=TrivyRepoScannerConfig(options=TrivyRepoScannerConfigOptions(**options)),
    )


def _checkov(tmp_path: Path, **options: Any) -> CheckovScanner:
    """checkov, built as test_checkov_vcs_configuration_frameworks.py builds it."""
    return CheckovScanner(
        context=_context(tmp_path, AshConfig()),
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions(**options)),
    )


def _ferret(tmp_path: Path, **options: Any) -> FerretScanScanner:
    """ferret-scan with a typed config, as test_ferret_scanner.py builds it."""
    return FerretScanScanner(
        context=_context(tmp_path, AshConfig()),
        config=FerretScannerConfig(options=FerretScannerConfigOptions(**options)),
    )


def _mcp_config(tmp_path: Path, **options: Any) -> McpConfigScanner:
    """mcp-config, built as test_mcp_config_scanner.py builds it."""
    return McpConfigScanner(
        context=_context(tmp_path, get_default_config()),
        config=McpConfigScannerConfig(options=McpConfigScannerConfigOptions(**options)),
    )


def _bandit(tmp_path: Path) -> BanditScanner:
    """bandit, built as test_scanner_refusal_message.py builds it."""
    return BanditScanner(
        context=_context(tmp_path, AshConfig()), config=BanditScannerConfig()
    )


# ---- trivy ------------------------------------------------------------------------


def test_trivy_serves_sca_and_container_at_its_defaults(tmp_path: Path) -> None:
    scanner = _trivy(tmp_path)
    assert scanner._effective_scanners() == ["vuln"]

    served = _will_serve(scanner)

    assert served == _categories("sca", "container"), _named(served)


def test_an_operator_chosen_trivy_secret_scanner_serves_secrets(
    tmp_path: Path,
) -> None:
    """The operator's ``scanners: [secret]`` is kept, and it serves ``secrets`` alone."""
    scanner = _trivy(tmp_path, provenance="operator", scanners=["secret"])
    assert scanner.config.options.scanners == ["secret"], (
        "the operator's set was refused"
    )

    served = _will_serve(scanner)

    assert served == _categories("secrets"), _named(served)


def test_a_trivy_scanner_set_from_the_scanned_tree_serves_the_default_set(
    tmp_path: Path,
) -> None:
    """The same set written in the tree's config is replaced by the default, ``vuln``,
    and the run serves what ``vuln`` serves."""
    scanner = _trivy(tmp_path, provenance="tree", scanners=["secret"])
    assert scanner.config.options.scanners == ["vuln"], "the tree's set was kept"

    served = _will_serve(scanner)

    assert served == _categories("sca", "container"), _named(served)


# ---- checkov ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        pytest.param({"frameworks": ["github_actions"]}, ("ci",), id="github_actions"),
        pytest.param({"frameworks": ["openapi"]}, ("api",), id="openapi"),
        pytest.param({}, ("secrets", "iac", "ci", "api"), id="default-all"),
        # An empty list is passed as --framework all with the three hosted-settings
        # frameworks skipped, so it reads like the default and serves what it serves.
        pytest.param(
            {"frameworks": []},
            ("secrets", "iac", "ci", "api"),
            id="empty-list-reads-like-the-default",
        ),
        # Each sca and sast framework needs a platform API key that ASH does not
        # pass, so as ASH runs checkov such a framework serves nothing.
        pytest.param({"frameworks": ["sca_package"]}, (), id="sca_package"),
        pytest.param(
            {"skip_frameworks": ["secrets"]},
            ("iac", "ci", "api"),
            id="all-but-secrets",
        ),
    ],
)
def test_checkov_serves_the_categories_of_the_frameworks_it_passes(
    tmp_path: Path, options: dict[str, Any], expected: tuple[str, ...]
) -> None:
    served = _will_serve(_checkov(tmp_path, **options))

    assert served == _categories(*expected), _named(served)


def test_an_operator_checkov_file_naming_openapi_serves_api(tmp_path: Path) -> None:
    """At the default ``["all"]`` the frameworks the operator's file names are the
    ones checkov runs, so they are the ones the run serves."""
    config_file = tmp_path / "operator" / ".checkov.yaml"
    config_file.parent.mkdir()
    config_file.write_text("framework:\n  - openapi\n", encoding="utf-8")
    scanner = _checkov(tmp_path, config_file=str(config_file))
    assert _flag_values(scanner, "--framework") == ["openapi"]

    served = _will_serve(scanner)

    assert served == _categories("api"), _named(served)


def test_checkov_reads_all_as_every_framework_it_does_not_skip(tmp_path: Path) -> None:
    """``all`` is every framework checkov knows but the three that audit a hosted
    service's settings, which the scanner skips unless they are named; each once."""
    scanner = _checkov(tmp_path)
    assert _flag_values(scanner, "--framework") == ["all"]

    values = _mode_values(scanner, "frameworks")

    assert values is not None, "checkov's frameworks read as every mode"
    expected = (
        set(get_args(CheckFrameworks))
        - {"all"}
        - set(KNOWN_VCS_CONFIGURATION_FRAMEWORKS)
    )
    assert len(values) == len(set(values)), f"a framework is read twice: {values}"
    assert set(values) == expected, (
        f"read but not run: {sorted(set(values) - expected)}; "
        f"run but not read: {sorted(expected - set(values))}"
    )


def test_checkov_reads_a_named_framework_as_itself(tmp_path: Path) -> None:
    scanner = _checkov(tmp_path, frameworks=["github_actions"])

    assert _mode_values(scanner, "frameworks") == ["github_actions"]


def test_checkov_with_no_framework_argument_reads_every_framework_it_does_not_skip(
    tmp_path: Path,
) -> None:
    """With no ``--framework`` entry checkov runs its own default, every framework, so
    the scanner reads as every key of the frameworks map but its ``--skip-framework``
    values, and serves what those keys serve. No option builds such a scanner, so the
    entries are taken out after it is built, and the skips are kept."""
    scanner = _checkov(tmp_path)
    assert _flag_values(scanner, "--framework") == ["all"]
    extra_args = scanner.args.extra_args
    extra_args[:] = [arg for arg in extra_args if arg.key != "--framework"]
    skipped = _flag_values(scanner, "--skip-framework")
    assert skipped, "the built scanner passes no --skip-framework entry"

    values = _mode_values(scanner, "frameworks")

    assert values is not None, "checkov's frameworks read as every mode"
    expected = _checkov_framework_map_keys() - set(skipped)
    assert len(values) == len(set(values)), f"a framework is read twice: {values}"
    assert set(values) == expected, (
        f"read but not run: {sorted(set(values) - expected)}; "
        f"run but not read: {sorted(expected - set(values))}"
    )
    served = _will_serve(scanner)
    assert served == _categories("secrets", "iac", "ci", "api"), _named(served)


# ---- ferret-scan ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("checks", "expected"),
    [
        pytest.param("SECRETS", ("secrets",), id="SECRETS"),
        pytest.param("CREDIT_CARD,SSN", ("pii",), id="CREDIT_CARD-SSN"),
        pytest.param("SECRETS,SSN", ("secrets", "pii"), id="SECRETS-SSN"),
        pytest.param("secrets", ("secrets",), id="secrets-in-lower-case"),
        pytest.param(None, ("secrets", "pii"), id="default-all"),
        pytest.param(" All ", ("secrets", "pii"), id="all-in-any-case"),
    ],
)
def test_ferret_scan_serves_the_categories_of_its_checks(
    tmp_path: Path, checks: Optional[str], expected: tuple[str, ...]
) -> None:
    options = {} if checks is None else {"checks": checks}

    served = _will_serve(_ferret(tmp_path, **options))

    assert served == _categories(*expected), _named(served)


@pytest.mark.parametrize(
    ("checks", "expected"),
    [
        pytest.param("all", None, id="all"),
        pytest.param(" ALL ", None, id="all-upper-case-padded"),
        pytest.param("", None, id="empty"),
        pytest.param("SECRETS", ["SECRETS"], id="one-check"),
        pytest.param("secrets, ssn", ["SECRETS", "SSN"], id="lower-case-checks"),
        pytest.param("CREDIT_CARD,,SSN ", ["CREDIT_CARD", "SSN"], id="an-empty-part"),
    ],
)
def test_ferret_scan_reads_its_checks_upper_cased_and_all_as_every_check(
    tmp_path: Path, checks: str, expected: Optional[list[str]]
) -> None:
    scanner = _ferret(tmp_path, checks=checks)

    assert _mode_values(scanner, "checks") == expected


# ---- mcp-config -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        pytest.param({}, ("secrets", "supply-chain", "agent"), id="defaults"),
        pytest.param(
            {"flag_env_secrets": False, "forbid_unpinned_runners": False},
            ("agent",),
            id="no-env-secrets-no-unpinned-runners",
        ),
        pytest.param(_EVERY_RULE_OFF, (), id="every-rule-off"),
        pytest.param(
            {**_EVERY_RULE_OFF, "remote_url_prefixes": ["https://mcp.example.test/"]},
            ("agent",),
            id="a-url-prefix-list-alone",
        ),
        pytest.param(
            {**_EVERY_RULE_OFF, "flag_env_secrets": True},
            ("secrets", "agent"),
            id="env-secrets-alone",
        ),
    ],
)
def test_mcp_config_serves_the_categories_of_the_rules_it_switches_on(
    tmp_path: Path, options: dict[str, Any], expected: tuple[str, ...]
) -> None:
    served = _will_serve(_mcp_config(tmp_path, **options))

    assert served == _categories(*expected), _named(served)


# ---- trivy-repo with no scanners named --------------------------------------------


@pytest.mark.parametrize(
    ("variable", "config_file_text", "effective", "expected"),
    [
        pytest.param("misconfig", None, ["misconfig"], ("iac",), id="TRIVY_SCANNERS"),
        pytest.param(
            "vuln, misconfig",
            None,
            ["vuln", " misconfig"],
            ("sca", "iac"),
            id="TRIVY_SCANNERS-untrimmed",
        ),
        pytest.param(
            "config", None, ["misconfig"], ("iac",), id="TRIVY_SCANNERS-alias"
        ),
        pytest.param(
            None,
            "scan:\n  scanners: [license, misconfig]\n",
            ["license", "misconfig"],
            ("iac", "license"),
            id="config-file",
        ),
        pytest.param(
            None, None, ["vuln", "secret"], ("secrets", "sca"), id="trivy-default"
        ),
    ],
)
def test_trivy_repo_with_no_scanners_serves_the_map_over_trivys_own_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    variable: Optional[str],
    config_file_text: Optional[str],
    effective: list[str],
    expected: tuple[str, ...],
) -> None:
    """``scanners: []`` passes no ``--scanners``, so trivy decides which scanners run:
    ``TRIVY_SCANNERS``, then ``scan.scanners`` in the config file ``TRIVY_CONFIG``
    names outside the scanned tree, then its own ``vuln`` and ``secret``. The run
    serves the map over that same reading, ``_effective_scanners()``, whose names
    are each stripped first."""
    if variable is not None:
        monkeypatch.setenv("TRIVY_SCANNERS", variable)
    if config_file_text is not None:
        operator = tmp_path / "operator" / "trivy.yaml"
        operator.parent.mkdir()
        operator.write_text(config_file_text, encoding="utf-8")
        monkeypatch.setenv("TRIVY_CONFIG", str(operator))
    scanner = _trivy_repo(tmp_path, scanners=[])
    read = scanner._effective_scanners()
    assert read == effective, f"trivy's own reading of its scanners is now {read}"

    served = _will_serve(scanner)

    from_map = _over_trivy_repo_map(read)
    assert from_map == _categories(*expected), _named(from_map)
    assert served == from_map, _named(served)


def test_a_mode_its_map_does_not_cover_serves_the_can_serve_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """trivy passes ``TRIVY_SCANNERS`` on as written, so a name the map does not
    cover can reach a run; it serves every category the scanner can serve, so the
    run's set never leaves out what that name might report."""
    monkeypatch.setenv("TRIVY_SCANNERS", "vuln,unmapped-scanner")
    scanner = _trivy_repo(tmp_path, scanners=[])
    assert scanner._effective_scanners() == ["vuln", "unmapped-scanner"]

    served = _will_serve(scanner)

    assert served == _categories("sca") | frozenset(_declared(scanner)), _named(served)
    assert served == _categories("secrets", "sca", "iac", "license"), _named(served)


# ---- a scanner whose options carry no map -----------------------------------------


def test_a_scanner_whose_options_carry_no_map_serves_its_can_serve_set(
    tmp_path: Path,
) -> None:
    scanner = _bandit(tmp_path)

    served = _will_serve(scanner)

    assert served == frozenset(_declared(scanner)), _named(served)
    assert served == _categories("sast"), _named(served)


# ---- the base reading of a mode option --------------------------------------------


@pytest.mark.parametrize(
    ("build", "field_name", "expected"),
    [
        pytest.param(
            _mcp_config, "forbid_privilege_escalation", ["true"], id="a-switch-on"
        ),
        pytest.param(_mcp_config, "require_local", [], id="a-switch-off"),
        pytest.param(_mcp_config, "remote_url_prefixes", [], id="an-empty-list"),
        pytest.param(
            partial(
                _mcp_config,
                remote_url_prefixes=[
                    "https://a.example.test/",
                    "",
                    "https://b.example.test/",
                ],
            ),
            "remote_url_prefixes",
            ["https://a.example.test/", "https://b.example.test/"],
            id="a-list-with-an-empty-item",
        ),
        pytest.param(
            partial(_ferret, checks="SECRETS, ,ssn"),
            "checks",
            ["SECRETS", "ssn"],
            id="a-comma-separated-string",
        ),
        pytest.param(_ferret, "profile", [], id="a-value-left-unset"),
    ],
)
def test_the_base_reads_an_option_value_as_mode_names(
    tmp_path: Path,
    build: Callable[[Path], Any],
    field_name: str,
    expected: list[str],
) -> None:
    """The reading every scanner gets unless it overrides it (mcp-config keeps it for
    its five switches): a bool is ``"true"`` when true and nothing when false, an unset
    value nothing, a string its comma-separated parts and a list its items, each
    stripped, empty ones dropped."""
    assert _base_mode_values(build(tmp_path), field_name) == expected


# ---- classify_result --------------------------------------------------------------


@pytest.mark.parametrize(
    ("build", "expected"),
    [
        pytest.param(_bandit, ("sast",), id="bandit"),
        pytest.param(
            partial(_checkov, frameworks=["openapi"]),
            ("api",),
            id="checkov-openapi-only",
        ),
    ],
)
def test_a_run_that_serves_one_category_gives_every_result_that_category(
    tmp_path: Path, build: Callable[[Path], Any], expected: tuple[str, ...]
) -> None:
    """checkov can serve four categories, but a run that passes openapi alone serves
    one, so without a classifier of its own each of its results is an ``api`` one."""
    scanner = build(tmp_path)
    served = _will_serve(scanner)
    assert served == _categories(*expected), _named(served)

    for result in _RESULTS:
        assert _classify(scanner, result) == served, result


def test_a_run_that_serves_several_categories_leaves_every_result_unclassified(
    tmp_path: Path,
) -> None:
    scanner = _trivy(tmp_path)
    assert len(_will_serve(scanner)) > 1

    for result in _RESULTS:
        assert _classify(scanner, result) == frozenset(), result
