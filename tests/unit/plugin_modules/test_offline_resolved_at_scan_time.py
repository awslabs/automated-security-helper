# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner's offline mode is read when the scanner runs, not when its config was built.

The defect these tests pin
--------------------------
Every scanner with an ``offline`` option used to default it to ``is_offline_mode()``,
evaluated when the options object was constructed. ``ScannerConfigSegment`` constructs
its default scanner configs when ``automated_security_helper.config.ash_config`` is
imported. In local mode ``ash scan --offline`` sets ``ASH_OFFLINE`` after that import,
so checkov, grype, npm-audit, opengrep, semgrep, syft and trivy-repo all kept
``offline=False`` and went to the network during an ``--offline`` scan (a strace of
checkov showed three connections to port 443).

Each test builds the config while ASH is online, then turns offline mode on the way
``--offline`` does, then builds the scanner. That order is the bug's order. Asserting
on the option value would prove nothing, so every test asserts on what the scanner
hands the tool: a flag, an environment variable, or the offline-cache verdict.

Negative control: putting back ``default_factory=is_offline_mode`` and reading
``options.offline`` directly makes every ``test_offline_flag_set_after_config_built``
case fail.
"""

from typing import Callable, NamedTuple

import pytest

from automated_security_helper.config.ash_config import ScannerConfigSegment
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
    GrypeScannerConfig,
    GrypeScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
    SyftScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)


def _arg_keys(scanner) -> list:
    return [a.key for a in scanner.args.extra_args]


def _grep_cache_verdict(env_var: str) -> Callable:
    # Offline, a *grep scanner swaps the registry for the local rule cache; with no
    # cache configured it records why it cannot run. Online it records nothing.
    def probe(scanner) -> bool:
        reason = scanner.dependency_unavailable_reason or ""
        return env_var in reason

    return probe


class Case(NamedTuple):
    scanner_cls: type
    config_cls: type
    options_cls: type
    segment_field: str
    went_offline: Callable


CASES = {
    "checkov": Case(
        CheckovScanner,
        CheckovScannerConfig,
        CheckovScannerConfigOptions,
        "checkov",
        lambda s: "--skip-download" in _arg_keys(s),
    ),
    "grype": Case(
        GrypeScanner,
        GrypeScannerConfig,
        GrypeScannerConfigOptions,
        "grype",
        lambda s: (
            s.extra_env.get("GRYPE_DB_AUTO_UPDATE") == "false"
            and s.extra_env.get("GRYPE_CHECK_FOR_APP_UPDATE") == "false"
        ),
    ),
    "opengrep": Case(
        OpengrepScanner,
        OpengrepScannerConfig,
        OpengrepScannerConfigOptions,
        "opengrep",
        _grep_cache_verdict("OPENGREP_RULES_CACHE_DIR"),
    ),
    "semgrep": Case(
        SemgrepScanner,
        SemgrepScannerConfig,
        SemgrepScannerConfigOptions,
        "semgrep",
        _grep_cache_verdict("SEMGREP_RULES_CACHE_DIR"),
    ),
    "syft": Case(
        SyftScanner,
        SyftScannerConfig,
        SyftScannerConfigOptions,
        "syft",
        lambda s: s.extra_env.get("SYFT_CHECK_FOR_APP_UPDATE") == "false",
    ),
    # trivy shares trivy-repo's argument building (TrivyScannerBase).
    "trivy": Case(
        TrivyScanner,
        TrivyScannerConfig,
        TrivyScannerConfigOptions,
        "",  # community plugin: not a declared ScannerConfigSegment field
        lambda s: (
            "--offline-scan" in _arg_keys(s) and "--skip-db-update" in _arg_keys(s)
        ),
    ),
    "trivy-repo": Case(
        TrivyRepoScanner,
        TrivyRepoScannerConfig,
        TrivyRepoScannerConfigOptions,
        "",  # community plugin: not a declared ScannerConfigSegment field
        lambda s: (
            "--offline-scan" in _arg_keys(s) and "--skip-db-update" in _arg_keys(s)
        ),
    ),
}

params = pytest.mark.parametrize("case", list(CASES.values()), ids=list(CASES))
# trivy and trivy-repo are community plugins, so ScannerConfigSegment has no field
# for them.
SEGMENT_CASES = {k: c for k, c in CASES.items() if c.segment_field}
segment_params = pytest.mark.parametrize(
    "case", list(SEGMENT_CASES.values()), ids=list(SEGMENT_CASES)
)


@pytest.fixture
def online(monkeypatch):
    """Start every test online, with no rule cache, whatever the host has exported."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)
    return monkeypatch


def _go_offline(monkeypatch):
    # What _run_local_mode does for --offline, after every config already exists.
    monkeypatch.setenv("ASH_OFFLINE", "YES")


@params
def test_offline_flag_set_after_config_built(case, online, test_plugin_context):
    """The bug's order: config built online, then --offline, then the scanner."""
    config = case.config_cls()
    _go_offline(online)

    scanner = case.scanner_cls(context=test_plugin_context, config=config)

    assert case.went_offline(scanner), (
        f"{case.scanner_cls.__name__} built from a config created before --offline "
        "set ASH_OFFLINE ran online"
    )


@segment_params
def test_default_segment_config_follows_offline_flag(case, online, test_plugin_context):
    """The config ``ScannerConfigSegment`` itself supplies, which ASH really uses."""
    config = getattr(ScannerConfigSegment(), case.segment_field)
    _go_offline(online)

    scanner = case.scanner_cls(context=test_plugin_context, config=config)

    assert case.went_offline(scanner)


@params
def test_config_round_trip_does_not_freeze_online(case, online, test_plugin_context):
    """resolve_config and the scanner both dump and re-validate configs.

    A round trip taken while online writes ``offline: false`` into the data. It
    must still mean "follow ASH", or the stale value comes back by another route.
    """
    dumped = case.config_cls().model_dump(by_alias=True)
    config = case.config_cls.model_validate(dumped)
    _go_offline(online)

    scanner = case.scanner_cls(context=test_plugin_context, config=config)

    assert case.went_offline(scanner)


@params
def test_online_by_default(case, online, test_plugin_context):
    """Control: with ASH online and no option set, nothing goes offline."""
    scanner = case.scanner_cls(context=test_plugin_context, config=case.config_cls())

    assert not case.went_offline(scanner)


@params
def test_explicit_option_true_forces_offline_while_ash_is_online(
    case, online, test_plugin_context
):
    """Precedence 2: a per-scanner ``offline: true`` still works on its own."""
    config = case.config_cls(options=case.options_cls(offline=True))

    scanner = case.scanner_cls(context=test_plugin_context, config=config)

    assert case.went_offline(scanner)


@params
def test_explicit_option_false_does_not_override_ash_offline(
    case, online, test_plugin_context
):
    """Precedence 1: ``offline: false`` (what ``ash config init`` writes) follows ASH."""
    config = case.config_cls(options=case.options_cls(offline=False))
    _go_offline(online)

    scanner = case.scanner_cls(context=test_plugin_context, config=config)

    assert case.went_offline(scanner)


# The three reads below change what reaches the tool only in part, so the CASES probes
# cannot see them. Each gets its own test in the bug's order.


def test_semgrep_offline_rules_reach_the_subprocess(
    online, test_plugin_context, tmp_path
):
    """``SEMGREP_RULES`` points semgrep at the cache; it must follow --offline too."""
    cache = tmp_path / "rules"
    cache.mkdir()
    (cache / "rule.yaml").write_text("rules: []\n", encoding="utf-8")
    online.setenv("SEMGREP_RULES_CACHE_DIR", str(cache))
    config = SemgrepScannerConfig()
    _go_offline(online)

    scanner = SemgrepScanner(context=test_plugin_context, config=config)

    assert scanner.extra_subprocess_env() == {"SEMGREP_RULES": f"{cache}/*"}


@pytest.mark.parametrize(
    "case", [CASES["semgrep"], CASES["opengrep"]], ids=["semgrep", "opengrep"]
)
def test_offline_rule_cache_is_held_to_its_staleness_bound(
    case, online, test_plugin_context
):
    """Offline, the rule cache is a content database the staleness gate must check."""
    config = case.config_cls()
    _go_offline(online)

    scanner = case.scanner_cls(context=test_plugin_context, config=config)

    assert [db.scanner for db in scanner.content_databases_in_use()] == [
        case.segment_field
    ]


@pytest.mark.parametrize(
    "case", [CASES["semgrep"], CASES["opengrep"]], ids=["semgrep", "opengrep"]
)
def test_online_rule_cache_is_not_a_content_database(case, online, test_plugin_context):
    """Control for the test above: online, the rules come from the registry."""
    scanner = case.scanner_cls(context=test_plugin_context, config=case.config_cls())

    assert scanner.content_databases_in_use() == []


def test_grype_online_db_bound_stays_out_of_an_offline_run(online, test_plugin_context):
    """Online, ASH sets grype's database-age bound; offline it must not.

    With the bound set, grype answers an old database by downloading a new one.
    """
    online.delenv("GRYPE_DB_MAX_ALLOWED_BUILT_AGE", raising=False)
    online.delenv("GRYPE_DB_VALIDATE_AGE", raising=False)
    config = GrypeScannerConfig()
    _go_offline(online)

    scanner = GrypeScanner(context=test_plugin_context, config=config)

    assert "GRYPE_DB_MAX_ALLOWED_BUILT_AGE" not in scanner.extra_env
    assert scanner.extra_env["GRYPE_DB_VALIDATE_AGE"] == "false"


def test_grype_online_db_bound_is_set_online(online, test_plugin_context):
    """Control for the test above: online, the bound is there to be kept out."""
    online.delenv("GRYPE_DB_MAX_ALLOWED_BUILT_AGE", raising=False)
    online.delenv("GRYPE_DB_VALIDATE_AGE", raising=False)

    scanner = GrypeScanner(context=test_plugin_context, config=GrypeScannerConfig())

    from automated_security_helper.utils.content_databases import get

    bound = get("grype-db").bound_env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"]
    assert scanner.extra_env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] == bound


def _scanner_options_with_offline() -> set:
    """Every scanner options class shipped in plugin_modules that has an ``offline`` field."""
    import importlib
    import pkgutil

    import automated_security_helper.plugin_modules as plugin_modules
    from automated_security_helper.base.options import ScannerOptionsBase

    for module in pkgutil.walk_packages(
        plugin_modules.__path__, plugin_modules.__name__ + "."
    ):
        importlib.import_module(module.name)

    found, stack = set(), list(ScannerOptionsBase.__subclasses__())
    while stack:
        cls = stack.pop()
        stack.extend(cls.__subclasses__())
        if cls.__module__.startswith(plugin_modules.__name__) and (
            "offline" in cls.model_fields
        ):
            found.add(cls)
    return found


def test_every_scanner_with_an_offline_option_is_covered():
    """A scanner, builtin or community, that grows an ``offline`` option needs a case."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScannerConfigOptions,
    )

    # npm-audit's flag is only observable from scan(); it is covered in
    # test_npm_audit_scanner_behavior.py with the same build-then-go-offline order.
    covered = {c.options_cls for c in CASES.values()} | {NpmAuditScannerConfigOptions}
    found = _scanner_options_with_offline()

    assert found == covered, sorted(c.__qualname__ for c in found ^ covered)


def test_offline_option_default_is_a_plain_false():
    """No option may go back to reading the environment when it is constructed.

    The helper ORs in ASH's offline mode, so an environment-derived default no
    longer changes behavior; it would make config dumps and the generated schema
    depend on the environment they were produced in.
    """
    for options_cls in _scanner_options_with_offline():
        field = options_cls.model_fields["offline"]
        assert field.default_factory is None, options_cls.__qualname__
        assert field.default is False, options_cls.__qualname__
