"""The mode maps five shipped scanners declare, and that no other scanner declares one.

A mode option names what a scanner runs: trivy's and trivy-repo's scanners,
checkov's frameworks, ferret-scan's checks, mcp-config's rule switches. Its map is
data on the option's field, under the ``x-ash-categories`` keyword, so it is
published with the config schema; it says which categories each mode serves, and
its ``*`` entry stands for every value the map does not name.

These tests read the maps as data: which fields carry one; that each is the map the
scanner documents, written as plain JSON in canonical order; that a map names only
categories its scanner can serve; that checkov's covers every framework its option
admits; and that what each scanner says it will serve at its defaults is its map
read over its default modes, so a map and its scanner's reading cannot drift apart.
"""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
from typing import Any, Callable, Mapping, get_args

import pytest
from pydantic import BaseModel

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_config import (
    declared_config_model,
    declared_plugin_name,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
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
from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES
from tests.utils.scanner_enumeration import load_scanner_universe

pytestmark = pytest.mark.unit

#: The fields of each options model that carry a map, in declaration order.
_MAPPED_FIELDS: dict[type[BaseModel], tuple[str, ...]] = {
    TrivyScannerConfigOptions: ("scanners",),
    TrivyRepoScannerConfigOptions: ("scanners",),
    CheckovScannerConfigOptions: ("frameworks",),
    FerretScannerConfigOptions: ("checks",),
    McpConfigScannerConfigOptions: (
        "forbid_privilege_escalation",
        "forbid_unpinned_runners",
        "forbid_auto_approval",
        "require_local",
        "remote_url_prefixes",
        "allowed_command_prefixes",
        "flag_env_secrets",
    ),
}

#: The scanner each of those options models belongs to, by its config name.
_SCANNER_OF: dict[type[BaseModel], str] = {
    TrivyScannerConfigOptions: "trivy",
    TrivyRepoScannerConfigOptions: "trivy-repo",
    CheckovScannerConfigOptions: "checkov",
    FerretScannerConfigOptions: "ferret-scan",
    McpConfigScannerConfigOptions: "mcp-config",
}

_MAPPED_IDS = [_SCANNER_OF[options_model] for options_model in _MAPPED_FIELDS]

#: The checkov frameworks that audit a hosted service's settings rather than files
#: in the tree. The scanner leaves them out of ``all`` unless they are named.
_CHECKOV_VCS_CONFIGURATION = (
    "bitbucket_configuration",
    "github_configuration",
    "gitlab_configuration",
)

#: checkov's map: a key for every framework but ``all``.
_CHECKOV_MAP: dict[str, tuple[str, ...]] = {
    **dict.fromkeys(
        (
            "terraform",
            "terraform_json",
            "terraform_plan",
            "cloudformation",
            "kubernetes",
            "helm",
            "kustomize",
            "arm",
            "bicep",
            "serverless",
            "ansible",
            "dockerfile",
            "json",
            "yaml",
            "3d_policy",
        ),
        ("iac",),
    ),
    "openapi": ("api",),
    **dict.fromkeys(
        (
            "github_actions",
            "gitlab_ci",
            "bitbucket_pipelines",
            "circleci_pipelines",
            "azure_pipelines",
            "argo_workflows",
            *_CHECKOV_VCS_CONFIGURATION,
        ),
        ("ci",),
    ),
    "secrets": ("secrets",),
    # Each of these needs a platform API key that ASH does not pass, so as ASH runs
    # checkov they serve nothing.
    **dict.fromkeys(
        (
            "cdk",
            "sast",
            "sast_python",
            "sast_java",
            "sast_javascript",
            "sast_typescript",
            "sast_golang",
            "sca_package",
            "sca_image",
        ),
        (),
    ),
}

#: Each mapped field's map as the scanner documents it, values in canonical order.
_DOCUMENTED_MAPS: dict[tuple[type[BaseModel], str], dict[str, tuple[str, ...]]] = {
    (TrivyScannerConfigOptions, "scanners"): {
        "vuln": ("sca", "container"),
        "misconfig": ("iac",),
        "secret": ("secrets",),
        "license": ("license",),
    },
    # trivy-repo scans no image, so its vuln scanner serves sca alone.
    (TrivyRepoScannerConfigOptions, "scanners"): {
        "vuln": ("sca",),
        "misconfig": ("iac",),
        "secret": ("secrets",),
        "license": ("license",),
    },
    (CheckovScannerConfigOptions, "frameworks"): _CHECKOV_MAP,
    (FerretScannerConfigOptions, "checks"): {
        "SECRETS": ("secrets",),
        "*": ("pii",),
    },
    (McpConfigScannerConfigOptions, "forbid_privilege_escalation"): {
        "true": ("agent",)
    },
    (McpConfigScannerConfigOptions, "forbid_unpinned_runners"): {
        "true": ("supply-chain", "agent")
    },
    (McpConfigScannerConfigOptions, "forbid_auto_approval"): {"true": ("agent",)},
    (McpConfigScannerConfigOptions, "require_local"): {"true": ("agent",)},
    (McpConfigScannerConfigOptions, "remote_url_prefixes"): {"*": ("agent",)},
    (McpConfigScannerConfigOptions, "allowed_command_prefixes"): {"*": ("agent",)},
    (McpConfigScannerConfigOptions, "flag_env_secrets"): {"true": ("secrets", "agent")},
}

_DOCUMENTED_MAP_IDS = [
    f"{_SCANNER_OF[options_model]}.{field_name}"
    for options_model, field_name in _DOCUMENTED_MAPS
]


@pytest.fixture(autouse=True)
def _no_trivy_setting_and_no_offline_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test here inherits a ``TRIVY_`` variable or ``ASH_OFFLINE`` from its shell,
    either of which could change what a trivy scanner builds at its defaults."""
    for name in list(os.environ):
        if name.startswith("TRIVY_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


# ---- reading the new names ------------------------------------------------------


def _opsf_name(name: str) -> Any:
    """A name of base.scanner_operational_facets, reached when a test runs."""
    found = getattr(opsf, name, None)
    assert found is not None, f"base.scanner_operational_facets has no {name}"
    return found


def _scan_category() -> Any:
    """``ScanCategory``, reached when a test runs so this module imports without it."""
    enums = importlib.import_module("automated_security_helper.core.enums")
    category = getattr(enums, "ScanCategory", None)
    assert category is not None, "core.enums has no ScanCategory"
    return category


def _named(categories: frozenset[Any]) -> list[str]:
    """``categories`` as sorted values, for a failure message."""
    return sorted(str(category) for category in categories)


def _can_serve(scanner_name: str) -> tuple[Any, ...]:
    """The scanner's can-serve set, from the name table."""
    names = importlib.import_module("automated_security_helper.utils.scanner_names")
    table = getattr(names, "SCANNER_CATEGORIES", None)
    assert table is not None, "utils.scanner_names has no SCANNER_CATEGORIES"
    return tuple(table[scanner_name])


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


def _options_model(scanner_class: type) -> type[BaseModel]:
    """The options model a scanner class declares, read from its config model."""
    config_model = declared_config_model(scanner_class, ScannerPluginConfigBase)
    assert config_model is not None, f"{scanner_class.__name__} declares no config"
    annotation = config_model.model_fields["options"].annotation
    for candidate in get_args(annotation) or (annotation,):
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate
    raise AssertionError(f"{config_model.__name__}.options is {annotation!r}")


# ---- the five scanners at their defaults ------------------------------------------


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


def _trivy_at_defaults(tmp_path: Path) -> TrivyScanner:
    return TrivyScanner(
        context=_context(tmp_path, AshConfig()), config=TrivyScannerConfig()
    )


def _trivy_repo_at_defaults(tmp_path: Path) -> TrivyRepoScanner:
    return TrivyRepoScanner(
        context=_context(tmp_path, get_default_config()),
        config=TrivyRepoScannerConfig(),
    )


def _checkov_at_defaults(tmp_path: Path) -> CheckovScanner:
    return CheckovScanner(
        context=_context(tmp_path, AshConfig()), config=CheckovScannerConfig()
    )


def _ferret_at_defaults(tmp_path: Path) -> FerretScanScanner:
    return FerretScanScanner(
        context=_context(tmp_path, AshConfig()), config=FerretScannerConfig()
    )


def _mcp_config_at_defaults(tmp_path: Path) -> McpConfigScanner:
    return McpConfigScanner(
        context=_context(tmp_path, get_default_config()),
        config=McpConfigScannerConfig(),
    )


_BUILT_AT_DEFAULTS: dict[type[BaseModel], Callable[[Path], Any]] = {
    TrivyScannerConfigOptions: _trivy_at_defaults,
    TrivyRepoScannerConfigOptions: _trivy_repo_at_defaults,
    CheckovScannerConfigOptions: _checkov_at_defaults,
    FerretScannerConfigOptions: _ferret_at_defaults,
    McpConfigScannerConfigOptions: _mcp_config_at_defaults,
}


def _default_modes(
    options_model: type[BaseModel], field_name: str, mapping: Mapping[str, Any]
) -> list[str]:
    """The modes a field's default turns on, read here from the default and the map.

    trivy-repo's default is all four scanner names. checkov's ``["all"]`` is every
    map key but the three ``*_configuration`` frameworks, which the scanner skips
    unless they are named. ferret-scan's ``"all"`` is every map entry, ``SECRETS``
    and ``*``. A bool mode contributes its ``"true"`` entry when true and nothing
    when false; a list mode contributes each item, so an empty list nothing.
    """
    default = options_model.model_fields[field_name].default
    if options_model is TrivyRepoScannerConfigOptions:
        assert sorted(default) == ["license", "misconfig", "secret", "vuln"], default
        return list(default)
    if options_model is CheckovScannerConfigOptions:
        assert default == ["all"], default
        assert set(_CHECKOV_VCS_CONFIGURATION) == set(
            KNOWN_VCS_CONFIGURATION_FRAMEWORKS
        ), KNOWN_VCS_CONFIGURATION_FRAMEWORKS
        return [key for key in mapping if key not in _CHECKOV_VCS_CONFIGURATION]
    if options_model is FerretScannerConfigOptions:
        assert default == "all", default
        assert set(mapping) == {"SECRETS", "*"}, sorted(mapping)
        return ["SECRETS", "*"]
    if isinstance(default, bool):
        return ["true"] if default else []
    assert isinstance(default, list), f"{options_model.__name__}.{field_name}"
    return [str(item) for item in default]


# ---- which fields carry a map -----------------------------------------------------


@pytest.mark.parametrize(
    ("options_model", "expected"), list(_MAPPED_FIELDS.items()), ids=_MAPPED_IDS
)
def test_the_mapped_fields_of_each_options_model(
    options_model: type[BaseModel], expected: tuple[str, ...]
) -> None:
    mapped_fields = _opsf_name("category_mapped_fields")

    assert mapped_fields(options_model) == expected


def test_no_other_shipped_scanner_carries_a_mode_map() -> None:
    """Every shipped scanner class the register tests enumerate, read through the
    options model its config declares."""
    mapped_fields = _opsf_name("category_mapped_fields")
    classes, load_errors = load_scanner_universe()
    assert not load_errors, load_errors
    walked: dict[str, type[BaseModel]] = {}
    for scanner_class in classes:
        name = declared_plugin_name(scanner_class) or scanner_class.__name__
        walked[name] = _options_model(scanner_class)
    missed = sorted(set(SCANNER_TOOL_TYPES) - set(walked))
    assert not missed, f"the walk missed shipped scanners: {missed}"
    for options_model, scanner_name in _SCANNER_OF.items():
        assert walked[scanner_name] is options_model, (scanner_name, walked)

    carriers = [
        f"{name}: {options_model.__name__} maps {fields}"
        for name, options_model in sorted(walked.items())
        if options_model not in _MAPPED_FIELDS
        and (fields := tuple(mapped_fields(options_model)))
    ]

    assert carriers == [], carriers


# ---- what each map says -----------------------------------------------------------


@pytest.mark.parametrize(
    ("options_model", "field_name"), list(_DOCUMENTED_MAPS), ids=_DOCUMENTED_MAP_IDS
)
def test_each_map_is_the_documented_map(
    options_model: type[BaseModel], field_name: str
) -> None:
    category_map = _opsf_name("category_map")
    category = _scan_category()
    expected = {
        mode: tuple(category(value) for value in values)
        for mode, values in _DOCUMENTED_MAPS[(options_model, field_name)].items()
    }

    mapping = category_map(options_model, field_name)

    assert mapping == expected
    assert all(
        isinstance(item, category) for values in mapping.values() for item in values
    ), mapping


@pytest.mark.parametrize(
    ("options_model", "field_name"), list(_DOCUMENTED_MAPS), ids=_DOCUMENTED_MAP_IDS
)
def test_a_map_is_published_as_plain_json_in_canonical_order(
    options_model: type[BaseModel], field_name: str
) -> None:
    """The map sits in the field's ``json_schema_extra``, which the config schema
    publishes as it is, so each mode's categories are a JSON list of their values
    in the canonical order, none twice."""
    keyword = _opsf_name("CATEGORY_MAP_KEY")
    order = [str(member.value) for member in _scan_category()]
    extra = options_model.model_fields[field_name].json_schema_extra
    assert isinstance(extra, dict), f"{options_model.__name__}.{field_name}: {extra!r}"

    published = extra.get(keyword)

    assert isinstance(published, dict), f"no {keyword} map: {extra!r}"
    assert json.loads(json.dumps(published)) == published, published
    for mode, values in published.items():
        assert isinstance(mode, str), mode
        assert isinstance(values, list), (mode, values)
        assert all(value in order for value in values), (mode, values)
        assert len(set(values)) == len(values), (mode, values)
        assert values == sorted(values, key=order.index), (mode, values)


@pytest.mark.parametrize("options_model", list(_MAPPED_FIELDS), ids=_MAPPED_IDS)
def test_every_category_a_map_names_is_one_its_scanner_can_serve(
    options_model: type[BaseModel],
) -> None:
    category_map = _opsf_name("category_map")
    mapped_fields = _opsf_name("category_mapped_fields")
    scanner_name = _SCANNER_OF[options_model]
    can_serve = _can_serve(scanner_name)
    fields = mapped_fields(options_model)
    assert fields, f"{scanner_name}: {options_model.__name__} carries no map"

    problems = [
        f"{scanner_name}: {options_model.__name__}.{field_name} maps {mode!r} to "
        f"{category}, which {scanner_name} cannot serve (it serves "
        f"{', '.join(str(served) for served in can_serve)})"
        for field_name in fields
        for mode, categories in category_map(options_model, field_name).items()
        for category in categories
        if category not in can_serve
    ]

    assert problems == [], problems


def test_checkovs_map_has_a_key_for_every_framework_but_all() -> None:
    category_map = _opsf_name("category_map")
    frameworks = set(get_args(CheckFrameworks))
    assert "all" in frameworks, sorted(frameworks)
    expected = frameworks - {"all"}

    keys = set(category_map(CheckovScannerConfigOptions, "frameworks"))

    assert keys == expected, (
        f"frameworks with no key: {sorted(expected - keys)}; "
        f"keys that are no framework checkov runs: {sorted(keys - expected)}"
    )


def test_a_field_without_a_map_reads_as_an_empty_map() -> None:
    category_map = _opsf_name("category_map")
    mapped_fields = _opsf_name("category_mapped_fields")

    assert category_map(CheckovScannerConfigOptions, "skip_frameworks") == {}
    assert category_map(TrivyScannerConfigOptions, "license_full") == {}
    assert category_map(TrivyScannerConfigOptions, "no_such_option") == {}
    assert mapped_fields(ScannerOptionsBase) == ()


def test_the_map_keyword_and_its_wildcard_key_are_the_published_spellings() -> None:
    assert _opsf_name("CATEGORY_MAP_KEY") == "x-ash-categories"
    assert _opsf_name("CATEGORY_MAP_ANY") == "*"


# ---- the map against the scanner's own reading ------------------------------------


@pytest.mark.parametrize("options_model", list(_MAPPED_FIELDS), ids=_MAPPED_IDS)
def test_will_serve_at_the_defaults_is_the_map_over_the_default_modes(
    tmp_path: Path, options_model: type[BaseModel]
) -> None:
    category_map = _opsf_name("category_map")
    mapped_fields = _opsf_name("category_mapped_fields")
    scanner = _BUILT_AT_DEFAULTS[options_model](tmp_path)

    served = _will_serve(scanner)

    expected: set[Any] = set()
    for field_name in mapped_fields(options_model):
        mapping = category_map(options_model, field_name)
        for mode in _default_modes(options_model, field_name, mapping):
            # A mode the map does not name reads its "*" entry, when it has one.
            covered = mapping[mode] if mode in mapping else mapping.get("*")
            assert covered is not None, (
                f"{_SCANNER_OF[options_model]}: the default of {field_name} turns "
                f"on {mode!r}, which its map does not cover"
            )
            expected.update(covered)
    assert expected, f"{_SCANNER_OF[options_model]}: its default modes serve nothing"
    assert served == frozenset(expected), (_named(served), _named(frozenset(expected)))
