# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Registry totality for manifests: every registered scanner has exactly one.

The manifests (``automated_security_helper/plugin_manifests``) are data a
kernel reads WITHOUT importing a plugin, so nothing about a plugin forces its
manifest to stay true. These tests bind the two sides, fail closed, and name
the scanner:

- every scanner class a plugin package registers has a manifest whose entry
  point is that class, and every manifest entry point resolves to a registered
  scanner class (no manifest without a scanner, no scanner without a manifest);
- the manifest's ``name`` is the ``name`` default of the scanner's config
  class, and its ``options_model`` is the model that config's ``options`` field
  is typed with;
- the ``default_enabled`` field agrees with where the plugin lives: a builtin
  scanner loads by default and any other one does not (``tier`` is the
  manifest's own, with no tie to the package);
- ``plugin_module`` is the package that provides the scanner, and the package
  is the one ``ash_plugin_modules`` would name;
- ``file_ownership`` paths exist and no path is owned twice.

The enumeration is guarded by planted controls, because a shrunken universe
would pass every parametrized row vacuously.
"""

from __future__ import annotations

import importlib
import pkgutil
import typing
from pathlib import Path

import pytest

from automated_security_helper import plugin_modules
from automated_security_helper.plugin_manifests import (
    manifest_for,
    scanner_manifests,
)
from automated_security_helper.plugin_modules import ash_builtin

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
BUILTIN_PACKAGE = f"{plugin_modules.__name__}.ash_builtin"

#: Import-order cycles can cost ash_builtin a plugin group on first import
#: (its own docstring measures which orders); the retry recovers every such
#: order. Anything still lost fails the guard below.
_REMAINING_LOAD_ERRORS = ash_builtin.retry_failed_plugin_groups()


def _registered_scanner_classes() -> list[type]:
    classes: list[type] = []
    seen: set[type] = set()
    modules = sorted(
        pkgutil.iter_modules(plugin_modules.__path__), key=lambda m: m.name
    )
    for info in modules:
        if not info.ispkg:
            continue
        package = importlib.import_module(f"{plugin_modules.__name__}.{info.name}")
        for cls in getattr(package, "ASH_SCANNERS", []):
            if cls not in seen:
                seen.add(cls)
                classes.append(cls)
    return classes


SCANNER_CLASSES = _registered_scanner_classes()
MANIFESTS = scanner_manifests()


def _ref(cls: type) -> str:
    return f"{cls.__module__}:{cls.__qualname__}"


def _config_class(scanner_cls: type) -> type:
    return _unwrapped(scanner_cls.model_fields["config"].annotation)


def _unwrapped(annotation: typing.Any) -> typing.Any:
    """The model class under ``Optional[...]`` / ``Annotated[...]``."""
    while typing.get_origin(annotation) is not None:
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        annotation = args[0]
    return annotation


def _resolve(ref: str) -> typing.Any:
    module, _, name = ref.partition(":")
    return getattr(importlib.import_module(module), name)


def test_the_enumeration_holds_every_shipped_scanner_and_manifest() -> None:
    """Planted controls: a shrunken universe fails here, not silently."""
    assert not _REMAINING_LOAD_ERRORS, _REMAINING_LOAD_ERRORS
    assert len(SCANNER_CLASSES) == 23, sorted(c.__name__ for c in SCANNER_CLASSES)
    assert len(MANIFESTS) == 23, sorted(m.name for m in MANIFESTS)
    names = {m.name for m in MANIFESTS}
    assert {"cdk-nag", "semgrep", "opengrep", "trivy-repo", "snyk-code"} <= names


@pytest.mark.parametrize("scanner_cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_every_registered_scanner_has_exactly_one_manifest(scanner_cls: type) -> None:
    owners = [m for m in MANIFESTS if m.entry_points.scanner == _ref(scanner_cls)]
    assert len(owners) == 1, (
        f"{_ref(scanner_cls)} is registered but {len(owners)} manifests name it "
        "as their scanner entry point; add its manifest under "
        "automated_security_helper/plugin_manifests"
    )


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda m: m.name)
def test_every_manifest_entry_point_is_a_registered_scanner(manifest) -> None:
    resolved = _resolve(manifest.entry_points.scanner)
    assert resolved in SCANNER_CLASSES, (
        f"manifest {manifest.name!r} names {manifest.entry_points.scanner}, "
        "which no plugin package registers in ASH_SCANNERS"
    )


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda m: m.name)
def test_the_name_and_options_model_are_the_scanners_own(manifest) -> None:
    scanner_cls = _resolve(manifest.entry_points.scanner)
    config_cls = _config_class(scanner_cls)
    assert config_cls.model_fields["name"].default == manifest.name
    options_cls = _unwrapped(config_cls.model_fields["options"].annotation)
    assert _resolve(manifest.options_model) is options_cls, (
        f"manifest {manifest.name!r} names {manifest.options_model} as its "
        f"options model, but the scanner's config types options as "
        f"{_ref(options_cls)}"
    )


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda m: m.name)
def test_default_enabled_agrees_with_where_the_plugin_lives(manifest) -> None:
    """Loading is a fact of where the plugin lives; maturity (``tier``) is not.

    ``tier`` is read from the manifest alone, so promoting an opt-in scanner to
    ``supported`` is the one-line manifest edit and needs no change here.
    """
    builtin = manifest.plugin_module == BUILTIN_PACKAGE
    assert manifest.default_enabled is builtin, (
        f"{manifest.name}: only the builtin package loads without being listed "
        "in ash_plugin_modules, so default_enabled must say exactly that"
    )


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda m: m.name)
def test_plugin_module_is_the_package_that_provides_the_scanner(manifest) -> None:
    scanner_cls = _resolve(manifest.entry_points.scanner)
    module = scanner_cls.__module__
    assert module == manifest.plugin_module or module.startswith(
        manifest.plugin_module + "."
    )
    package = importlib.import_module(manifest.plugin_module)
    assert scanner_cls in getattr(package, "ASH_SCANNERS", ())


def test_every_plugin_package_with_scanners_is_covered_by_a_manifest() -> None:
    """A package that registers scanners has a manifest naming it as its module."""
    packages = {
        f"{plugin_modules.__name__}.{info.name}"
        for info in pkgutil.iter_modules(plugin_modules.__path__)
        if info.ispkg
        and getattr(
            importlib.import_module(f"{plugin_modules.__name__}.{info.name}"),
            "ASH_SCANNERS",
            (),
        )
    }
    assert packages, "no scanner package found; the check below would be vacuous"
    assert packages == {m.plugin_module for m in MANIFESTS}


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda m: m.name)
def test_owned_paths_exist(manifest) -> None:
    for path in manifest.file_ownership:
        assert (REPO_ROOT / path).exists(), (
            f"{manifest.name} owns {path}, which does not exist in this tree"
        )


def test_no_path_is_owned_by_two_manifests() -> None:
    claimed: dict[str, str] = {}
    for manifest in MANIFESTS:
        for path in manifest.file_ownership:
            assert path not in claimed, (
                f"{path} is owned by both {claimed[path]!r} and {manifest.name!r}"
            )
            claimed[path] = manifest.name


def test_every_scanner_source_file_is_owned_by_its_manifest() -> None:
    for manifest in MANIFESTS:
        scanner_cls = _resolve(manifest.entry_points.scanner)
        source = Path(importlib.import_module(scanner_cls.__module__).__file__)
        relative = source.resolve().relative_to(REPO_ROOT).as_posix()
        owned = manifest.file_ownership
        assert any(
            relative == path or relative.startswith(path.rstrip("/") + "/")
            for path in owned
        ), f"{manifest.name} does not own its scanner source {relative}"


def test_manifest_lookup_is_by_name_only() -> None:
    assert manifest_for("  Bandit ").name == "bandit"
    assert manifest_for("no-such-scanner") is None
