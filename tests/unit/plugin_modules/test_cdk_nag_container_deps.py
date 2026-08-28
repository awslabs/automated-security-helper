"""Regression tests for the cdk-nag scanner's dependency installation.

Two defects are covered, and they pull in opposite directions.

The first: the Dockerfile installed ASH without the [cdk] optional extra and the
cdk-nag scanner did not override ``get_installation_commands()``, so
``ash dependencies install`` had no way to install the CDK dependencies and
cdk-nag was reported MISSING in container mode. That is why the scanner must
emit an install command at all.

The second: the fix for the first installed ``automated-security-helper[cdk]``.
ASH is not published to any package index -- it installs from git -- so that
name resolves to an unrelated third party's distribution, which a security
scanner then installed inside CI. That is why the command must never name ASH's
own distribution.

The guards below are written against the *class* of mistake rather than against
the one string that was wrong, because the second defect passed the original
version of this file: the tests asserted the buggy behavior.
"""

import re
import sys
from importlib.metadata import PackageNotFoundError, packages_distributions
from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cdk_nag_scanner as cdk_nag_scanner_module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    _CDK_EXTRA_FALLBACK_REQUIREMENTS,
    CdkNagScanner,
    CdkNagScannerConfig,
    _cdk_extra_requirements,
)

# The packages the "cdk" extra actually exists to install. Names only -- the
# version bounds are asserted against metadata in TestCdkExtraResolution rather
# than duplicated here, so bumping a bound does not require editing this file.
_REAL_CDK_PACKAGES = ("aws-cdk-lib", "cdk-nag", "constructs")


def _self_referential_names() -> set[str]:
    """Names that would mean ASH is installing itself from a package index.

    Derived from the distribution that provides ASH rather than written out, so
    renaming the distribution cannot quietly retire this guard. Both separator
    spellings are included because ``pip install automated_security_helper``
    resolves to the same project as the hyphenated form.
    """
    provided_by = packages_distributions().get("automated_security_helper") or []
    names = set(provided_by) | {"automated-security-helper"}
    return {name.replace("_", "-").lower() for name in names}


_INSTALL_VERBS = frozenset({"install", "add", "sync"})


def _install_targets(commands: list[list[str]]) -> list[str]:
    """Every argument a package manager would treat as something to install.

    Takes the arguments following the last install verb in each command, or
    everything after argv[0] when there is no verb to anchor on.

    argv[0] is always excluded, and that exclusion is load-bearing rather than
    tidiness: argv[0] is ``sys.executable``, whose path contains the checkout
    directory, and DEVELOPMENT.md tells contributors to clone into a directory
    named after the project. Scanning it for the project's own name would fail
    for everyone who followed those instructions.
    """
    targets: list[str] = []
    for cmd in commands:
        verb_positions = [i for i, arg in enumerate(cmd) if arg in _INSTALL_VERBS]
        start = verb_positions[-1] + 1 if verb_positions else 1
        targets.extend(arg for arg in cmd[start:] if not arg.startswith("-"))
    return targets


def _scannable(values: list[str]) -> str:
    """Join values into one lowercase, separator-normalized string."""
    return " ".join(values).replace("_", "-").lower()


def _requirement_name(requirement: str) -> str:
    """Extract the distribution name from a PEP 508 requirement string."""
    return re.split(r"[\[<>=!~;\s]", requirement, maxsplit=1)[0].strip().lower()


AshConfig.model_rebuild()
CdkNagScannerConfig.model_rebuild()
CdkNagScanner.model_rebuild()


@pytest.fixture
def scanner_context(tmp_path):
    """Create a PluginContext for the scanner."""
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()

    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


@pytest.fixture
def install_commands_when_cdk_missing(
    scanner_context: PluginContext,
) -> list[list[str]]:
    """The commands emitted when the CDK dependencies are not importable."""
    with patch.object(cdk_nag_scanner_module, "_CDK_AVAILABLE", False):
        scanner = CdkNagScanner(context=scanner_context)
        return scanner.get_installation_commands("linux", "amd64")


class TestCdkNagInstallationCommands:
    """get_installation_commands must install the CDK packages, and only those."""

    def test_installs_the_real_cdk_packages(
        self, install_commands_when_cdk_missing: list[list[str]]
    ) -> None:
        """Exactly one pip install command, naming each package the extra declares."""
        pip_cmds = [
            cmd
            for cmd in install_commands_when_cdk_missing
            if cmd[:4] == [sys.executable, "-m", "pip", "install"]
        ]
        assert len(pip_cmds) == 1, (
            "Expected exactly one pip install command, got: "
            f"{install_commands_when_cdk_missing}"
        )

        installed = {_requirement_name(arg) for arg in pip_cmds[0][4:]}
        assert installed == set(_REAL_CDK_PACKAGES), (
            f"Expected the cdk extra's own packages, got: {pip_cmds[0]}"
        )

    def test_never_installs_ash_by_distribution_name(
        self, install_commands_when_cdk_missing: list[list[str]]
    ) -> None:
        """No command may name ASH's own distribution.

        This is the supply-chain guard. ASH is not published to any package
        index, so any command naming its distribution resolves to whoever owns
        that name -- and `ash dependencies install` executes these commands
        inside CI. Asserted against the whole flattened argument list rather than
        one exact string so that reintroducing it in any form fails here:
        bare, with an extra, with a version pin, or under the underscore
        spelling of the name.
        """
        targets = _scannable(_install_targets(install_commands_when_cdk_missing))
        for name in _self_referential_names():
            assert name not in targets, (
                f"Installation commands resolve ASH's own distribution ({name!r}) "
                f"from a package index: {install_commands_when_cdk_missing}"
            )

    def test_requirements_carry_no_pep508_markers(
        self, install_commands_when_cdk_missing: list[list[str]]
    ) -> None:
        """Install targets must be bare requirements, with any marker stripped.

        pip evaluates markers with ``extra`` undefined, so an argument that kept
        its ``; extra == "cdk"`` marker is skipped -- and pip still exits 0. That
        failure mode is invisible to the caller, which only checks the exit code.
        """
        for target in _install_targets(install_commands_when_cdk_missing):
            assert ";" not in target and "extra ==" not in target, (
                f"Requirement {target!r} still carries a PEP 508 marker; pip will "
                "silently skip it and report success."
            )

    def test_no_pip_install_when_cdk_available(
        self, scanner_context: PluginContext
    ) -> None:
        """When _CDK_AVAILABLE is True, must NOT emit a CDK install command."""
        with patch.object(cdk_nag_scanner_module, "_CDK_AVAILABLE", True):
            scanner = CdkNagScanner(context=scanner_context)
            commands = scanner.get_installation_commands("linux", "amd64")

            targets = _scannable(_install_targets(commands))
            for package in _REAL_CDK_PACKAGES:
                assert package not in targets, (
                    f"Should not install {package} when CDK is already available, "
                    f"got: {commands}"
                )

    def test_validate_deps_fails_when_cdk_unavailable(
        self, scanner_context: PluginContext, caplog: pytest.LogCaptureFixture
    ) -> None:
        """validate_plugin_dependencies must fail, and must not advertise ASH's name."""
        with patch.object(cdk_nag_scanner_module, "_CDK_AVAILABLE", False):
            scanner = CdkNagScanner(context=scanner_context)
            with caplog.at_level("WARNING"):
                result = scanner.validate_plugin_dependencies()

            assert result is False
            assert scanner.dependencies_satisfied is False

            # The remediation hint is user-facing instruction, so it is subject
            # to the same rule as the install command itself.
            hint = _scannable([caplog.text])
            for name in _self_referential_names():
                assert name not in hint, (
                    f"Dependency warning tells the user to install {name!r} from a "
                    f"package index: {caplog.text}"
                )


class TestCdkExtraResolution:
    """_cdk_extra_requirements must track pyproject.toml, not a stale copy."""

    def test_resolves_from_installed_metadata(self) -> None:
        """The extra is read from metadata, bounds included."""
        requirements = _cdk_extra_requirements()

        assert {_requirement_name(req) for req in requirements} == set(
            _REAL_CDK_PACKAGES
        ), f"Unexpected cdk extra contents: {requirements}"
        assert all(
            any(op in req for op in (">=", "==", "~=")) for req in requirements
        ), f"Requirements should carry version bounds: {requirements}"

    def test_fallback_matches_installed_metadata(self) -> None:
        """The hardcoded fallback must not drift from the declared extra.

        The fallback is a copy of [project.optional-dependencies] cdk. Comparing
        it against metadata is what catches someone bumping a bound in
        pyproject.toml without updating the copy, which would otherwise only
        surface as the installer resolving stale versions on machines where
        metadata is unreadable.

        Compared as name plus an unordered set of specifier clauses, because
        importlib.metadata reorders them: pyproject's ">=2.257.0,<3.0.0" comes
        back as "<3.0.0,>=2.257.0".
        """

        def normalize(requirement: str) -> tuple[str, frozenset[str]]:
            name = _requirement_name(requirement)
            specifier = requirement[len(name) :].lstrip()
            return name, frozenset(
                clause.strip() for clause in specifier.split(",") if clause.strip()
            )

        assert {normalize(req) for req in _CDK_EXTRA_FALLBACK_REQUIREMENTS} == {
            normalize(req) for req in _cdk_extra_requirements()
        }, (
            "_CDK_EXTRA_FALLBACK_REQUIREMENTS has drifted from "
            "[project.optional-dependencies] cdk in pyproject.toml"
        )

    def test_falls_back_when_distribution_is_not_found(self) -> None:
        """An uninstalled checkout must still get a usable requirement list.

        Returning nothing here would make `ash dependencies install` exit 0
        having installed nothing, which is the original MISSING-scanner defect.
        """
        with patch.object(
            cdk_nag_scanner_module, "packages_distributions", return_value={}
        ):
            assert _cdk_extra_requirements() == _CDK_EXTRA_FALLBACK_REQUIREMENTS

    @pytest.mark.parametrize(
        "raised",
        [PackageNotFoundError("automated-security-helper"), OSError("no perms")],
    )
    def test_falls_back_when_metadata_read_raises(self, raised: Exception) -> None:
        """The except branch must reach the fallback, not propagate.

        Separate from the not-found case above: that one returns an empty mapping
        and never enters the except block, so without this test the handler is
        present but unexecuted. Both exception types are covered because catching
        only one of them would let the other escape into
        `ash dependencies install` as an unhandled traceback.
        """
        with patch.object(
            cdk_nag_scanner_module, "packages_distributions", side_effect=raised
        ):
            assert _cdk_extra_requirements() == _CDK_EXTRA_FALLBACK_REQUIREMENTS

    def test_returns_empty_when_extra_was_removed(self) -> None:
        """A distribution declaring no cdk extra means there is nothing to install.

        Distinct from the unreadable-metadata case, which must fall back. Here the
        metadata is readable and authoritative, so honoring it beats installing
        the stale hardcoded pins.
        """
        with patch.object(
            cdk_nag_scanner_module,
            "packages_distributions",
            return_value={"automated_security_helper": ["automated-security-helper"]},
        ):
            with patch.object(
                cdk_nag_scanner_module, "requires", return_value=["requests>=2.28.0"]
            ):
                assert _cdk_extra_requirements() == []

    def test_skips_distributions_declaring_nothing(self) -> None:
        """A distribution whose requires() is None is skipped, not treated as empty.

        importlib.metadata returns None rather than [] for a distribution with no
        declared requirements. Without the skip, the first such name would short
        circuit the search and hide a later distribution that does declare the
        extra.
        """
        with patch.object(
            cdk_nag_scanner_module,
            "packages_distributions",
            return_value={"automated_security_helper": ["ghost-dist", "real-dist"]},
        ):
            with patch.object(
                cdk_nag_scanner_module,
                "requires",
                side_effect=[None, ["cdk-nag>=3.0.2,<4.0.0; extra == 'cdk'"]],
            ):
                assert _cdk_extra_requirements() == ["cdk-nag>=3.0.2,<4.0.0"]

    def test_fallback_names_no_ash_distribution(self) -> None:
        """The fallback list is an install target too, so the same rule applies."""
        flattened = _scannable(_CDK_EXTRA_FALLBACK_REQUIREMENTS)
        for name in _self_referential_names():
            assert name not in flattened, (
                f"Fallback requirements name ASH's own distribution ({name!r}): "
                f"{_CDK_EXTRA_FALLBACK_REQUIREMENTS}"
            )
