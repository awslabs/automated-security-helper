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

import json
import re
import sys
from importlib.metadata import PackageNotFoundError, packages_distributions
from pathlib import Path, PureWindowsPath
from unittest.mock import MagicMock, patch

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
    _cdk_extra_requirements_from_metadata,
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
        metadata is unreadable. It caught #547 doing exactly that.

        Compared as name plus an unordered set of specifier clauses, because
        importlib.metadata reorders them: pyproject's ">=2.257.0,<3.0.0" comes
        back as "<3.0.0,>=2.257.0".

        Asserted against _cdk_extra_requirements_from_metadata rather than
        _cdk_extra_requirements, because the latter substitutes the very constant
        under test when the read fails. Measured at 804036ba across four
        interpreters on one editable install, that substitution happened on
        py3.10.20 and py3.11.15 -- so this comparison was the constant against
        itself, it could not fail for any value of the constant, and it reported a
        genuine PASSED with no skip. Reading None here is now a failure rather
        than a free pass.
        """

        def normalize(requirement: str) -> tuple[str, frozenset[str]]:
            name = _requirement_name(requirement)
            specifier = requirement[len(name) :].lstrip()
            return name, frozenset(
                clause.strip() for clause in specifier.split(",") if clause.strip()
            )

        declared = _cdk_extra_requirements_from_metadata()
        assert declared is not None, (
            "the cdk extra could not be read from installed metadata at all, so "
            "this comparison has nothing to check the hardcoded copy against. "
            "Passing here would mean the guard is vacuous, which is the defect "
            "this assertion exists to prevent -- see "
            "test_the_comparison_is_not_against_the_constant_itself"
        )
        assert {normalize(req) for req in _CDK_EXTRA_FALLBACK_REQUIREMENTS} == {
            normalize(req) for req in declared
        }, (
            "_CDK_EXTRA_FALLBACK_REQUIREMENTS has drifted from "
            "[project.optional-dependencies] cdk in pyproject.toml"
        )

    def test_the_comparison_is_not_against_the_constant_itself(self) -> None:
        """The anti-vacuity control, and the reason the split above exists.

        Perturb the hardcoded constant and the derived value must not move. If the
        derivation is secretly returning the constant -- which is what
        _cdk_extra_requirements does whenever the metadata read fails -- the
        perturbed value shows up here and this fails.

        Without this test the guard above can silently become vacuous again the
        next time distribution discovery breaks on some interpreter or install
        layout, which is precisely how it went unnoticed on py3.10 and py3.11.
        A passing comparison proves nothing unless the two sides have different
        origins, so that is what is asserted rather than the comparison's result.
        """
        sentinel = ["aws-cdk-lib>=0.0.1,<0.0.2", "not-a-real-package>=9.9"]

        with patch.object(
            cdk_nag_scanner_module, "_CDK_EXTRA_FALLBACK_REQUIREMENTS", sentinel
        ):
            derived = _cdk_extra_requirements_from_metadata()

        assert derived is not None, (
            "installed metadata must be readable for the drift guard to mean "
            "anything; None here is the vacuous state itself"
        )
        assert derived != sentinel, (
            "the derived requirements are the hardcoded constant, so the drift "
            "guard is comparing that constant against itself and cannot fail"
        )
        assert not any("0.0.1" in req for req in derived), (
            f"the perturbed constant leaked into the derived value: {derived}"
        )
        assert any("aws-cdk-lib" in req for req in derived), (
            f"metadata was read but carries no aws-cdk-lib requirement: {derived}"
        )

    def test_discovery_survives_a_dist_info_without_a_direct_url(self) -> None:
        """The install-location strategy walks every installed distribution.

        A sibling with no direct_url.json, unreadable metadata, or a non-file URL
        must be skipped rather than crashing the walk. Only reachable when the
        declared mapping is empty, which is the editable-install shape on py3.10
        and py3.11.
        """
        broken = MagicMock()
        broken.read_text.side_effect = OSError("unreadable")
        nameless = MagicMock()
        nameless.read_text.return_value = '{"url": "file:///nowhere"}'
        nameless.metadata = {}
        remote = MagicMock()
        remote.read_text.return_value = '{"url": "https://example.invalid/x.whl"}'
        remote.metadata = {"Name": "from-an-index"}
        malformed = MagicMock()
        malformed.read_text.return_value = "{not json"
        malformed.metadata = {"Name": "malformed"}

        with (
            patch.object(
                cdk_nag_scanner_module, "packages_distributions", return_value={}
            ),
            patch.object(
                cdk_nag_scanner_module,
                "distributions",
                return_value=[broken, nameless, remote, malformed],
            ),
        ):
            located = cdk_nag_scanner_module._distributions_declaring_this_module(
                "automated_security_helper"
            )
            # Inside the patches deliberately: outside them the real distribution
            # resolves and this asserts the fallback while getting metadata.
            reqs = _cdk_extra_requirements()

        assert located == [], (
            f"none of these distributions contains this module, so none should be "
            f"reported: {located}"
        )
        assert reqs == _CDK_EXTRA_FALLBACK_REQUIREMENTS

    def test_the_install_location_strategy_finds_this_distribution(self) -> None:
        """The strategy that makes the guard live on py3.10 and py3.11.

        With the declared mapping forced empty -- the editable-install shape on
        those versions -- discovery must still resolve, from the PEP 610
        direct_url.json that records the directory this module was installed from.
        """
        with patch.object(
            cdk_nag_scanner_module, "packages_distributions", return_value={}
        ):
            located = cdk_nag_scanner_module._distributions_declaring_this_module(
                "automated_security_helper"
            )
            derived = _cdk_extra_requirements_from_metadata()

        assert located, (
            "with no declared mapping, the install-location strategy found "
            "nothing, so the metadata read falls back to the hardcoded constant "
            "and every drift guard above it goes vacuous"
        )
        assert derived is not None
        assert any("aws-cdk-lib" in req for req in derived), derived

    def test_falls_back_when_distribution_is_not_found(self) -> None:
        """An uninstalled checkout must still get a usable requirement list.

        Returning nothing here would make `ash dependencies install` exit 0
        having installed nothing, which is the original MISSING-scanner defect.

        Both discovery strategies are defeated, and that is a change in what this
        test asserts rather than a change in what it protects. An empty
        packages_distributions() used to be enough to reach the fallback; it no
        longer is, because the install-location strategy resolves the distribution
        from direct_url.json when the declared mapping is empty. That is the whole
        point of adding it -- an empty mapping is the ORDINARY state of an editable
        install on py3.10 and py3.11, and treating it as "not installed" is what
        made the drift guard vacuous there. Reaching the fallback now requires
        genuinely finding nothing, which is what an uninstalled checkout is.
        """
        with (
            patch.object(
                cdk_nag_scanner_module, "packages_distributions", return_value={}
            ),
            patch.object(cdk_nag_scanner_module, "distributions", return_value=[]),
        ):
            assert _cdk_extra_requirements() == _CDK_EXTRA_FALLBACK_REQUIREMENTS
            assert _cdk_extra_requirements_from_metadata() is None, (
                "with nothing installed the metadata read must report that it "
                "failed, not hand back the constant wearing the same shape"
            )

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

        The raise now falls through to the install-location strategy instead of
        returning immediately, so that strategy is emptied too -- otherwise this
        asserts the fallback and silently gets real metadata.
        """
        with (
            patch.object(
                cdk_nag_scanner_module, "packages_distributions", side_effect=raised
            ),
            patch.object(cdk_nag_scanner_module, "distributions", return_value=[]),
        ):
            assert _cdk_extra_requirements() == _CDK_EXTRA_FALLBACK_REQUIREMENTS

    def test_a_raising_mapping_does_not_block_the_location_strategy(self) -> None:
        """The raise must not short circuit discovery, only skip one strategy.

        Before, an OSError from packages_distributions() returned the fallback
        immediately. Since that error comes from walking sys.path rather than from
        anything about this distribution, the direct_url.json route is still
        perfectly readable and should still be tried.
        """
        with patch.object(
            cdk_nag_scanner_module,
            "packages_distributions",
            side_effect=OSError("unreadable sys.path entry"),
        ):
            derived = _cdk_extra_requirements_from_metadata()

        assert derived is not None, (
            "an unreadable sys.path entry made the whole read fail, when the "
            "install-location strategy could have answered it"
        )
        assert any("aws-cdk-lib" in req for req in derived), derived

    def test_the_url_a_directory_spells_maps_back_to_that_directory(self) -> None:
        """The assertion that was red on all four Windows cells of the matrix.

        ``as_uri()`` is the spelling pip and uv write into direct_url.json, so
        reading one back has to be its inverse. Slicing ``file://`` off
        ``file:///D:/proj`` leaves ``/D:/proj`` -- rooted, but carrying no drive
        -- which resolves against whichever drive happens to be current and so
        equals nothing. On POSIX the leftover text happens to be the right path,
        which is why every Linux and macOS cell stayed green through the defect
        and this test passes there both before and after the fix.

        Two ancestors, because the discovery loop accepts the project directory
        or any ancestor of this module; a conversion correct at only one depth
        would still be wrong.
        """
        here = Path(cdk_nag_scanner_module.__file__).resolve()

        for directory in (here.parent, here.parents[3]):
            recovered = cdk_nag_scanner_module._local_path_from_file_url(
                directory.as_uri()
            )
            assert recovered == directory, (
                f"{directory.as_uri()} did not read back as {directory}, so a "
                f"distribution installed from there cannot be recognized as the "
                f"one containing this module: {recovered}"
            )

    def test_a_windows_drive_letter_url_reads_back_as_a_drive_path(self) -> None:
        """The Windows half of the defect, asserted from any runner.

        On Windows ``urllib.request.url2pathname`` *is* ``nturl2path.url2pathname``
        -- urllib.request imports it under ``os.name == "nt"`` -- and nturl2path
        imports on every platform, so substituting it here runs the conversion the
        Windows cells run. Without this the drive-letter shape is observable only
        on a Windows runner, and the round-trip test above, which passes on POSIX
        before and after the fix, would be the only thing standing behind it.
        """
        import nturl2path

        with patch.object(
            cdk_nag_scanner_module, "url2pathname", nturl2path.url2pathname
        ):
            recovered = cdk_nag_scanner_module._local_path_from_file_url(
                "file:///D:/a/project"
            )

        assert recovered is not None
        assert PureWindowsPath(str(recovered)) == PureWindowsPath("D:/a/project"), (
            f"the drive-letter URL did not read back as a path on drive D:, so a "
            f"distribution installed from D:\\a\\project cannot be matched against "
            f"this module's own path: {recovered}"
        )
        assert PureWindowsPath(str(recovered)).drive == "D:", (
            f"the recovered path is rooted but carries no drive, which is the "
            f"shape that resolved against whatever drive was current: {recovered}"
        )

    def test_a_percent_encoded_directory_still_matches(self) -> None:
        """The other half of the same defect: nothing unquoted the URL.

        Unlike the drive-letter shape above, this misses on every platform. CI
        just never checks out into a directory whose name needs escaping, so no
        cell ever caught it. The fixture forces the escaping rather than waiting
        for a checkout path to supply it, which is what lets this fail on the
        runner that is actually available.
        """
        ancestor = Path(cdk_nag_scanner_module.__file__).resolve().parent
        head, _, tail = ancestor.as_uri().rpartition("/")
        # Escape every byte of the last segment. quote() leaves ordinary
        # characters alone, which would make this fixture identical to the plain
        # URL and the test vacuous.
        encoded = head + "/" + "".join(f"%{byte:02X}" for byte in tail.encode())
        assert encoded != ancestor.as_uri(), (
            "the fixture URL is not actually percent-encoded, so it cannot "
            "distinguish a read that unquotes from one that does not"
        )

        dist = MagicMock()
        dist.read_text.return_value = json.dumps({"url": encoded})
        dist.metadata = {"Name": "installed-from-an-escaped-path"}

        with (
            patch.object(
                cdk_nag_scanner_module, "packages_distributions", return_value={}
            ),
            patch.object(cdk_nag_scanner_module, "distributions", return_value=[dist]),
        ):
            located = cdk_nag_scanner_module._distributions_declaring_this_module(
                "automated_security_helper"
            )

        assert located == ["installed-from-an-escaped-path"], (
            f"the percent-encoded project directory did not match this module's "
            f"own path, so discovery reported nothing and the requirements fall "
            f"back to the pinned copy: {located}"
        )

    def test_the_authority_is_kept_for_a_share_and_dropped_for_localhost(self) -> None:
        """RFC 8089 puts a host in the authority; it belongs to the path.

        On Windows a host authority addresses ``\\\\server\\share``. Dropping it
        would turn that share into a local directory spelling the same tail, so a
        distribution installed from a network share could match a local path it
        has nothing to do with. Asserted as "the host survives" rather than as
        one platform's rendering of it, because only Windows renders a UNC path.

        ``localhost`` is the one authority that means *this* host and names no
        path of its own, so it has to reduce to the empty-authority form.
        """
        share = cdk_nag_scanner_module._local_path_from_file_url(
            "file://build-share/proj"
        )
        assert share is not None
        assert "build-share" in str(share), (
            f"the host authority was dropped, so a share reads as the local "
            f"directory /proj: {share}"
        )

        assert cdk_nag_scanner_module._local_path_from_file_url(
            "file://localhost/proj"
        ) == cdk_nag_scanner_module._local_path_from_file_url("file:///proj")

    def test_an_unreadable_url_is_skipped_rather_than_raising(self) -> None:
        """The walk covers every installed distribution, so nothing may escape.

        Each case is something a sibling distribution can genuinely carry: a
        non-string from hand-edited JSON, an ordinary install from an index, and
        an unterminated IPv6 authority that makes urlsplit itself raise. The last
        one is injected because only nturl2path raises for a drive specifier it
        cannot parse, and that code does not run on this runner.
        """
        assert cdk_nag_scanner_module._local_path_from_file_url(None) is None
        assert cdk_nag_scanner_module._local_path_from_file_url({"url": 1}) is None
        assert (
            cdk_nag_scanner_module._local_path_from_file_url(
                "https://example.invalid/x.whl"
            )
            is None
        )
        assert (
            cdk_nag_scanner_module._local_path_from_file_url("file://[::1/proj") is None
        )

        with patch.object(
            cdk_nag_scanner_module, "url2pathname", side_effect=OSError("Bad URL")
        ):
            assert (
                cdk_nag_scanner_module._local_path_from_file_url("file:///proj") is None
            )

    def test_falls_back_when_no_distribution_declares_the_extra(self) -> None:
        """Readable metadata with no cdk extra falls back; it does not return [].

        This expectation is the reverse of what it was, and the reversal is the
        point. The earlier version asserted ``== []`` on the argument that
        readable metadata is authoritative, so honoring it beats installing stale
        pins. That argument assumes the metadata being read belongs to ASH, and
        the code cannot know that: ``packages_distributions()`` maps a top-level
        name to every distribution providing it, so a stale or shadowing
        ``*.dist-info`` -- an editable install left beside a real one -- is read
        with exactly the same confidence as the genuine one.

        Weighed as failure modes rather than as semantics: honoring an empty read
        means ``ash dependencies install`` emits no pip command, exits 0, and
        leaves cdk-nag MISSING, which is the original defect this whole area
        exists to remove and is invisible to a caller that only checks the exit
        code. Falling back installs pins that may lag pyproject.toml by a bound,
        which is loud, recoverable, and separately guarded by
        ``test_fallback_matches_installed_metadata``.
        """
        with patch.object(
            cdk_nag_scanner_module,
            "packages_distributions",
            return_value={"automated_security_helper": ["automated-security-helper"]},
        ):
            with patch.object(
                cdk_nag_scanner_module, "requires", return_value=["requests>=2.28.0"]
            ):
                assert _cdk_extra_requirements() == _CDK_EXTRA_FALLBACK_REQUIREMENTS

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
