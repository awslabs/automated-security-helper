"""Module containing the Opengrep security scanner implementation.

The bulk of the logic (arg-building, offline cache, SARIF post-processing)
lives in :mod:`_grep_scanner_base`. This module only customises:

- the binary command (`opengrep`) and its custom URL-based install commands
- version-gated `--metrics` (deprecated in opengrep 1.7.0+)
- patterns mode (`--pattern`) which switches the scanner to JSON output
"""

from __future__ import annotations

import platform
import struct
import sys
from pathlib import Path
from typing import Annotated, ClassVar, Dict, List, Literal, Optional, Tuple

from pydantic import Field, model_validator

from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.models.core import ToolArgs, ToolExtraArg
from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
    GrepScannerBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.download_utils import (
    create_url_download_command,
    get_opengrep_url,
    pinned_tool_install_commands,
)
from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import find_executable, spawn_run
from automated_security_helper.utils.process_env import snapshot_environ


class OpengrepScannerConfigOptions(ScannerOptionsBase):
    config: Annotated[
        str,
        Field(
            description="YAML configuration file, directory of YAML files ending in .yml|.yaml, URL of a configuration file, or Opengrep registry entry name. Defaults to 'p/ci' for consistent results across online and offline modes.",
        ),
    ] = "p/ci"

    exclude: Annotated[
        List[str],
        Field(
            description="Skip any file or directory whose path matches the pattern.",
        ),
    ] = ["*-converted.py", "*_report_result.txt"]

    exclude_rule: Annotated[
        List[str],
        Field(description="Skip any rule with the given id."),
    ] = []

    severity: Annotated[
        List[Literal["INFO", "WARNING", "ERROR"]],
        Field(
            description="Report findings only from rules matching the supplied severity level.",
        ),
    ] = []

    metrics: Annotated[
        Literal["auto", "on", "off"],
        Field(
            description="Configures how usage metrics are sent to the OpenGrep server. Deprecated in Opengrep v1.7.0+. This configuration is ignored if the installed version is >= 1.7.0.",
        ),
    ] = "auto"

    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, using locally cached rules. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]

    patterns: Annotated[
        List[str],
        Field(description="Patterns to search for with OpenGrep."),
    ] = []

    # The pinned version, read from the table rather than restated, so the default
    # and the digests it is verified against cannot name different releases.
    version: Annotated[
        str,
        Field(description="Version of OpenGrep to use."),
    ] = TOOL_VERSIONS["opengrep"]

    # Required for any version other than the pinned one. ASH installs no binary it
    # cannot verify, and it only carries digests for the version it pins, so a
    # custom version has to bring its own. Keyed per platform because opengrep
    # publishes a different executable for each, and a platform left out is refused
    # rather than installed unverified.
    sha256: Annotated[
        Dict[
            Literal[
                "linux/amd64",
                "linux/arm64",
                "darwin/amd64",
                "darwin/arm64",
                "windows/amd64",
            ],
            Annotated[str, Field(pattern=r"^[0-9a-fA-F]{64}$")],
        ],
        Field(
            description=(
                "SHA256 of the OpenGrep release asset for a custom `version`, keyed "
                "by platform/arch (e.g. linux/amd64). Required for any version other "
                "than the one ASH pins; ignored for the pinned version, whose digests "
                "ship with ASH. Get it from GitHub's per-asset digest for the "
                "release, or by running sha256sum on the downloaded asset."
            ),
        ),
    ] = {}


class OpengrepScannerConfig(ScannerPluginConfigBase):
    name: Literal["opengrep"] = "opengrep"
    enabled: bool = platform.system().lower() != "windows"
    options: Annotated[
        OpengrepScannerConfigOptions, Field(description="Configure Opengrep scanner")
    ] = OpengrepScannerConfigOptions()


def unverified_version_refusal(
    version: str, target_platform: str, arch: str, asset: str
) -> str:
    """The message a custom opengrep version without a digest is refused with."""
    pinned = TOOL_VERSIONS["opengrep"]
    return (
        f"Refusing to install opengrep {version} on {target_platform}/{arch}: ASH pins "
        f"opengrep {pinned}, and the configuration supplies no SHA256 for "
        f"{target_platform}/{arch}, so the download could not be verified. Either drop "
        f"scanners.opengrep.options.version to use the pinned {pinned}, or add the "
        f"digest of the release asset {asset} under "
        f'scanners.opengrep.options.sha256 as "{target_platform}/{arch}": '
        f'"<sha256>". Get it from the digest GitHub lists for that asset '
        f"(gh api repos/opengrep/opengrep/releases/tags/{version} --jq "
        f"'.assets[] | select(.name == \"{asset}\") | .digest'), or by running "
        f"sha256sum {asset} on the downloaded asset."
    )


def _refuse_unverified_install_command(
    version: str, target_platform: str, arch: str, asset: str
) -> CustomCommand:
    """An install command that prints the refusal and exits 1, installing nothing.

    ``sys.exit`` with a string writes it to stderr and exits 1, so the installer
    counts the command as failed and shows why. The message travels as an argument
    rather than inside the ``-c`` source, so nothing in it is interpreted as code.
    """
    return CustomCommand(
        args=[
            sys.executable,
            "-c",
            "import sys; sys.exit(sys.argv[1])",
            unverified_version_refusal(version, target_platform, arch, asset),
        ],
        shell=False,
    )


@ash_scanner_plugin
class OpengrepScanner(GrepScannerBase[OpengrepScannerConfig]):
    """OpengrepScanner implements code scanning using Opengrep."""

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        cache_paths=("~/.opengrep",),
        env_prefixes=("OPENGREP_", "SEMGREP_"),
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = OpengrepScannerConfig()
        self.command = "opengrep"
        self.subcommands = ["scan"]
        self.tool_type = ScannerToolType.SAST
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg="--sarif-output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "OpengrepScanner":
        """Set up custom installation commands for opengrep.

        No path installs an unverified binary.

        * The pinned version is installed from ``utils/tool_downloads.py``, verified
          against its SHA256 before it is put on disk, exactly as grype, syft and
          trivy are.
        * A custom ``version`` is installed only on a platform for which the
          configuration supplies ``sha256``, and goes through the same verified
          download, failing closed on a mismatch.
        * A custom ``version`` with no digest for a platform gets a command that
          refuses, naming the key to add and how to obtain the value.

        Before this, every install fetched the release asset by URL with no digest
        at all, so the binary a SAST scan then trusted was whatever that URL served.
        The refusal is an install command rather than a validation error on purpose:
        a config naming a custom version must still load, so a host that already has
        opengrep can scan with it, and only the install is refused.
        """
        version = self.config.options.version
        if version == TOOL_VERSIONS["opengrep"]:
            self.custom_install_commands.update(
                pinned_tool_install_commands("opengrep")
            )
            return self

        digests = self.config.options.sha256
        # TODO: detect manylinux vs musllinux
        for target_platform, arch in (
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("windows", "amd64"),
        ):
            url = get_opengrep_url(
                target_platform, arch, version=version, linux_type="manylinux"
            )
            digest = digests.get(f"{target_platform}/{arch}")
            if digest is None:
                command = _refuse_unverified_install_command(
                    version, target_platform, arch, url.rsplit("/", 1)[-1]
                )
            else:
                command = create_url_download_command(
                    url=url,
                    rename_to=(
                        "opengrep.exe" if target_platform == "windows" else "opengrep"
                    ),
                    expected_sha256=digest,
                )
            self.custom_install_commands.setdefault(target_platform, {})[arch] = [
                command
            ]
        return self

    # ---------------------------------------------------------------
    # GrepScannerBase hooks
    # ---------------------------------------------------------------

    def cache_dir_env_var(self) -> str:
        return "OPENGREP_RULES_CACHE_DIR"

    def cache_dir_name(self) -> str:
        return "Opengrep"

    def default_rulesets(self) -> List[str]:
        return ["p/ci"]

    def emit_metrics_flag(self) -> bool:
        """`--metrics` was removed in opengrep 1.7.0; only emit on older versions."""
        return self._should_use_metrics_flag()

    # ---------------------------------------------------------------
    # Dependency resolution
    # ---------------------------------------------------------------

    def _validate_tool_dependencies(self) -> bool:
        """Opengrep's tool-reachability check.

        Named for the ``GrepScannerBase`` hook rather than overriding
        ``validate_plugin_dependencies`` directly: the base method now consults the
        offline-cache verdict first, and an override here would skip it.
        """
        found = find_executable(self.command)
        ASH_LOGGER.verbose(f"Found opengrep executable at: {found}")
        return found is not None

    def _has_install_commands(self) -> bool:
        system = platform.system().lower()
        arch = "amd64" if struct.calcsize("P") * 8 == 64 else "arm64"
        if system in self.custom_install_commands:
            if arch in self.custom_install_commands[system]:
                return len(self.custom_install_commands[system][arch]) > 0
        return False

    # ---------------------------------------------------------------
    # Version detection (used to gate --metrics)
    # ---------------------------------------------------------------

    def _get_opengrep_version(self) -> tuple[int, int, int] | None:
        try:
            result = spawn_run(  # nosec B603 — list args, executable from find_executable()
                [self.command, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                env=snapshot_environ(),
            )
            if result.returncode == 0:
                version_str = result.stdout.strip().split()[-1].lstrip("v")
                parts = version_str.split(".")
                if len(parts) >= 3:
                    return (int(parts[0]), int(parts[1]), int(parts[2]))
        except FileNotFoundError:
            return None
        except Exception as e:
            ASH_LOGGER.verbose(f"Unable to determine Opengrep version: {e}")
        return None

    def _should_use_metrics_flag(self) -> bool:
        version = self._get_opengrep_version()
        if version is None:
            ASH_LOGGER.verbose(
                "Unable to determine Opengrep version, assuming --metrics is NOT supported (default version >= 1.7.0)"
            )
            return False
        if version >= (1, 7, 0):
            ASH_LOGGER.verbose(
                f"Opengrep version {'.'.join(map(str, version))} detected, skipping --metrics flag"
            )
            return False
        ASH_LOGGER.verbose(
            f"Opengrep version {'.'.join(map(str, version))} detected, using --metrics flag"
        )
        return True

    # ---------------------------------------------------------------
    # Patterns mode — opengrep-only override
    # ---------------------------------------------------------------

    def _process_config_options(self):
        result = super()._process_config_options()

        # Patterns mode: switch to JSON output and replace extra_args with
        # only --json + --pattern entries (matches pre-refactor behaviour).
        if self.config.options.patterns:
            self.args.extra_args = [ToolExtraArg(key="--json", value="")]
            for pattern in self.config.options.patterns:
                self.args.extra_args.append(
                    ToolExtraArg(key="--pattern", value=pattern)
                )

        return result

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths,
    ) -> Tuple[List[str], Path, Optional[dict]]:
        final_args, results_file, env = super()._execute_scan(
            target, target_type, global_ignore_paths
        )
        if self.config.options.patterns:
            results_file = results_file.parent / "opengrep_results.json"
            # Re-resolve final_args so output_arg uses the json path.
            final_args = self._resolve_arguments(
                target=target, results_file=results_file
            )
        return final_args, results_file, env
