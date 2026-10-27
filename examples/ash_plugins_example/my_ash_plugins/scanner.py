# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Example scanner plugin for ASH."""

from pathlib import Path
from typing import Annotated, Any, ClassVar, List, Literal, Optional, Tuple

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    open_in_scanned_tree,
)

RULE_ID = "EXAMPLE-001"


class ExampleScannerConfigOptions(ScannerOptionsBase):
    marker: str = Field(
        default="TODO(security)",
        description="Text that marks a line for review",
    )


class ExampleScannerConfig(ScannerPluginConfigBase):
    """Configuration for the example scanner."""

    name: Literal["my-example-scanner"] = "my-example-scanner"
    enabled: bool = True
    options: Annotated[
        ExampleScannerConfigOptions,
        Field(description="Configure my-example-scanner"),
    ] = ExampleScannerConfigOptions()


@ash_scanner_plugin
class ExampleScanner(ScannerPluginBase[ExampleScannerConfig]):
    """Reports every line that contains a marker, as a SARIF ``note`` result.

    A pure-Python scanner, so it overrides ``scan()`` instead of running a tool
    through the base class's ``_execute_scan`` template. ``note`` maps to LOW, which
    is below ASH's default severity threshold: the findings appear in every report
    and do not fail the scan.
    """

    # Runs in-process and starts no other program, so --python-only keeps it. A
    # scanner that declares nothing counts as Python-only only when it runs its tool
    # through uv; see "Declaring whether a scanner is Python-only" in the guide.
    python_only: ClassVar[bool | None] = True

    def model_post_init(self, context):
        if self.config is None:
            self.config = ExampleScannerConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Pure Python, so there is nothing to install."""
        return True

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[dict]]:
        """Required by the base class, and never reached: scan() is overridden."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: Any = None,
        *args,
        **kwargs,
    ) -> SarifReport | bool:
        """Scan one target and return the findings as a SarifReport.

        ASH calls this once for the source directory and, when a converter wrote
        files, once more for the converted files. Only a SarifReport carries
        findings into the reports; return False when the scanner cannot run.
        """
        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False

        marker = self.config.options.marker
        ASH_LOGGER.info(f"ExampleScanner: scanning {target} ({target_type})")

        if target_type == "converted":
            # The converted files live under the work directory, outside the scan
            # set, so they are listed directly.
            root = Path(target)
            files = [p for p in root.rglob("*") if p.is_file()]
        else:
            root = Path(self.context.source_dir)
            files = [
                Path(name.rstrip("\n"))
                for name in scan_set(
                    source=self.context.source_dir, output=self.context.output_dir
                )
            ]

        results = []
        for path in files:
            # Opened through open_in_scanned_tree, never by name: it refuses a
            # symlink, a file with a second hard link and a path outside the tree,
            # any of which could be a file elsewhere on the host.
            try:
                with open_in_scanned_tree(path, root) as handle:
                    lines = handle.read().decode("utf-8").splitlines()
            except (TreeInputRefused, OSError, UnicodeDecodeError):
                continue
            for line_number, line in enumerate(lines, start=1):
                if marker in line:
                    results.append(
                        {
                            "ruleId": RULE_ID,
                            "level": "note",
                            "message": {"text": f"Line marked {marker!r} for review"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        # Absolute here; ASH makes paths under the
                                        # source directory relative to it.
                                        "artifactLocation": {
                                            "uri": path.absolute().as_posix()
                                        },
                                        "region": {"startLine": line_number},
                                    }
                                }
                            ],
                        }
                    )

        self._post_scan(target=target, target_type=target_type)
        return SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "my-example-scanner",
                                "version": "0.1.0",
                                "rules": [
                                    {
                                        "id": RULE_ID,
                                        "shortDescription": {
                                            "text": "Line marked for security review"
                                        },
                                    }
                                ],
                            }
                        },
                        "results": results,
                    }
                ],
            }
        )
