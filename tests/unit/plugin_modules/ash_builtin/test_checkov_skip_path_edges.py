"""checkov: empty and oversized ``--skip-path`` sets, a comma in the results path,
and a source directory behind a symlink.

* an operator ``skip_path`` entry whose path is empty became ``--skip-path=``,
  which checkov matches against every path, so checkov scanned nothing and the
  scan read as clean; it is left out with a warning;
* every ignored file became its own ``--skip-path`` value, each re-validated by
  compiling a regex over the whole accumulated list (quadratic) and with no limit
  on the argument list; the list is compiled once and bounded;
* a results directory holding a comma is split by checkov into per-format output
  paths; the scan is refused instead of writing outside the results directory;
* ``rewrite_checkov_paths`` made URIs relative to the source directory's real path
  while the scanned dirs were spelled as given, so a symlink component in the
  source directory gave absolute-looking URIs.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    _IGNORE_SKIP_PATH_CHAR_BUDGET,
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
    _module_finder_compiles,
    rewrite_checkov_paths,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()


def _scanner(source: Path, output: Path, **opts) -> CheckovScanner:
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return CheckovScanner(
        context=context,
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions(**opts)),
    )


def _skip_values(argv):
    values = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--skip-path"]
    values.extend(
        a[len("--skip-path=") :] for a in argv if a.startswith("--skip-path=")
    )
    return values


def test_an_empty_skip_path_entry_is_left_out(test_plugin_context):
    scanner = CheckovScanner(
        context=test_plugin_context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                skip_path=[
                    IgnorePathWithReason(path="", reason="a slip"),
                    IgnorePathWithReason(path="   ", reason="another slip"),
                    IgnorePathWithReason(path="cdk.out", reason="synth output"),
                ]
            )
        ),
    )
    scanner._process_config_options()
    keys = [a.key for a in scanner.args.extra_args if a.key.startswith("--skip-path=")]
    assert "--skip-path=" not in keys, keys
    assert "--skip-path=   " not in keys, keys
    assert "--skip-path=cdk.out" in keys, keys


def test_a_results_directory_with_a_comma_is_refused(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out,put"
    output.mkdir()
    with pytest.raises(ScannerError, match="comma"):
        _scanner(source, output)._execute_scan(source, "source", [])


@pytest.mark.skipif(
    os.sep != "/", reason="ignored-path --skip-path values are POSIX-only"
)
def test_ignored_files_are_compiled_once_and_bounded(tmp_path):
    source = tmp_path / "src"
    output = tmp_path / "out"
    output.mkdir(parents=True)
    source.mkdir()
    many = [f"^{source.as_posix()}/gen/file-{i:05d}[.]tf$" for i in range(3000)]
    assert sum(len(v) + 13 for v in many) > _IGNORE_SKIP_PATH_CHAR_BUDGET
    compiles: list = []
    real = _module_finder_compiles

    def counting(values):
        compiles.append(len(values))
        return real(values)

    scanner = _scanner(source, output)
    with (
        patch.object(CheckovScanner, "_ignore_skip_patterns", return_value=many),
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "checkov_scanner._module_finder_compiles",
            counting,
        ),
    ):
        argv, _, _ = scanner._execute_scan(source, "source", [])

    passed = [v for v in _skip_values(argv) if "/gen/file-" in v]
    assert 0 < len(passed) < len(many), len(passed)
    assert sum(len(v) + 13 for v in passed) <= _IGNORE_SKIP_PATH_CHAR_BUDGET
    assert len(compiles) <= 2, f"{len(compiles)} compiles for {len(many)} values"
    assert passed == many[: len(passed)]


@pytest.mark.skipif(os.name != "posix", reason="symbolic links on POSIX")
def test_a_source_directory_behind_a_symlink_gives_relative_uris(tmp_path):
    real = tmp_path / "real"
    (real / "sub").mkdir(parents=True)
    (real / "sub" / "a.tf").write_text("", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    source = link.as_posix()
    document = {
        "runs": [
            {
                "results": [
                    {
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": f"{source.lstrip('/')}/sub/a.tf"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }
    rewrite_checkov_paths(
        document, ran_in="/", source_dir=source, scanned_dirs=[source]
    )
    uri = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "sub/a.tf", uri
    assert not re.match(r"^(/|[A-Za-z]:)", uri)
