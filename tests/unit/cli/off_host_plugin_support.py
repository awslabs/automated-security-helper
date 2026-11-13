# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""What the ``ash report`` and ``ash merge`` plugin-reporter tests share.

These tests run the command in a subprocess against a stand-in reporter from a
plugin package written outside every scanned tree, because importing a plugin
package registers its plugins for the rest of the process. This module holds the
stand-in's source, the drivers the subprocess runs, and the helpers that build the
package, the environment and the command line. It has no tests of its own, so no
test module has to import another one for them.

The stand-in sends nothing: its ``report`` returns the options it was built with.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Sequence

from tests.utils.helpers import importing_this_checkout

PLUGIN = "quiet_ash_plugins"
REPORTER = "quiet-offhost"
DEFAULT_ENDPOINT = "https://default.invalid/"
FILE_ENDPOINT = "https://file.invalid/"
OVERRIDE_ENDPOINT = "https://override.invalid/"

DECLARED_PLUGIN = "declared_ash_plugins"
DECLARED_REPORTER = "declared-offhost"

DECLARED_ON_PLUGIN = "declared_on_ash_plugins"
DECLARED_ON_REPORTER = "declared-on-offhost"


def reporter_source(
    prefix: str,
    reporter: str,
    extension: str,
    *,
    enabled: bool,
    declares_destinations: bool,
) -> str:
    """The source of a plugin package holding one off-host stand-in reporter.

    The reporter takes two options, ``endpoint`` and ``title``. With
    ``declares_destinations`` it lists ``endpoint`` in ``destination_options``;
    without, it declares none. ``enabled`` is the default its config model gives
    ``enabled``.
    """
    typing_names = "Annotated, ClassVar, Literal"
    declared = ""
    if declares_destinations:
        typing_names += ", Tuple"
        declared = (
            '\n    destination_options: ClassVar[Tuple[str, ...]] = ("endpoint",)'
        )
    return f'''
import json
from typing import {typing_names}

from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class {prefix}ReporterOptions(ReporterOptionsBase):
    endpoint: str = "{DEFAULT_ENDPOINT}"
    title: str = "default title"


class {prefix}ReporterConfig(ReporterPluginConfigBase):
    name: Literal["{reporter}"] = "{reporter}"
    extension: str = "{extension}"
    enabled: bool = {enabled}
    options: Annotated[{prefix}ReporterOptions, Field()] = {prefix}ReporterOptions()


@ash_reporter_plugin
class {prefix}Reporter(ReporterPluginBase[{prefix}ReporterConfig]):
    sends_off_host: ClassVar[bool] = True{declared}

    def model_post_init(self, context):
        if self.config is None:
            self.config = {prefix}ReporterConfig()
        return super().model_post_init(context)

    def report(self, model):
        options = self.config.options
        return json.dumps({{"endpoint": options.endpoint, "title": options.title}})


ASH_REPORTERS = [{prefix}Reporter]
'''


#: The stand-in that declares no destination options and is off by default.
PLUGIN_SOURCE = reporter_source(
    "Quiet", REPORTER, "quiet.json", enabled=False, declares_destinations=False
)

#: The stand-in that declares ``endpoint`` as a destination option and is off by
#: default.
DECLARED_SOURCE = reporter_source(
    "Declared",
    DECLARED_REPORTER,
    "declared.json",
    enabled=False,
    declares_destinations=True,
)

#: The stand-in that declares ``endpoint`` as a destination option and is ON by
#: default. Its own default is what a ``true`` in a config file would match.
DECLARED_ON_SOURCE = reporter_source(
    "DeclaredOn",
    DECLARED_ON_REPORTER,
    "declared-on.json",
    enabled=True,
    declares_destinations=True,
)

#: Runs ``ash report`` with the arguments in ``argv[1]`` and prints the exit code
#: and the output as JSON.
REPORT_DRIVER = """
import json, os, sys

spec = json.loads(sys.argv[1])
os.chdir(spec["cwd"])

from typer.testing import CliRunner
from automated_security_helper.cli.main import app

result = CliRunner().invoke(app, spec["args"])
print(json.dumps({"exit": result.exit_code, "output": result.output}))
"""

#: Hands back the warnings ASH logged, for a driver that wants them. A filter, not a
#: handler: the command sets the logger up again, which drops every handler and
#: keeps the filters. It follows the driver's imports and defines ``warnings``.
COLLECT_WARNINGS = """
import logging

from automated_security_helper.utils.log import ASH_LOGGER

warnings = []


class _Collect(logging.Filter):
    def filter(self, record):
        if record.levelno >= logging.WARNING:
            warnings.append(record.getMessage())
        return True


ASH_LOGGER.addFilter(_Collect())
"""

#: Runs ``ash merge`` and prints the exit code, the output, the files it wrote to
#: ``reports/`` and the warnings.
MERGE_DRIVER = (
    """
import json, os, sys

spec = json.loads(sys.argv[1])
os.chdir(spec["cwd"])

from pathlib import Path
from typer.testing import CliRunner
from automated_security_helper.cli.main import app
"""
    + COLLECT_WARNINGS
    + """
result = CliRunner().invoke(app, spec["args"])
reports = {}
directory = Path(spec["output"]) / "reports"
if directory.is_dir():
    for entry in sorted(directory.iterdir()):
        if entry.is_file():
            reports[entry.name] = entry.read_text(encoding="utf-8", errors="replace")
print(json.dumps({"exit": result.exit_code, "output": result.output, "reports": reports, "warnings": warnings}))
"""
)

#: Variables that would make the subprocess read a config or a plugin list the
#: test did not write.
AMBIENT = ("ASH_CONFIG", "ASH_PLUGIN_MODULES", "ASH_OUTPUT_DIR")


def make_plugin_site(tmp_path: Path, package: str, source: str) -> Path:
    """An installed plugin package, written outside every scanned tree.

    ``package`` is the importable name and ``source`` its ``__init__.py``. Calling
    it again with the same ``tmp_path`` adds another package to the same site
    directory. Returns the directory to make importable with
    ``plugin_environment``.
    """
    site = tmp_path / "site"
    (site / package).mkdir(parents=True, exist_ok=True)
    (site / package / "__init__.py").write_text(source, encoding="utf-8")
    return site


def plugin_environment(site: Path) -> Dict[str, str]:
    """The subprocess's environment: the caller's, less ``AMBIENT``, with ``site`` importable."""
    environment = {k: v for k, v in os.environ.items() if k not in AMBIENT}
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(site), *filter(None, [os.environ.get("PYTHONPATH")])]
    )
    return environment


def outside_every_checkout(path: Path) -> None:
    """Precondition: no directory holding ``path`` is a git checkout.

    Inside one, the file would be held to the repository's rules for that reason
    alone, and a test of the case nothing else marks would pass vacuously.
    """
    holding = [path, *path.parents]
    assert not any((p / ".git").exists() for p in holding), holding


def write_results(output: Path) -> None:
    """Write an empty aggregated results file into ``output``, which must not exist."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    output.mkdir(parents=True)
    (output / "ash_aggregated_results.json").write_text(
        AshAggregatedResults(ash_config=AshConfig()).model_dump_json(),
        encoding="utf-8",
    )


def run_report(
    tmp_path: Path,
    site: Path,
    overrides: List[str],
    plugin: str = PLUGIN,
    reporter: str = REPORTER,
) -> Dict:
    """``ash report --format <reporter> --config <file outside every tree>``.

    The file enables the reporter and gives it an endpoint and a title. ``plugin``
    and ``reporter`` name the stand-in, which must take the two options
    ``endpoint`` and ``title``; the plugin module is named by an override, as a
    caller of the command would name it.
    """
    repo = tmp_path / "repo"
    output = repo / ".ash" / "ash_output"
    write_results(output)
    operator = tmp_path / "operator" / ".ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        f"reporters:\n"
        f"  {reporter}:\n"
        f"    enabled: true\n"
        f"    options:\n"
        f"      endpoint: {FILE_ENDPOINT}\n"
        f"      title: file title\n",
        encoding="utf-8",
    )
    outside_every_checkout(operator)
    args = ["report", "--format", reporter, "--config", str(operator)]
    args += ["--output-dir", str(output)]
    for override in [f"ash_plugin_modules=[{plugin}]", *overrides]:
        args += ["--config-overrides", override]
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            importing_this_checkout(REPORT_DRIVER),
            json.dumps({"cwd": str(repo), "args": args}),
        ],
        cwd=tmp_path,
        env=plugin_environment(site),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr[-4000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def run_merge(
    tmp_path: Path,
    site: Path,
    overrides: List[str],
    plugin: str = PLUGIN,
    reporter: str = REPORTER,
    extra_args: Sequence[str] = (),
) -> Dict:
    """``ash merge --config <file outside every tree>`` over two shards.

    The file names the plugin module, enables the reporter and gives it an
    endpoint and a title. It lives in ``tmp_path/operator``, and the command runs
    in ``tmp_path/collector``, a directory in no git checkout. ``plugin`` and
    ``reporter`` name the stand-in, which must take the two options ``endpoint``
    and ``title``. ``extra_args`` are appended to the command line after the
    overrides, for a test that passes another option (``--output-formats``).
    """
    from tests.unit.cli.merge_shard_support import build_shards, write_shards

    shards = write_shards(tmp_path / "artifacts", build_shards(2))
    operator = tmp_path / "operator" / ".ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        f"ash_plugin_modules:\n"
        f"  - {plugin}\n"
        f"reporters:\n"
        f"  {reporter}:\n"
        f"    enabled: true\n"
        f"    options:\n"
        f"      endpoint: {FILE_ENDPOINT}\n"
        f"      title: file title\n",
        encoding="utf-8",
    )
    outside_every_checkout(operator)
    collector = tmp_path / "collector"
    collector.mkdir()
    outside_every_checkout(collector)
    output = tmp_path / "merged"
    args = ["merge", "--no-color", "--output-dir", str(output)]
    for shard in shards:
        args += ["--results", shard]
    args += ["--config", str(operator)]
    for override in overrides:
        args += ["--config-overrides", override]
    args += list(extra_args)
    spec = {"cwd": str(collector), "args": args, "output": str(output)}
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            importing_this_checkout(MERGE_DRIVER),
            json.dumps(spec),
        ],
        cwd=tmp_path,
        env=plugin_environment(site),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-4000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def reporter_texts(result: Dict) -> List[str]:
    """What the stand-in reporter wrote: the report files that name its options."""
    return [
        text
        for text in result["reports"].values()
        if '"endpoint"' in text and '"title"' in text
    ]
