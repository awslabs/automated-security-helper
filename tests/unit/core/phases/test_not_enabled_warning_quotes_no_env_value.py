# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The warning for an off-host reporter left off names enabled's type, not its value.

An off-host reporter runs only when its section sets ``enabled`` to the boolean
true, and a section that sets it to anything else is told so once, at WARNING.
The value can be one the configuration file reads from the environment
(``enabled: ${VAR}``), so the warning names the key and the value's type, never
the value. Checked on the console and in ash.log of ``ash scan``, and on the
console of ``ash report``, which refuses the reporter outright, with the
operator's own --config file setting it. Each command runs in a child process,
so the console is the one an operator sees.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout

CANARY = "ash-canary-zq9"
AWS_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"
#: The control for the scan: the warning was written, for this reporter.
WARNING = "Reporter 's3' sends findings off the host and is not run"
#: The control for ash report, which refuses the requested reporter instead.
REFUSAL = "reporter 's3' sends findings off the host and is not enabled"

#: Run in the child before ASH loads: every start the subprocess layer would
#: make is refused and recorded, so the scan starts no real tool. detect-secrets
#: scans through its Python API and asks for its CLI (``uv tool run
#: detect-secrets --version``) only to log where it is, so a refused probe
#: changes no result. subprocess_utils is patched before uv_tool_runner is
#: imported, so uv_tool_runner's own ``from ... import spawn_run`` binds the
#: refusing stub too. The unit tests' tool guard does not reach a child process.
_REFUSE_TOOL_STARTS = (
    "import os as _os\n"
    "def _refused(args, **kwargs):\n"
    "    with open(_os.environ['REFUSED_STARTS'], 'a', encoding='utf-8') as log:\n"
    "        log.write(' '.join(str(arg) for arg in args) + '\\n')\n"
    "    raise OSError('refused: a unit test starts no tool')\n"
    "from automated_security_helper.utils import subprocess_utils as _subprocess\n"
    "_subprocess.spawn_run = _refused\n"
    "from automated_security_helper.utils import uv_tool_runner as _runner\n"
    "_runner.spawn_run = _refused\n"
)


def _ash(root: Path, *args: str) -> subprocess.CompletedProcess:
    env = {key: value for key, value in os.environ.items() if key != "ASH_CONFIG"}
    env.update(
        REFUSED_STARTS=str(root / "refused-starts.log"),
        ASH_ENABLED_CANARY=CANARY,
        # No AWS request is expected; any that were made would go nowhere.
        AWS_ACCESS_KEY_ID="testing",  # pragma: allowlist secret
        AWS_SECRET_ACCESS_KEY="testing",  # pragma: allowlist secret
        AWS_DEFAULT_REGION="us-east-1",
        AWS_ENDPOINT_URL="http://127.0.0.1:9",
        AWS_CONFIG_FILE=str(root / "no-aws-config"),
        AWS_SHARED_CREDENTIALS_FILE=str(root / "no-aws-credentials"),
        AWS_EC2_METADATA_DISABLED="true",
        COLUMNS="300",
    )
    return subprocess.run(  # nosec B603 -- the test's own interpreter, list args
        [
            sys.executable,
            "-c",
            importing_this_checkout(
                _REFUSE_TOOL_STARTS
                + "from automated_security_helper.cli.main import app; app()"
            ),
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=600,
        cwd=root,
        env=env,
        check=False,
    )


@pytest.fixture(scope="module")
def runs(tmp_path_factory: pytest.TempPathFactory):
    """An ash scan and an ash report, each with the operator's --config file
    setting reporters.s3.enabled from ASH_ENABLED_CANARY."""
    root = tmp_path_factory.mktemp("not-enabled")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    # Outside the directory either command runs in, so it is the operator's.
    config = tmp_path_factory.mktemp("operator") / "ash.yaml"
    config.write_text(
        "ash_plugin_modules:\n"
        f"  - {AWS_PLUGIN_MODULE}\n"
        "reporters:\n"
        "  s3:\n"
        "    enabled: ${ASH_ENABLED_CANARY}\n"
        "    options:\n"
        "      bucket_name: operator-bucket\n"
        "      aws_region: us-east-1\n",
        encoding="utf-8",
    )
    scan = _ash(
        root,
        "scan",
        "--no-progress",
        "--no-color",
        "--source-dir",
        "src",
        "--output-dir",
        "out",
        "--config",
        str(config),
        "--scanners",
        "detect-secrets",
        "--no-fail-on-incomplete-scanners",
        "--no-fail-on-findings",
    )
    report = _ash(
        root,
        "report",
        "--format",
        "s3",
        "--output-dir",
        str(root / "out"),
        "--config",
        str(config),
        "--no-color",
    )
    return {"root": root, "scan": scan, "report": report}


def _squeezed(text: str) -> str:
    """*text* without whitespace: the console wraps long words where it likes."""
    return "".join(text.split())


def test_the_scan_warning_names_the_type_on_the_console(runs):
    result = runs["scan"]
    printed = _squeezed(f"{result.stdout}\n{result.stderr}")

    # The control: the warning was printed, naming the key and the type.
    assert _squeezed(WARNING) in printed, (result.returncode, result.stdout[-3000:])
    assert "reporters.s3.enabled" in printed, printed
    assert _squeezed("sets enabled to a str") in printed, printed
    assert CANARY not in printed, printed


def test_the_scan_logs_name_the_type(runs):
    directory = runs["root"] / "out"
    logs = {
        path.name: path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(directory.rglob("ash.log*"))
        if path.is_file()
    }
    # The control: ash.log was written, and the warning is in every log file.
    assert "ash.log" in logs, sorted(logs)
    assert all(WARNING in text for text in logs.values()), sorted(logs)
    leaked = [name for name, text in logs.items() if CANARY in text]
    assert leaked == [], leaked


def test_the_runs_start_no_tool(runs):
    """The scan starts no tool: the one start it used to ask for, detect-secrets'
    CLI probe, is gone, so the refused-starts log is empty or absent."""
    log = runs["root"] / "refused-starts.log"
    refused = log.read_text(encoding="utf-8").splitlines() if log.exists() else []

    # Any recorded start would be a tool the scan tried to run through the
    # subprocess layer.
    assert refused == [], refused


def test_ash_report_refuses_it_without_the_value(runs):
    result = runs["report"]
    printed = _squeezed(f"{result.stdout}\n{result.stderr}")

    # The control: the reporter was refused, by name.
    assert _squeezed(REFUSAL) in printed, (result.returncode, result.stdout[-3000:])
    assert CANARY not in printed, printed
