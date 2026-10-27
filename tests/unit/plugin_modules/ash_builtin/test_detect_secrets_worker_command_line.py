# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The command line the detect-secrets scanner starts its worker with.

The scan runs in ``python -m automated_security_helper.utils.detect_secrets_worker``.
``DetectSecretsScanner._worker_command`` returns the arguments after the
interpreter, and ``utils/python_child.python_child`` puts ASH's own interpreter in
front of them (with ``-P`` on Python 3.11 and later). A ``_worker_command`` that
returned the interpreter as well made the child's command line
``python -P python -m ...``: Python took the second ``python`` for the script to
run, tried to read the interpreter's own executable file as source, and stopped
with ``source code cannot contain null bytes``. Every scan that reached the worker
then failed with ``detect-secrets worker exited 1``.

The first two tests read the command the scanner hands to the process runner and
start nothing. The last two start the real worker through the scanner, once with
nothing to scan and once with a planted credential, so a command line that is
shaped right but does not run is caught too.
"""

import sys
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    WORKER_OUTPUT_FILE_NAME,
    WORKER_REQUEST_FILE_NAME,
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.python_child import _SAFE_PATH_FLAGS
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS, checkout_env

WORKER_MODULE = "automated_security_helper.utils.detect_secrets_worker"
SETTINGS = {"plugins_used": [{"name": "AWSKeyDetector"}]}

# Assembled at runtime so this file contains no contiguous key-shaped literal: ASH
# scans its own repository with this scanner. The value is AWS's documentation
# placeholder.
PLANTED_KEY = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002


@pytest.fixture
def scanner(test_plugin_context):
    return DetectSecretsScanner(
        context=test_plugin_context, config=DetectSecretsScannerConfig()
    )


def _scan(scanner, work_dir, paths):
    """One worker scan of *paths*, as ``DetectSecretsScanner.scan`` starts it."""
    work_dir.mkdir(parents=True, exist_ok=True)
    return scanner._scan_in_worker(
        baseline=None,
        scan_paths=paths,
        scan_settings_dict=SETTINGS,
        work_dir=work_dir,
        scan_timeout=CHILD_TIMEOUT_SECONDS,
    )


def test_the_worker_command_holds_the_arguments_after_the_interpreter(tmp_path):
    request = tmp_path / "request.json"
    output = tmp_path / "output.json"

    command = DetectSecretsScanner._worker_command(request, output)

    # The interpreter is python_child's to add. One kept here would be the second
    # one on the command line.
    assert sys.executable not in command, command
    assert command == ["-m", WORKER_MODULE, str(request), str(output)]


def test_the_worker_is_started_with_one_interpreter_running_the_module(
    scanner, tmp_path, monkeypatch
):
    starts = []

    def record(*, command, **_kwargs):
        starts.append(list(command))
        # What the worker does on success, so the scan reads a result back.
        Path(command[-1]).write_text("[]", encoding="utf-8")
        return {"returncode": 0, "timed_out": False, "stdout": "", "stderr": ""}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", record)
    work_dir = tmp_path / "results"

    _scan(scanner, work_dir, [])

    assert len(starts) == 1, starts
    argv = starts[0]
    # Element 0 is ASH's interpreter, once: Python reads a second copy as the
    # script to run.
    assert argv[0] == sys.executable, argv
    assert argv.count(sys.executable) == 1, argv
    # Then only the interpreter's own options (-P where Python has it), and then
    # the module flag, not a path to run.
    after_options = argv[1:]
    assert after_options[: len(_SAFE_PATH_FLAGS)] == _SAFE_PATH_FLAGS, argv
    after_options = after_options[len(_SAFE_PATH_FLAGS) :]
    assert after_options[:2] == ["-m", WORKER_MODULE], argv
    # And the request and output files the worker reads and writes.
    assert argv[-2:] == [
        str(work_dir.absolute() / WORKER_REQUEST_FILE_NAME),
        str(work_dir.absolute() / WORKER_OUTPUT_FILE_NAME),
    ], argv


def test_the_worker_the_scanner_starts_runs_and_reports_nothing_to_scan(
    scanner, tmp_path, monkeypatch
):
    # The child imports this checkout, not whichever copy the interpreter finds.
    monkeypatch.setenv("PYTHONPATH", checkout_env()["PYTHONPATH"])

    collection = _scan(scanner, tmp_path / "results", [])

    assert collection is not None
    assert dict(collection.data) == {}


def test_the_worker_the_scanner_starts_runs_and_reports_a_planted_key(
    scanner, tmp_path, monkeypatch
):
    monkeypatch.setenv("PYTHONPATH", checkout_env()["PYTHONPATH"])
    source = tmp_path / "source"
    source.mkdir()
    settings = source / "settings.py"
    settings.write_text(f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'\n", encoding="utf-8")
    scanner._secrets_collection.root = source

    collection = _scan(scanner, tmp_path / "results", [str(settings)])

    assert collection is not None
    [(key, secrets)] = list(collection.data.items())
    assert Path(key).name == "settings.py"
    assert [secret.type for secret in secrets] == ["AWS Access Key"]
