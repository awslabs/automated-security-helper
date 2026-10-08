"""Substitutes for ``DetectSecretsScanner._worker_command`` in tests.

detect-secrets scans in a subprocess (``utils/detect_secrets_worker.py``), so a test
can no longer patch ``SecretsCollection.scan_files`` or ``transient_settings`` in the
test process and see the scan. What those patches observed -- the file list handed to
``scan_files`` and the dict handed to ``transient_settings`` -- is exactly the worker's
request, so :func:`capturing_worker_command` records the request and then runs the
real worker. The other two replace the worker with one that fails or hangs.

Install with
``monkeypatch.setattr(DetectSecretsScanner, "_worker_command", staticmethod(cmd))``.
"""

import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List

WorkerCommand = Callable[[Path, Path], List[str]]


def capturing_worker_command(capture_file: Path) -> WorkerCommand:
    """Copy the worker's request to ``capture_file``, then run the real worker."""
    code = (
        "import runpy, shutil, sys\n"
        "shutil.copyfile(sys.argv[1], sys.argv[3])\n"
        "sys.argv = [sys.argv[0], sys.argv[1], sys.argv[2]]\n"
        "runpy.run_module('automated_security_helper.utils.detect_secrets_worker',"
        " run_name='__main__', alter_sys=True)\n"
    )

    def command(request_file: Path, output_file: Path) -> List[str]:
        return [
            sys.executable,
            "-c",
            code,
            str(request_file),
            str(output_file),
            str(capture_file),
        ]

    return command


def read_capture(capture_file: Path) -> Dict[str, Any]:
    with open(capture_file, encoding="utf-8") as f:
        return json.load(f)


def failing_worker_command(message: str) -> WorkerCommand:
    """A worker that raises RuntimeError(message) before scanning anything."""

    def command(request_file: Path, output_file: Path) -> List[str]:
        return [sys.executable, "-c", f"raise RuntimeError({message!r})"]

    return command


def hanging_worker_command(seconds: float) -> WorkerCommand:
    """A worker that sleeps for ``seconds`` and writes nothing."""

    def command(request_file: Path, output_file: Path) -> List[str]:
        return [sys.executable, "-c", f"import time; time.sleep({seconds!r})"]

    return command
