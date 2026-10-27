# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""detect-secrets runs in a worker subprocess so the scanner sandbox can wrap it.

Pins the two things the move has to preserve: the worker reports the same
collection the in-process scan built (same keys, same secrets), and the scanner
asks the sandbox for a network only when its settings verify secrets online. Also
pins that the column the worker adds is taken from the line detect-secrets
numbered, counting lines as detect-secrets counts them.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScanSettingsFiltersUsed,
)
from automated_security_helper.utils.detect_secrets_worker import (
    START_COLUMN_KEY,
    _start_column,
)
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS, checkout_env
from tests.utils.refusing_proxy import (
    RecordingProxy,
    route_through,
    scrub_cloud_credentials,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret


def _in_process(root, paths, settings):
    from detect_secrets.core.secrets_collection import SecretsCollection
    from detect_secrets.settings import transient_settings

    collection = SecretsCollection()
    collection.root = str(root)
    with transient_settings(settings):
        collection.scan_files(*paths)
    return {
        key: sorted(json.dumps(s.json(), sort_keys=True) for s in secrets)
        for key, secrets in collection.data.items()
    }


def _run_worker(tmp_path, root, paths, settings):
    """The worker's OUTPUT for one scan, started as the scanner starts it."""
    request = tmp_path / "request.json"
    output = tmp_path / "output.json"
    request.write_text(
        json.dumps(
            {"root": str(root), "baseline": None, "settings": settings, "paths": paths}
        ),
        encoding="utf-8",
    )
    subprocess.run(  # nosec B603 - fixed argv
        [
            sys.executable,
            "-m",
            "automated_security_helper.utils.detect_secrets_worker",
            str(request),
            str(output),
        ],
        check=True,
        cwd=tmp_path,
        timeout=CHILD_TIMEOUT_SECONDS,
        env=checkout_env(),
    )
    return json.loads(output.read_text(encoding="utf-8"))


def test_worker_reports_the_collection_the_in_process_scan_builds(tmp_path):
    src = tmp_path / "src"
    (src / "a").mkdir(parents=True)
    (src / "a" / "one.py").write_text(f'key = "{AWS_KEY}"\n', encoding="utf-8")
    (src / "two.py").write_text(f'\n\nother = "{AWS_KEY}"\n', encoding="utf-8")
    paths = [str(p) for p in sorted(src.rglob("*.py"))]
    settings = {"plugins_used": [{"name": "AWSKeyDetector"}]}

    written = _run_worker(tmp_path, src, paths, settings)
    # The worker adds the column each secret starts at, which detect-secrets does
    # not report; everything else is the in-process collection's.
    columns = {
        (key, secret["line_number"]): secret.pop(START_COLUMN_KEY, None)
        for key, secrets in written
        for secret in secrets
    }
    from_worker = {
        key: sorted(json.dumps(s, sort_keys=True) for s in secrets)
        for key, secrets in written
    }

    expected = _in_process(src, paths, settings)
    assert expected, "the fixture should contain findings"
    assert from_worker == expected
    assert sorted(columns.values()) == [
        len('key = "') + 1,
        len('other = "') + 1,
    ], columns


#: Characters ``str.splitlines`` ends a line at and detect-secrets does not.
#: detect-secrets reads a file with universal newlines, which end a line only at
#: ``\n``, ``\r`` and ``\r\n``.
NOT_LINE_BREAKS = {
    "vertical-tab": "\v",
    "form-feed": "\f",
    "file-separator": "\x1c",
    "group-separator": "\x1d",
    "record-separator": "\x1e",
    "next-line": "\N{NEXT LINE}",
    "line-separator": "\N{LINE SEPARATOR}",
    "paragraph-separator": "\N{PARAGRAPH SEPARATOR}",
}
#: The line ends of universal newlines other than ``\n``.
LINE_BREAKS = {"carriage-return": "\r", "crlf": "\r\n"}


def test_a_separator_above_the_key_keeps_its_line_and_column(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    for name, separator in {**NOT_LINE_BREAKS, **LINE_BREAKS}.items():
        text = f'a = 1{separator}b = 2\nkey = "{AWS_KEY}"\n'
        (src / f"{name}.py").write_bytes(text.encode("utf-8"))
    paths = [str(p) for p in sorted(src.glob("*.py"))]
    settings = {"plugins_used": [{"name": "AWSKeyDetector"}]}

    written = _run_worker(tmp_path, src, paths, settings)

    found = {
        Path(secret["filename"]).stem: (
            secret["line_number"],
            secret.get(START_COLUMN_KEY),
        )
        for _, secrets in written
        for secret in secrets
    }
    column = len('key = "') + 1
    assert found == {
        **dict.fromkeys(NOT_LINE_BREAKS, (2, column)),
        **dict.fromkeys(LINE_BREAKS, (3, column)),
    }


def test_a_file_is_read_only_as_far_as_the_line_asked_for(tmp_path):
    source = tmp_path / "long.py"
    source.write_text(
        f'key = "{AWS_KEY}"\n' + "x = 1\n" * 1000 + f'other = "{AWS_KEY}"\n',
        encoding="utf-8",
    )
    cache = {}

    def column(line_number):
        secret = SimpleNamespace(
            secret_value=AWS_KEY, line_number=line_number, filename=str(source)
        )
        return _start_column(secret, cache)

    assert column(1) == len('key = "') + 1
    assert len(cache[str(source)]) == 1
    assert column(1002) == len('other = "') + 1
    assert len(cache[str(source)]) == 1002
    assert column(1) == len('key = "') + 1
    assert len(cache[str(source)]) == 1002


def _scanner(tmp_path):
    ctx = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    return DetectSecretsScanner(context=ctx, config=DetectSecretsScannerConfig())


def test_no_network_unless_secrets_are_verified_online(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scanner = _scanner(tmp_path)
    assert scanner.sandbox_requirements.network is False
    assert isinstance(scanner.sandbox_requirements, SandboxRequirements)

    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(
            path="detect_secrets.filters.common.is_ignored_due_to_verification_policies",
            min_level=2,
        )
    ]
    assert scanner.sandbox_requirements.network is True


#: AWS's documentation placeholder secret key, in parts so that this file holds no
#: key-shaped literal for ASH's own detect-secrets self-scan to report.
_SECRET_KEY_PARTS = ("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCY", "EXAMPLEKEY")


def _verifying_worker_run(tmp_path, verify):
    """Run the worker on a key pair with the verification filter in its settings."""
    secret = "".join(_SECRET_KEY_PARTS)
    src = tmp_path / "src"
    src.mkdir()
    target = src / "creds.py"
    target.write_text(
        f'aws_access_key_id = "{AWS_KEY}"\naws_secret_access_key = "{secret}"\n',
        encoding="utf-8",
    )
    request = {
        "root": str(src),
        "baseline": None,
        "settings": {
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [
                {
                    "path": "detect_secrets.filters.common.is_ignored_due_to_verification_policies",
                    "min_level": 2,
                }
            ],
        },
        "paths": [str(target)],
    }
    if verify is not None:
        request["verify"] = verify
    request_file = tmp_path / "request.json"
    output = tmp_path / "output.json"
    request_file.write_text(json.dumps(request), encoding="utf-8")
    subprocess.run(  # nosec B603 - fixed argv
        [
            sys.executable,
            "-m",
            "automated_security_helper.utils.detect_secrets_worker",
            str(request_file),
            str(output),
        ],
        check=True,
        cwd=tmp_path,
        timeout=CHILD_TIMEOUT_SECONDS,
    )
    return json.loads(output.read_text(encoding="utf-8"))


@pytest.mark.parametrize("verify", [False, None], ids=["verify-false", "no-verify-key"])
def test_the_worker_sends_no_request_unless_the_scan_may_verify(
    tmp_path, monkeypatch, verify
):
    """The scanner removes the filter when verification may not run; the worker
    also refuses the requests, so a filter that reaches it anyway sends nothing.
    The secret is still reported, as unverified."""
    scrub_cloud_credentials(monkeypatch)
    proxy = RecordingProxy()
    route_through(monkeypatch, proxy)
    try:
        scanned = _verifying_worker_run(tmp_path, verify)
    finally:
        proxy.close()

    assert proxy.external_requests() == [], proxy.requests
    assert scanned and scanned[0][1], "the key was not reported"


def test_control_the_worker_verifies_when_the_scan_may(tmp_path, monkeypatch):
    """Control: with verify true the same run asks the issuer (the refusing local
    proxy answers), which shows the run above would have sent a request."""
    scrub_cloud_credentials(monkeypatch)
    proxy = RecordingProxy()
    route_through(monkeypatch, proxy)
    try:
        _verifying_worker_run(tmp_path, True)
    finally:
        proxy.close()

    assert any("sts.amazonaws.com" in line for line in proxy.external_requests()), (
        proxy.requests
    )


# ---------------------------------------------------------------------------
# Pool processes started with 'spawn' (macOS, Windows)
# ---------------------------------------------------------------------------

#: Runs the worker as on macOS and Windows: multiprocessing's 'spawn' start method,
#: which the worker's own switch to 'fork' (Linux only) cannot override here.
_SPAWN_WORKER = """
import multiprocessing, runpy, sys
multiprocessing.set_start_method("spawn", force=True)
_set = multiprocessing.set_start_method
multiprocessing.set_start_method = (
    lambda method, force=False: None if method == "fork" else _set(method, force=force)
)
sys.argv = ["detect_secrets_worker", sys.argv[1], sys.argv[2]]
runpy.run_module(
    "automated_security_helper.utils.detect_secrets_worker",
    run_name="__main__",
    alter_sys=True,
)
"""


def _spawn_pool_run(tmp_path, monkeypatch, refuse_env):
    """Three files, so detect-secrets scans them in a pool; verify is false."""
    from automated_security_helper.utils.detect_secrets_worker import REFUSE_HTTP_ENV

    scrub_cloud_credentials(monkeypatch)
    proxy = RecordingProxy()
    route_through(monkeypatch, proxy)
    if refuse_env:
        monkeypatch.setenv(REFUSE_HTTP_ENV, "1")
    else:
        monkeypatch.delenv(REFUSE_HTTP_ENV, raising=False)
    secret = "".join(_SECRET_KEY_PARTS)
    src = tmp_path / "src"
    src.mkdir()
    paths = []
    for index in range(3):
        target = src / f"creds{index}.py"
        target.write_text(
            f'aws_access_key_id = "{AWS_KEY}"\naws_secret_access_key = "{secret}"\n',
            encoding="utf-8",
        )
        paths.append(str(target))
    request = tmp_path / "request.json"
    output = tmp_path / "output.json"
    request.write_text(
        json.dumps(
            {
                "root": str(src),
                "baseline": None,
                "settings": {
                    "plugins_used": [{"name": "AWSKeyDetector"}],
                    "filters_used": [
                        {
                            "path": "detect_secrets.filters.common.is_ignored_due_to_verification_policies",
                            "min_level": 2,
                        }
                    ],
                },
                "paths": paths,
                "verify": False,
            }
        ),
        encoding="utf-8",
    )
    try:
        subprocess.run(  # nosec B603 - fixed argv
            [sys.executable, "-c", _SPAWN_WORKER, str(request), str(output)],
            check=True,
            cwd=tmp_path,
            timeout=300,
        )
    finally:
        proxy.close()
    return proxy, json.loads(output.read_text(encoding="utf-8"))


def test_spawned_pool_processes_send_no_request_either(tmp_path, monkeypatch):
    """The scanner starts the worker with ASH_DETECT_SECRETS_REFUSE_HTTP=1; pool
    processes started with 'spawn' import the worker again and refuse too."""
    proxy, scanned = _spawn_pool_run(tmp_path, monkeypatch, refuse_env=True)

    assert proxy.external_requests() == [], proxy.requests
    assert len(scanned) == 3, scanned


def test_control_spawned_pool_processes_need_the_variable(tmp_path, monkeypatch):
    """Control: without the variable only the worker's own process refuses, and the
    spawned pool processes verify. This is what the variable is for."""
    proxy, _ = _spawn_pool_run(tmp_path, monkeypatch, refuse_env=False)

    assert any(ISSUER_HOST in line for line in proxy.external_requests()), (
        proxy.requests
    )


ISSUER_HOST = "sts.amazonaws.com"


@pytest.mark.parametrize("verify", [False, True])
def test_the_scanner_starts_the_worker_with_the_refusal_unless_it_may_verify(
    tmp_path, monkeypatch, verify
):
    from automated_security_helper.utils import subprocess_utils
    from automated_security_helper.utils.detect_secrets_worker import REFUSE_HTTP_ENV

    seen = {}

    def record(command, *args, **kwargs):
        seen["env"] = kwargs.get("env")
        return {"returncode": 1, "stdout": "", "stderr": "not run"}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", record)
    scanner = _scanner(tmp_path)
    scanner._secrets_collection.root = str(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(Exception):
        scanner._scan_in_worker(
            baseline=None,
            scan_paths=[],
            scan_settings_dict={"plugins_used": [{"name": "AWSKeyDetector"}]},
            work_dir=work,
            scan_timeout=None,
            verify=verify,
        )

    env = seen["env"] or {}
    assert (env.get(REFUSE_HTTP_ENV) == "1") is (not verify), seen["env"]


def test_importing_the_worker_module_in_ash_refuses_nothing(tmp_path):
    """The variable acts only in the worker's own processes: ASH imports the module
    for its constant, and must keep its own HTTP working whatever its environment."""
    from automated_security_helper.utils.detect_secrets_worker import REFUSE_HTTP_ENV

    probe = (
        "import automated_security_helper.utils.detect_secrets_worker\n"
        "from requests.adapters import HTTPAdapter\n"
        "print(HTTPAdapter.send.__name__)\n"
    )
    result = subprocess.run(  # nosec B603 - fixed argv
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=True,
        cwd=tmp_path,
        env={**os.environ, REFUSE_HTTP_ENV: "1"},
        timeout=CHILD_TIMEOUT_SECONDS,
    )

    assert result.stdout.strip() == "send", result.stdout
