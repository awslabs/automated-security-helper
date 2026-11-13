# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The detect-secrets worker double, and the route the detect-secrets scenarios build on.

``test_detect_secrets`` pins how ASH launches the detect-secrets worker; the
explicit-executor cells run the same worker against other executors. Both build on
what is here: the source the scenarios scan, the worker double that answers each
request the way the worker would, the scanner's config, and the route that leaves
the worker as the one launch. This module imports nothing from a test file.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, List, Optional

# detect-secrets imports requests, whose urllib3 binds a socket at import time to
# learn whether IPv6 works. The harness allows that probe, and only that one, at
# collection or inside a test (the scanner imports detect-secrets lazily); it is
# imported here, at collection, all the same.
from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class

from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
)
from tests.unit.characterization._harness import (
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
    register_cache_reset,
)

WORKER = "automated_security_helper.utils.detect_secrets_worker"

#: The AWS documentation's example access key id. Not a credential.
MARKER = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret

LOCKFILE = """{
  "lockfileVersion": 3,
  "name": "app",
  "packages": {
    "": {
      "name": "app",
      "version": "1.0.0"
    }
  },
  "requires": true
}
"""

SOURCE = {
    "app.py": f'import boto3\n\nkey = "{MARKER}"\nclient = boto3.client("s3")\n',
    "notes.md": "# Notes\n\nNothing in this file looks like a secret.\n",
    "package-lock.json": LOCKFILE,
}

REQUEST_KEYS = ["baseline", "paths", "root", "settings"]


class WorkerDouble(ToolDouble):
    """``python -m automated_security_helper.utils.detect_secrets_worker REQUEST OUTPUT``.

    Reads the request ASH wrote and refuses one whose shape it does not know. Writes
    OUTPUT as the worker would: the baseline's results, then one ``AWS Access Key``
    secret for each line of a requested file that holds ``MARKER``. A key is the path
    as given for a one-file scan and relative to ``root`` for more, as
    ``SecretsCollection.scan_files`` keys them. Every path is confined to the test's
    tree before it is read or even tested, so a request that names a host file is
    a violation rather than that file's name in a golden.
    """

    def __init__(
        self, outcome: Optional[Outcome] = None, *, writes_output: bool = True
    ) -> None:
        self.outcome = outcome
        self.writes_output = writes_output

    def run(self, call: ToolCall) -> Outcome:
        if len(call.args) != 2:
            raise call.reject("expected REQUEST OUTPUT")
        request_path = call.confined(call.args[0])
        output_path = call.confined(call.args[1])
        if not request_path.is_file():
            raise call.reject(f"request {request_path} is not a file")
        request = json.loads(call.read(request_path).decode("utf-8"))
        if sorted(request) != REQUEST_KEYS:
            raise call.reject(f"request keys {sorted(request)}")
        paths: List[str] = request["paths"]
        for path in paths:
            if not os.path.isabs(path) or not call.confined(path).is_file():
                raise call.reject(f"requested path {path} is not an absolute file")
        if not output_path.parent.is_dir():
            raise call.reject(f"the directory of {output_path} does not exist")
        if self.writes_output:
            collection: List[List[Any]] = []
            baseline = request["baseline"] or {}
            for key, secrets in (baseline.get("results") or {}).items():
                collection.append([key, secrets])
            for path in paths:
                found = [
                    {
                        "type": "AWS Access Key",
                        "filename": path,
                        "hashed_secret": hashlib.sha1(MARKER.encode()).hexdigest(),
                        "is_verified": False,
                        "line_number": number,
                    }
                    for number, line in enumerate(
                        call.read(path).decode("utf-8").splitlines(), 1
                    )
                    if MARKER in line
                ]
                if found:
                    key = (
                        path
                        if len(paths) == 1
                        else os.path.relpath(path, request["root"])
                    )
                    collection.append([key, found])
            call.write(output_path, json.dumps(collection).encode("utf-8"))
        return self.outcome if self.outcome is not None else Exit(0)


@register_cache_reset
def _forget_detect_secrets_plugin_types() -> None:
    """detect-secrets memoizes its secret-type-to-plugin map (an ``lru_cache`` that
    neither ``cache_bust`` nor ASH clears) over the plugins configured on its first
    call, and the scanner reads it. Primed by one test with a custom plugin, it
    would hold 28 plugins for the next. The function is bound at import, so this
    runs even while a test hides detect-secrets from ``sys.modules``."""
    get_mapping_from_secret_type_to_class.cache_clear()


def _config(**options) -> DetectSecretsScannerConfig:
    return DetectSecretsScannerConfig(
        options=DetectSecretsScannerConfigOptions(**options)
    )


def _worker_route(char, worker: Optional[WorkerDouble] = None) -> None:
    """No uv and no CLI: validation probes nothing, and the worker is the one launch."""
    char.absent("uv", "detect-secrets")
    char.tool(WORKER, worker or WorkerDouble(), on=None)
