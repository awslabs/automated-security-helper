# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A malicious scanner that reaches for macOS session services through Mach lookups.

Run by the sandbox-escape fixture scanner in place of escape_probe.py (the spec's
``probe`` names this file), so it is spawned through the same choke point as a real
scanner. Each attempt records "succeeded" or "blocked: <why>" in the outcome file.

Both attempts run a system tool, so a failure to start the tool (PermissionError on
exec) is reported as it is, and a test can tell "the sandbox stopped the tool from
running" apart from "the tool ran and the service refused it".

- ``launch_services``: ``open -a TextEdit``. LaunchServices asks launchd to start the
  app, and launchd starts it outside the sandbox. With ``open`` able to reach
  LaunchServices, a sandboxed process can run code that is not sandboxed (a
  ``.command`` file opened in Terminal, for example).
- ``pasteboard_read``: ``pbpaste``. The test puts a canary on the pasteboard first, so
  the attempt succeeds only if the canary comes back, not merely if pbpaste exits 0.

Standard library only, because it runs with whatever the sandbox lets it see.
"""

import json
import subprocess
import sys


def attempt(fn):
    try:
        fn()
        return "succeeded"
    except BaseException as e:  # noqa: BLE001 - every failure is an outcome here
        return f"blocked: {type(e).__name__}: {e}"


def _last_line(data: bytes) -> str:
    lines = data.decode("utf-8", errors="replace").strip().splitlines()
    return lines[-1] if lines else "no output"


def main() -> int:
    spec = json.loads(sys.argv[1])

    def launch_services():
        # -g and -j: start it in the background and hidden. The request goes through
        # LaunchServices exactly as a plain `open -a TextEdit` does.
        result = subprocess.run(  # nosec B603 - fixed argv
            ["/usr/bin/open", "-g", "-j", "-a", "TextEdit"],
            capture_output=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"open exited {result.returncode}: {_last_line(result.stderr)}"
            )

    def pasteboard_read():
        result = subprocess.run(  # nosec B603 - fixed argv
            ["/usr/bin/pbpaste"], capture_output=True, timeout=30, check=False
        )
        if spec["secret"].encode() not in result.stdout:
            raise RuntimeError(
                "pbpaste did not return the pasteboard "
                f"(exit {result.returncode}: {_last_line(result.stderr)})"
            )

    checks = {
        "launch_services": launch_services,
        "pasteboard_read": pasteboard_read,
    }
    outcomes = {
        name: attempt(fn)
        for name, fn in checks.items()
        if name in spec.get("checks", list(checks))
    }
    with open(spec["outcome"], "w", encoding="utf-8") as f:
        json.dump(outcomes, f, indent=2)
    print("macOS services probe finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
