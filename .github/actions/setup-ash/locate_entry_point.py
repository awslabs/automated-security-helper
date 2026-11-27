# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Find the `ashx` entry point `pip install .` just wrote, and check PATH reaches it.

Run by setup-ash after the install. Callers of setup-ash run `ashx` by name, so the
action's contract is that `ashx` on PATH is the one just installed. setup-ash used
to try to provide that with a GITHUB_PATH write, which added a directory that
never held the entry point. This checks the contract instead of assuming it, and
writes the directory to GITHUB_OUTPUT as `scripts-dir` for a caller that wants an
absolute path.

The candidates are asked of this interpreter, not hardcoded: pip writes console
scripts to the interpreter's own scheme when its directory is writable and to the
user scheme when it is not. Exits 1 with an ::error:: annotation when neither holds
the entry point, or when PATH resolves `ashx` to some other file.

The name checked is v4's canonical command, CLI_NAME below. The deprecated `ash`
alias is not the contract: on Windows, Git for Windows and MSYS2 ship an Almquist
shell named `ash`, which is one of the reasons v4 renamed the command. This file
runs from the checkout before the package is importable, so the name is written
here and tests/unit/test_setup_ash_entry_point.py holds it equal to
CANONICAL_CLI_NAME and scripts/e2e/cli_name.json.
"""

from __future__ import annotations

import os
import shutil
import sys
import sysconfig

CLI_NAME = "ashx"


def candidate_dirs() -> list[str]:
    dirs = [sysconfig.get_path("scripts")]
    dirs.append(
        sysconfig.get_path("scripts", scheme=sysconfig.get_preferred_scheme("user"))
    )
    return list(dict.fromkeys(d for d in dirs if d))


def main() -> int:
    exe = f"{CLI_NAME}.exe" if os.name == "nt" else CLI_NAME
    candidates = candidate_dirs()
    found = [d for d in candidates if os.path.isfile(os.path.join(d, exe))]
    if not found:
        print(
            f"::error::'pip install .' left no {exe} in any Python scripts directory. "
            f"Looked in: {' ; '.join(candidates)}"
        )
        return 1
    installed = os.path.join(found[0], exe)
    resolved = shutil.which(CLI_NAME)
    if resolved is None or not os.path.samefile(resolved, installed):
        where = resolved if resolved is not None else "nothing"
        print(
            f"::error::ASH was installed to {installed}, but '{CLI_NAME}' on PATH "
            f"resolves to {where}. Callers of setup-ash run '{CLI_NAME}' by name, so "
            "they would get that one or none."
        )
        return 1
    print(f"{CLI_NAME} resolves to {resolved}")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"scripts-dir={found[0]}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
