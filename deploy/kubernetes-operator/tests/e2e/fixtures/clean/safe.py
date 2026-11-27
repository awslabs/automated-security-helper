"""The negative control.

A scan of this tree must report zero findings and succeed. Without it, the dirty
fixture proves only that the pipeline reports *something* -- not that it reports
findings rather than always reporting them. A pipeline that hard-codes "2
actionable" passes the positive test and fails this one.

No shell=True, no eval, no credentials, no dynamic import.
"""

import shlex
import subprocess


def run_fixed_command(argument: str) -> int:
    return subprocess.call(["/bin/echo", shlex.quote(argument)])


def add(left: int, right: int) -> int:
    return left + right
