# Benign test fixture for the facets corpus gate (never executed).
# The construct m0_rule.yaml matches.
import subprocess


def run(cmd: str) -> int:
    return subprocess.call(cmd, shell=True)
