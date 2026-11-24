# Benign test fixture for the facets program's M0 sample runs (never executed).
# Two constructs bandit flags (B602 shell=True, B307 eval), so a captured
# `bandit --format sarif` run shows whether issue_severity (and the snippet)
# appear as structured SARIF fields.
import subprocess


def run(cmd: str) -> int:
    return subprocess.call(cmd, shell=True)


def compute(expr: str):
    return eval(expr)
