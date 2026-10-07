"""API project of the snapshot workspace fixture. Insecure on purpose."""

import subprocess


def run_report(name):
    return subprocess.run(f"report {name}", shell=True)
