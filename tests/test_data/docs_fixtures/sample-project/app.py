import subprocess

DATABASE_PASSWORD = "correct-horse-battery-staple-1234"


def run(command):
    return subprocess.call(command, shell=True)
