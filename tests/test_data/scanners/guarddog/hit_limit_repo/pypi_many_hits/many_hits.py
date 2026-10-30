# Inert test fixture for the GuardDog scanner's max_hits option. It is never
# imported or run: the first statement below exits before anything else
# executes, and each base64 payload decodes to a print() call.
#
# GuardDog 3.2.0 stops threat-runtime-obfuscation-base64exec after one hit per
# package root. This file holds three, each with different surrounding lines
# (GuardDog drops a match whose code snippet repeats one it already has), so a
# scan with the limit removed reports three and a default scan reports one.
raise SystemExit("inert test fixture: not an importable module")

import base64


def first():
    exec(base64.b64decode("cHJpbnQoMSk="))


def second():
    exec(base64.b64decode("cHJpbnQoMik="))


def third():
    exec(base64.b64decode("cHJpbnQoMyk="))
