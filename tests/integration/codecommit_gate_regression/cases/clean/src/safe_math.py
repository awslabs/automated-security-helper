"""Negative control for the ASH pull-request gate.

No subprocess, no shell, no eval, no crypto, no network, no credentials. The
point of this file is that a correct gate reports a passing verdict on it *and*
its scanners actually ran. A passing verdict alone is not evidence: during the
2026-08-28 validation both this file and the positive control were reported as
"passed" because no scanner ran at all. See ../../README.md.

If a future scanner does flag something here, the finding is the scanner's or
the gate's, not this code's — fix the fixture only after ruling those out.
"""


def add(left, right):
    return left + right


def mean(values):
    if not values:
        raise ValueError("mean() requires at least one value")
    return sum(values) / len(values)
