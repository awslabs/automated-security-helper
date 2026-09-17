# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Compatibility spellings kept from the deleted root ``ash`` bash script.

That script parsed its own flag surface and forwarded the rest to the Python
CLI. Two of its spellings had no Python equivalent, so removing the script would
have broken any caller using them. They are accepted here and announce the name
that replaced them.

A warning that only says "deprecated" makes the reader go looking for the
replacement, so each entry maps to the canonical spelling and the message names
it. The mapping is data rather than a string per call site because both ``scan``
and ``build-image`` accept these options, and two hand-written messages drift
apart.
"""

import sys

# Deprecated spelling -> the canonical spelling that replaces it.
DEPRECATED_OPTION_SPELLINGS = {
    "--ash-revision": "--ash-revision-to-install",
    "-rev": "--ash-revision-to-install",
}


def warn_deprecated_option_spellings(argv=None, stream=None):
    """Warn once for each deprecated option spelling present in ``argv``.

    Matched against ``argv`` rather than against the parsed value because click
    reports the value it bound, not the spelling the caller typed, and the whole
    point is to name the spelling back to them.

    Call this from a command body after the ``ctx.invoked_subcommand`` guard, not
    from an option callback. The root callback and the ``scan`` command share one
    function, so during ``ash scan ...`` its parameters are parsed twice and an
    option callback would emit the warning twice.

    Comparison is exact. A substring match would fire on
    ``--ash-revision-to-install`` itself, which is the spelling being
    recommended.
    """
    args = sys.argv[1:] if argv is None else list(argv)
    out = stream if stream is not None else sys.stderr
    warned = set()
    for token in args:
        # Split so `--ash-revision=v1` is recognized as well as `--ash-revision v1`.
        spelling = token.split("=", 1)[0]
        replacement = DEPRECATED_OPTION_SPELLINGS.get(spelling)
        if replacement is not None and spelling not in warned:
            warned.add(spelling)
            print(
                f"warning: '{spelling}' is deprecated and is scheduled for "
                f"removal; use '{replacement}' instead.",
                file=out,
            )
