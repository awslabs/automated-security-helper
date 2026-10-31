# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A helper the reporter tests share: grade by the global threshold alone."""


def without_scanner_thresholds(model):
    """Clear every scanner's own ``options.severity_threshold`` in *model*.

    The reporters grade a finding by its scanner's own threshold ahead of the
    global one, and ``get_default_config`` honours the ``ASH_CONFIG``
    environment variable, so a configuration that sets one for bandit or
    cdk-nag would silently override every entry of a matrix that names the
    global threshold, and the tests would no longer measure it. A test that
    wants one scanner's threshold sets it after this.

    It walks the scanners the model holds, declared or not, and fails when it
    cleared none, or when any scanner still holds a threshold afterwards: a
    change to the scanners model's shape would otherwise leave the helper
    clearing nothing, and every test above it graded by whatever the
    environment set.
    """
    scanners = model.ash_config.scanners
    cleared = 0
    for _name, scanner in scanners:
        options = getattr(scanner, "options", None)
        if options is not None and hasattr(options, "severity_threshold"):
            options.severity_threshold = None
            cleared += 1
    assert cleared, (
        "no scanner's threshold was cleared; the scanners model changed shape"
    )
    left = [
        name
        for name, scanner in scanners
        if getattr(getattr(scanner, "options", None), "severity_threshold", None)
        is not None
    ]
    assert not left, f"these scanners still hold a threshold: {left}"
    assert scanners.bandit.options.severity_threshold is None, (
        "bandit's own threshold is still set; the scanners model changed shape"
    )
    return model
