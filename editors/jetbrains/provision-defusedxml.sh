#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Sourced, not run: puts defusedxml on PYTHONPATH for the Gradle gates that parse XML
# (assert-coverage.py, assert-tests-ran.py). verify-in-container.sh and e2e-real-cli.sh both
# source it, so the pinned URL and digest exist once. Expects HERE to be editors/jetbrains and
# `set -euo pipefail` to be in force in the caller.
#
# assert-coverage.py and assert-tests-ran.py parse XML through defusedxml rather than
# xml.etree, so this container has to supply it. The image is gradle:jdk21, which has python3
# and -- measured, not assumed -- no pip, no ensurepip and no uv. So the wheel is fetched and
# unpacked directly. defusedxml is pure Python (py2.py3-none-any), which makes unpacking the
# wheel the whole install: nothing to compile, no entry points to generate.
#
# Pinned by sha256 rather than by version alone. This is a security scanner's own build, and a
# fetch that trusts whatever the index hands back is the shape of problem this repository
# exists to find.
#
# THIS STEP MUST FAIL THE BUILD IF IT CANNOT COMPLETE, and it does, three ways: `set -euo
# pipefail` is in force from the top of this file, `curl -f` turns an HTTP error into a
# non-zero exit, and `sha256sum -c` exits non-zero on a digest mismatch. Neither gate has a
# fallback to xml.etree either -- both import defusedxml at module scope and stop with a
# diagnostic if it is absent (assert-coverage.py exits 2, "could not run its checks at all";
# assert-tests-ran.py exits 1, the only failure code it defines). Measured in this image with
# nothing provisioned: a HEALTHY test-results fixture exits 1 rather than reporting a count.
#
# That combination is deliberate and is the point of the whole change: a gate that quietly
# degraded to the standard library when the network hiccuped would be strictly worse than the
# B314 suppression it replaced, because it would still print PASSED.
DEFUSEDXML_WHEEL_URL="https://files.pythonhosted.org/packages/07/6c/aa3f2f849e01cb6a001cd8554a88d4c77c5c1a31c95bdf1cf9301e6d9ef4/defusedxml-0.7.1-py2.py3-none-any.whl"
# The digest carries `# pragma: allowlist secret` for the same reason the pinned tool
# digests in automated_security_helper/utils/tool_downloads.py do, and that block states it
# at length: a 64-character hex string is exactly what a high-entropy-string detector is
# built to find, and ASH flagged this line as a CRITICAL secret on the first run after it
# was added -- correctly, by its own heuristic. A published package digest is public by
# construction and is the opposite of a credential; it exists to be compared against.
# Marked on this one line rather than by suppressing the rule or the file, so a real secret
# added to this script later is still found.
DEFUSEDXML_WHEEL_SHA256="a352e7e428770286cc899e2542b6cdaedb2b4953ff269a210103ec58f6198a61"  # pragma: allowlist secret
VENDOR="$HERE/build/python-vendor"
rm -rf "$VENDOR"
mkdir -p "$VENDOR"
curl -fsSL -o "$VENDOR/defusedxml.whl" "$DEFUSEDXML_WHEEL_URL"
echo "$DEFUSEDXML_WHEEL_SHA256  $VENDOR/defusedxml.whl" | sha256sum -c -
# `python3 -m zipfile` rather than `unzip`, which the image does not ship.
python3 -m zipfile -e "$VENDOR/defusedxml.whl" "$VENDOR"
# Exported, so it reaches the gates Gradle runs as well as the ones invoked directly below.
# assertCoverage and assertTestsRan are Gradle Exec tasks whose commandLine starts with
# "python3", and Gradle inherits this environment, so build.gradle.kts needs no change and no
# network access is added inside the Gradle build itself.
export PYTHONPATH="$VENDOR${PYTHONPATH:+:$PYTHONPATH}"
python3 -c 'import defusedxml; print("   defusedxml " + defusedxml.__version__ + " ready at " + defusedxml.__file__)'

