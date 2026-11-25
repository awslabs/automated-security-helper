# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The fixture plugin: the positive control of the plugin conformance tests.

``manifest.MANIFEST`` is its manifest, ``scanner.FixtureScanner`` carries its register
rows, and ``../transcripts`` holds its recorded transcript. It is importable only when a
test puts this directory on ``sys.path``; it is never a registered plugin.
"""
