# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The fixture the extension's central assertion is about. It is not a real
# credential: the value below is the example secret access key from AWS's own
# public documentation, and it is the same value packaging/deb/verify-in-container
# .sh and packaging/rpm/verify-in-container.sh plant, so the whole branch plants
# one known secret and one only.
#
# It is planted deliberately, and it is what makes the assertion mean anything. An
# ASH scan that finds nothing exits 0, so "the command ran" and "a SARIF file
# appeared" are both satisfied by a scan that saw nothing. The extension test
# asserts a NON-ZERO count of diagnostics in the editor model against this file.
# Delete the value to quieten a scanner and the assertion becomes vacuous.
#
# test/fixtures/planted-secret.sarif is real `ash scan --scanners detect-secrets`
# output over this file, with the scanning machine's absolute path replaced. Three
# rules fire on the two lines below: SECRET-AWS-ACCESS-KEY on the value,
# SECRET-SECRET-KEYWORD on the name beside it, and
# SECRET-BASE64-HIGH-ENTROPY-STRING on the value again.
#
# .ash/.ash.yaml carries a SECRET-* suppression for this exact path, scoped to the
# path and not to a glob, so ASH's scan of its own repository does not fail on its
# own test fixture.
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
