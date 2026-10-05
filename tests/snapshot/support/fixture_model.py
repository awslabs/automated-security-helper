# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The canonical snapshot input: a fixture repository and the model ASH builds from it.

Every snapshot of a reporter, of the aggregated results file and of anything else that
renders a scan result starts here, so that one set of findings and one set of scanner
statuses is what every surface is asserted against.
"""
