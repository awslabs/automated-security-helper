# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Second fixture file, so the suite asserts diagnostics land on the right FILE
as well as the right line. With one file, a grouping bug that attributed every
finding to the same document would pass."""

BUCKET_NAME = "example-reports"

PUBLIC_READ = True

RETENTION_DAYS = 0
