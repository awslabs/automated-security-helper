# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.reporters.ash_default import (
    AsffReporter,
    CloudWatchLogsReporter,
    CsvReporter,
    CycloneDXReporter,
    FlatJsonReporter,
    HtmlReporter,
    JunitXmlReporter,
    MarkdownReporter,
    OcsfReporter,
    SarifReporter,
    SpdxReporter,
    TextReporter,
    YamlReporter,
)

# Make plugins discoverable
ASH_REPORTERS = [
    AsffReporter,
    CloudWatchLogsReporter,
    CsvReporter,
    CycloneDXReporter,
    FlatJsonReporter,
    HtmlReporter,
    JunitXmlReporter,
    MarkdownReporter,
    OcsfReporter,
    SarifReporter,
    SpdxReporter,
    TextReporter,
    YamlReporter,
]
