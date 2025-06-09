# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

### Converters ###

from automated_security_helper.plugin_modules.ash_builtin.converters import (
    ArchiveConverter,
    JupyterConverter,
)

### Scanners ###

from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    BanditScanner,
    CdkNagScanner,
    CfnNagScanner,
    CheckovScanner,
    DetectSecretsScanner,
    GrypeScanner,
    SyftScanner,
    OpengrepScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
)

### Reporters ###

from automated_security_helper.plugin_modules.ash_builtin.reporters import (
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

### Event Callbacks ###

from automated_security_helper.plugin_modules.ash_builtin.event_callbacks import (
    handle_scan_completion_logging,
)
from automated_security_helper.plugins.events import AshEventType


### ASH Plugin Discoverability ###

ASH_CONVERTERS = [ArchiveConverter, JupyterConverter]

ASH_SCANNERS = [
    BanditScanner,
    CdkNagScanner,
    CfnNagScanner,
    CheckovScanner,
    DetectSecretsScanner,
    GrypeScanner,
    NpmAuditScanner,
    OpengrepScanner,
    SemgrepScanner,
    SyftScanner,
]

ASH_REPORTERS = [
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

ASH_EVENT_CALLBACKS = {
    AshEventType.SCAN_COMPLETE: [
        handle_scan_completion_logging,
    ],
}
