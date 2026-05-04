# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib

from automated_security_helper.plugins.events import AshEventType


def _load_module(module_path: str):
    """Import a module by its dotted path and return it."""
    # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
    return importlib.import_module(module_path)


def _load_builtin_plugins():
    """Load all built-in plugin classes lazily via importlib.

    The @ash_scanner_plugin / @ash_converter_plugin / @ash_reporter_plugin
    decorators fire at import time to register each class with the plugin
    manager, so the import itself is sufficient for registration.
    """
    _base = "automated_security_helper.plugin_modules.ash_builtin"

    # -- Converters --
    converters_mod = _load_module(f"{_base}.converters")
    ArchiveConverter = converters_mod.ArchiveConverter
    JupyterConverter = converters_mod.JupyterConverter

    # -- Scanners --
    scanners_mod = _load_module(f"{_base}.scanners")
    BanditScanner = scanners_mod.BanditScanner
    CdkNagScanner = scanners_mod.CdkNagScanner
    CfnNagScanner = scanners_mod.CfnNagScanner
    CheckovScanner = scanners_mod.CheckovScanner
    DetectSecretsScanner = scanners_mod.DetectSecretsScanner
    GrypeScanner = scanners_mod.GrypeScanner
    SyftScanner = scanners_mod.SyftScanner
    OpengrepScanner = scanners_mod.OpengrepScanner

    npm_mod = _load_module(
        f"{_base}.scanners.npm_audit_scanner"
    )
    NpmAuditScanner = npm_mod.NpmAuditScanner

    semgrep_mod = _load_module(
        f"{_base}.scanners.semgrep_scanner"
    )
    SemgrepScanner = semgrep_mod.SemgrepScanner

    # -- Reporters --
    reporters_mod = _load_module(f"{_base}.reporters")
    CsvReporter = reporters_mod.CsvReporter
    CycloneDXReporter = reporters_mod.CycloneDXReporter
    FlatJsonReporter = reporters_mod.FlatJsonReporter
    GitLabSASTReporter = reporters_mod.GitLabSASTReporter
    HtmlReporter = reporters_mod.HtmlReporter
    JunitXmlReporter = reporters_mod.JunitXmlReporter
    MarkdownReporter = reporters_mod.MarkdownReporter
    OcsfReporter = reporters_mod.OcsfReporter
    SarifReporter = reporters_mod.SarifReporter
    SpdxReporter = reporters_mod.SpdxReporter
    TextReporter = reporters_mod.TextReporter
    UnusedSuppressionsReporter = reporters_mod.UnusedSuppressionsReporter
    YamlReporter = reporters_mod.YamlReporter

    # -- Event Handlers --
    event_handlers_mod = _load_module(f"{_base}.event_handlers")
    handle_scan_completion_logging = event_handlers_mod.handle_scan_completion_logging
    handle_suppression_expiration_check = event_handlers_mod.handle_suppression_expiration_check

    return (
        [ArchiveConverter, JupyterConverter],
        [
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
        ],
        [
            CsvReporter,
            CycloneDXReporter,
            FlatJsonReporter,
            GitLabSASTReporter,
            HtmlReporter,
            JunitXmlReporter,
            MarkdownReporter,
            OcsfReporter,
            SarifReporter,
            SpdxReporter,
            TextReporter,
            UnusedSuppressionsReporter,
            YamlReporter,
        ],
        {
            AshEventType.SCAN_COMPLETE: [handle_scan_completion_logging],
            AshEventType.EXECUTION_START: [handle_suppression_expiration_check],
        },
    )


# Lazy-load on first access via load_internal_plugins() in plugins/loader.py.
# The module-level lists below are populated once _load_builtin_plugins runs
# (triggered by `importlib.import_module` in the loader).
_loaded = _load_builtin_plugins()

ASH_CONVERTERS = _loaded[0]
ASH_SCANNERS = _loaded[1]
ASH_REPORTERS = _loaded[2]
ASH_EVENT_HANDLERS = _loaded[3]
