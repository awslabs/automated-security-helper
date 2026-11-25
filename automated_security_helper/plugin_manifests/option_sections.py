# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The typed config sections of the builtin reporters and converters.

Pure data, like the scanner manifests beside it: a scanner's section comes from
its manifest (``ScannerManifest.config_section``); reporters and converters have
no manifest yet, so their sections are declared here as ``(name, section)``
rows, in the order the generated config schema lists them. When reporters and
converters get manifests of their own these rows move into them and this module
goes away.

``name`` is the plugin's selectable name, which is the key of its section in the
config file (``gitlab-sast``); the section's Python field name is the same word
with ``-`` read as ``_``.
"""

from automated_security_helper.base.plugin_manifest import ConfigSection

_REPORTERS = "automated_security_helper.plugin_modules.ash_builtin.reporters"
_CONVERTERS = "automated_security_helper.plugin_modules.ash_builtin.converters"


def _section(package: str, module: str, config_class: str, what: str) -> ConfigSection:
    return ConfigSection(
        model=f"{package}.{module}:{config_class}",
        description=f"Configure the options for {what}",
    )


#: ``(reporter name, section)``, in the order of the config schema.
REPORTER_SECTIONS = (
    (
        "csv",
        _section(_REPORTERS, "csv_reporter", "CSVReporterConfig", "the CSV reporter"),
    ),
    (
        "cyclonedx",
        _section(
            _REPORTERS,
            "cyclonedx_reporter",
            "CycloneDXReporterConfig",
            "the CycloneDX reporter",
        ),
    ),
    (
        "gitlab-cyclonedx",
        _section(
            _REPORTERS,
            "gitlab_cyclonedx_reporter",
            "GitLabCycloneDXReporterConfig",
            "the GitLab CycloneDX dependency scanning reporter",
        ),
    ),
    (
        "html",
        _section(
            _REPORTERS, "html_reporter", "HTMLReporterConfig", "the HTML reporter"
        ),
    ),
    (
        "flat-json",
        _section(
            _REPORTERS,
            "flatjson_reporter",
            "FlatJSONReporterConfig",
            "the Flat JSON reporter",
        ),
    ),
    (
        "gitlab-sast",
        _section(
            _REPORTERS,
            "gitlab_sast_reporter",
            "GitLabSASTReporterConfig",
            "the GitLab SAST reporter",
        ),
    ),
    (
        "github-ghas",
        _section(
            _REPORTERS,
            "github_ghas_reporter",
            "GHASReporterConfig",
            "the GitHub Advanced Security (GHAS) SARIF reporter",
        ),
    ),
    (
        "junitxml",
        _section(
            _REPORTERS,
            "junitxml_reporter",
            "JUnitXMLReporterConfig",
            "the JUnit XML reporter",
        ),
    ),
    (
        "markdown",
        _section(
            _REPORTERS,
            "markdown_reporter",
            "MarkdownReporterConfig",
            "the Markdown reporter",
        ),
    ),
    (
        "asff",
        _section(
            _REPORTERS, "asff_reporter", "AsffReporterConfig", "offline ASFF export"
        ),
    ),
    (
        "ocsf",
        _section(
            _REPORTERS, "ocsf_reporter", "OCSFReporterConfig", "the OCSF reporter"
        ),
    ),
    (
        "sarif",
        _section(
            _REPORTERS, "sarif_reporter", "SARIFReporterConfig", "the SARIF reporter"
        ),
    ),
    (
        "spdx",
        _section(
            _REPORTERS, "spdx_reporter", "SPDXReporterConfig", "the SPDX reporter"
        ),
    ),
    (
        "text",
        _section(
            _REPORTERS, "text_reporter", "TextReporterConfig", "the Text reporter"
        ),
    ),
    (
        "unused-suppressions",
        _section(
            _REPORTERS,
            "unused_suppressions_reporter",
            "UnusedSuppressionsReporterConfig",
            "the Unused Suppressions reporter",
        ),
    ),
    (
        "yaml",
        _section(
            _REPORTERS, "yaml_reporter", "YAMLReporterConfig", "the YAML reporter"
        ),
    ),
)

#: ``(converter name, section)``, in the order of the config schema.
CONVERTER_SECTIONS = (
    (
        "archive",
        _section(
            _CONVERTERS,
            "archive_converter",
            "ArchiveConverterConfig",
            "the ArchiveConverter",
        ),
    ),
    (
        "jupyter",
        _section(
            _CONVERTERS,
            "jupyter_converter",
            "JupyterConverterConfig",
            "the JupyterConverter",
        ),
    ),
    (
        "mcp_config",
        _section(
            _CONVERTERS,
            "mcp_config_converter",
            "McpConfigConverterConfig",
            "the McpConfigConverter",
        ),
    ),
)
