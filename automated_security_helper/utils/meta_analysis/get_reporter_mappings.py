from typing import Dict


def get_reporter_mappings() -> Dict[str, Dict[str, str]]:
    """
    Get field mappings from registered reporters.

    This function collects SARIF field mappings from all registered reporter plugins.
    Each reporter can define how it maps SARIF fields to its own output format.

    Returns:
        Dictionary mapping reporter names to their field mappings
    """
    mappings = {}

    # Try to import reporter plugins dynamically
    try:
        from automated_security_helper.plugin_modules.ash_builtin.reporters import (
            CsvReporter,
            CycloneDXReporter,
            HtmlReporter,
            FlatJsonReporter,
            JunitXmlReporter,
            MarkdownReporter,
            OcsfReporter,
            SarifReporter,
            SpdxReporter,
            TextReporter,
            YamlReporter,
        )

        # Define mappings for each reporter
        # OCSF mappings
        mappings["ocsf"] = {
            "runs[].tool.driver.rules[].id": "vulnerabilities[].cve.uid",
            "runs[].results[].message.text": "vulnerabilities[].desc",
            "runs[].results[].ruleId": "vulnerabilities[].title",
            "runs[].results[].level": "severity",
            "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "affected_code[].file.path",
            "runs[].results[].locations[].physicalLocation.region.startLine": "affected_code[].start_line",
            "runs[].results[].locations[].physicalLocation.region.endLine": "affected_code[].end_line",
        }

        # ASFF mappings
        mappings["asff"] = {
            "runs[].results[].ruleId": "Findings[].Types[]",
            "runs[].results[].message.text": "Findings[].Description",
            "runs[].results[].level": "Findings[].Severity.Label",
            "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "Findings[].Resources[].Details.AwsEc2Instance.Path",
            "runs[].tool.driver.name": "Findings[].ProductFields.aws/securityhub/ProductName",
        }

        # CSV mappings
        mappings["csv"] = {
            "runs[].results[].ruleId": "Rule ID",
            "runs[].results[].message.text": "Description",
            "runs[].results[].level": "Severity",
            "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "File Path",
            "runs[].results[].locations[].physicalLocation.region.startLine": "Line Start",
            "runs[].tool.driver.name": "Scanner",
        }

        # Flat JSON mappings
        mappings["flat-json"] = {
            "runs[].results[].ruleId": "rule_id",
            "runs[].results[].message.text": "description",
            "runs[].results[].level": "severity",
            "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "file_path",
            "runs[].results[].locations[].physicalLocation.region.startLine": "line_start",
            "runs[].results[].locations[].physicalLocation.region.endLine": "line_end",
            "runs[].tool.driver.name": "scanner",
        }

        # JUnit XML mappings
        mappings["junitxml"] = {
            "runs[].results[].ruleId": "testcase.classname",
            "runs[].results[].message.text": "testcase.name",
            "runs[].results[].level": "testcase.result.type",
            "runs[].tool.driver.name": "testsuite.name",
        }

        # Markdown mappings
        mappings["markdown"] = {
            "runs[].results[].ruleId": "Finding.title",
            "runs[].results[].message.text": "Finding.description",
            "runs[].results[].level": "Finding.severity",
            "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "Finding.location",
            "runs[].tool.driver.name": "Finding.scanner",
        }

        # HTML mappings
        mappings["html"] = {
            "runs[].results[].ruleId": "table.row.rule",
            "runs[].results[].message.text": "table.row.message",
            "runs[].results[].level": "table.row.severity",
            "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "table.row.location",
            "runs[].tool.driver.name": "table.section.scanner",
        }

        # Try to get mappings from reporter instances if they have a sarif_field_mappings attribute
        reporters = [
            CsvReporter,
            CycloneDXReporter,
            HtmlReporter,
            FlatJsonReporter,
            JunitXmlReporter,
            MarkdownReporter,
            OcsfReporter,
            SarifReporter,
            SpdxReporter,
            TextReporter,
            YamlReporter,
        ]

        for reporter in reporters:
            if hasattr(reporter, "sarif_field_mappings") and callable(
                getattr(reporter, "sarif_field_mappings")
            ):
                reporter_name = reporter.__class__.__name__.replace(
                    "Reporter", ""
                ).lower()
                reporter_mappings = reporter.sarif_field_mappings()
                if reporter_mappings:
                    mappings[reporter_name] = reporter_mappings

    except ImportError:
        # If we can't import reporters, just use the static mappings defined above
        pass

    return mappings
