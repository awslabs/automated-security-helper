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
        from automated_security_helper.reporters.ash_default import (
            AsffReporter,
            CsvReporter,
            CycloneDXReporter,
            HtmlReporter,
            FlatJSONReporter,
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
            "runs[0].tool.driver.rules[0].id": "vulnerabilities[0].cve.uid",
            "runs[0].results[0].message.text": "vulnerabilities[0].desc",
            "runs[0].results[0].ruleId": "vulnerabilities[0].title",
            "runs[0].results[0].level": "severity",
            "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri": "affected_code[0].file.path",
            "runs[0].results[0].locations[0].physicalLocation.region.startLine": "affected_code[0].start_line",
            "runs[0].results[0].locations[0].physicalLocation.region.endLine": "affected_code[0].end_line",
        }

        # ASFF mappings
        mappings["asff"] = {
            "runs[0].results[0].ruleId": "Findings[0].Types[0]",
            "runs[0].results[0].message.text": "Findings[0].Description",
            "runs[0].results[0].level": "Findings[0].Severity.Label",
            "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri": "Findings[0].Resources[0].Details.AwsEc2Instance.Path",
            "runs[0].tool.driver.name": "Findings[0].ProductFields.aws/securityhub/ProductName",
        }

        # CSV mappings
        mappings["csv"] = {
            "runs[0].results[0].ruleId": "Rule ID",
            "runs[0].results[0].message.text": "Description",
            "runs[0].results[0].level": "Severity",
            "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri": "File Path",
            "runs[0].results[0].locations[0].physicalLocation.region.startLine": "Line Start",
            "runs[0].tool.driver.name": "Scanner",
        }

        # Flat JSON mappings
        mappings["flat-json"] = {
            "runs[0].results[0].ruleId": "rule_id",
            "runs[0].results[0].message.text": "description",
            "runs[0].results[0].level": "severity",
            "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri": "file_path",
            "runs[0].results[0].locations[0].physicalLocation.region.startLine": "line_start",
            "runs[0].results[0].locations[0].physicalLocation.region.endLine": "line_end",
            "runs[0].tool.driver.name": "scanner",
        }

        # JUnit XML mappings
        mappings["junitxml"] = {
            "runs[0].results[0].ruleId": "testcase.classname",
            "runs[0].results[0].message.text": "testcase.name",
            "runs[0].results[0].level": "testcase.result.type",
            "runs[0].tool.driver.name": "testsuite.name",
        }

        # Markdown mappings
        mappings["markdown"] = {
            "runs[0].results[0].ruleId": "Finding.title",
            "runs[0].results[0].message.text": "Finding.description",
            "runs[0].results[0].level": "Finding.severity",
            "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri": "Finding.location",
            "runs[0].tool.driver.name": "Finding.scanner",
        }

        # HTML mappings
        mappings["html"] = {
            "runs[0].results[0].ruleId": "table.row.rule",
            "runs[0].results[0].message.text": "table.row.message",
            "runs[0].results[0].level": "table.row.severity",
            "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri": "table.row.location",
            "runs[0].tool.driver.name": "table.section.scanner",
        }

        # Try to get mappings from reporter instances if they have a sarif_field_mappings attribute
        reporters = [
            AsffReporter(),
            CsvReporter(),
            CycloneDXReporter(),
            HtmlReporter(),
            FlatJSONReporter(),
            JunitXmlReporter(),
            MarkdownReporter(),
            OcsfReporter(),
            SarifReporter(),
            SpdxReporter(),
            TextReporter(),
            YamlReporter(),
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
