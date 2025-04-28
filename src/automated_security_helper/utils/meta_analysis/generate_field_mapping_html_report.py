from automated_security_helper.utils.meta_analysis.get_reporter_mappings import (
    get_reporter_mappings,
)


import json
from typing import Any, Dict


def generate_html_report(
    validation_results: Dict,
    output_path: str,
    field_presence: Dict[str, Dict[str, Any]] = None,
) -> None:
    """
    Generate a comprehensive HTML report showing SARIF field analysis and validation results.

    Args:
        validation_results: Validation results dictionary
        output_path: Path to write the HTML report
        field_presence: Optional dictionary with field presence information
    """
    html = []
    html.append("<!DOCTYPE html>")
    html.append("<html>")
    html.append("<head>")
    html.append("  <title>SARIF Field Analysis Report</title>")
    # Add CSS for sortable headers and filtering
    html.append("  <style>")
    html.append("    body { font-family: Arial, sans-serif; margin: 20px; }")
    html.append("    h1, h2, h3 { color: #333; }")
    html.append(
        "    .summary { background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }"
    )
    html.append(
        "    .scanner { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }"
    )
    html.append(
        "    .scanner-header { display: flex; justify-content: space-between; align-items: center; }"
    )
    html.append("    .stats { display: flex; gap: 20px; margin: 10px 0; }")
    html.append(
        "    .stat { background-color: #eee; padding: 10px; border-radius: 3px; }"
    )
    html.append("    .critical { color: #d32f2f; }")
    html.append("    .important { color: #f57c00; }")
    html.append("    .informational { color: #388e3c; }")
    html.append("    .present { color: #388e3c; }")
    html.append("    .missing { color: #d32f2f; }")
    html.append(
        "    .field-table { width: 100%; border-collapse: collapse; margin: 15px 0; }"
    )
    html.append(
        "    .field-table th, .field-table td { padding: 8px; text-align: left; border: 1px solid #ddd; }"
    )
    html.append("    .field-table th { background-color: #f2f2f2; }")
    html.append("    .field-table tr:nth-child(even) { background-color: #f9f9f9; }")
    html.append("    .field-path { font-family: monospace; font-weight: bold; }")
    html.append(
        "    .field-value { font-family: monospace; color: #666; white-space: pre-wrap; }"
    )
    html.append(
        "    .collapsible { cursor: pointer; padding: 10px; background-color: #f1f1f1; }"
    )
    html.append("    .content { display: none; padding: 10px; overflow: hidden; }")
    html.append("    .active { display: block; }")
    html.append(
        "    .tab { overflow: hidden; border: 1px solid #ccc; background-color: #f1f1f1; }"
    )
    html.append(
        "    .tab button { background-color: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 14px 16px; transition: 0.3s; }"
    )
    html.append("    .tab button:hover { background-color: #ddd; }")
    html.append("    .tab button.active { background-color: #ccc; }")
    html.append(
        "    .tabcontent { display: none; padding: 6px 12px; border: 1px solid #ccc; border-top: none; }"
    )
    html.append("    .search-container { margin: 10px 0; }")
    html.append("    #fieldSearch { width: 300px; padding: 8px; margin-right: 10px; }")
    html.append("    .reporter-mapping { margin-top: 5px; color: #0066cc; }")
    # Add styles for sortable headers
    html.append("    .sortable { cursor: pointer; position: relative; }")
    html.append(
        "    .sortable:after { content: '\\25BC'; font-size: 0.7em; position: absolute; right: 5px; opacity: 0.5; }"
    )
    html.append("    .sortable.asc:after { content: '\\25B2'; opacity: 1; }")
    html.append("    .sortable.desc:after { content: '\\25BC'; opacity: 1; }")
    html.append(
        "    .filter-row input { width: 100%; padding: 5px; box-sizing: border-box; margin-bottom: 5px; }"
    )
    html.append("    .jq-query { font-size: 0.8em; margin-top: 5px; color: #666; }")
    html.append(
        "    .jq-query code { background-color: #f5f5f5; padding: 2px 4px; border-radius: 3px; }"
    )
    html.append("  </style>")
    html.append("</head>")
    html.append("<body>")

    # Add title and tabs
    html.append("  <h1>SARIF Field Analysis Report</h1>")

    html.append("  <div class='tab'>")
    html.append(
        "    <button class='tablinks active' onclick='openTab(event, \"FieldAnalysis\")'>Field Analysis</button>"
    )
    html.append(
        "    <button class='tablinks' onclick='openTab(event, \"ValidationResults\")'>Validation Results</button>"
    )
    html.append(
        "    <button class='tablinks' onclick='openTab(event, \"SarifFieldTable\")'>SARIF Field Table</button>"
    )
    html.append("  </div>")

    # Field Analysis Tab
    html.append("  <div id='FieldAnalysis' class='tabcontent' style='display: block;'>")
    html.append("    <h2>Field Analysis by Scanner</h2>")

    # Extract all scanners and fields from validation results
    all_scanners = set()
    all_fields = {}

    for scanner, importance_categories in validation_results["missing_fields"].items():
        all_scanners.add(scanner)
        for importance, fields in importance_categories.items():
            for field_info in fields:
                path = field_info["path"]
                if path not in all_fields:
                    all_fields[path] = {
                        "type": set(),
                        "scanners": set([scanner]),
                        "in_aggregate": False,  # It's missing, so it's not in aggregate
                    }
                else:
                    all_fields[path]["scanners"].add(scanner)

    # Add scanner sections
    for scanner, stats in validation_results["match_statistics"].items():
        html.append("    <div class='scanner'>")
        html.append("      <div class='scanner-header'>")
        html.append(f"        <h3>{scanner}</h3>")
        html.append(
            f"        <div>Match Rate: {stats['matched_results']}/{stats['total_results']} ({stats['field_preservation_rate']:.2%})</div>"
        )
        html.append("      </div>")

        # Add missing fields sections
        for importance in ["critical", "important", "informational"]:
            missing_fields = validation_results["missing_fields"][scanner][importance]
            if missing_fields:
                html.append(
                    f"      <div class='collapsible {importance}'>{importance.capitalize()} Missing Fields ({len(missing_fields)})</div>"
                )
                html.append("      <div class='content'>")
                html.append("        <table class='field-table'>")
                html.append(
                    "          <tr><th>Field Path</th><th>Original Value</th></tr>"
                )

                for field in missing_fields:
                    html.append("          <tr>")
                    html.append(
                        f"            <td class='field-path'>{field['path']}</td>"
                    )
                    html.append(
                        f"            <td class='field-value'>{json.dumps(field['original_value'], indent=2)}</td>"
                    )
                    html.append("          </tr>")

                html.append("        </table>")
                html.append("      </div>")

        html.append("    </div>")

    html.append("  </div>")

    # Validation Results Tab
    html.append("  <div id='ValidationResults' class='tabcontent'>")

    # Add validation summary section
    html.append("    <div class='summary'>")
    html.append("      <h2>Validation Summary</h2>")
    html.append("      <div class='stats'>")
    html.append(
        f"        <div class='stat'>Total Findings: {validation_results['summary']['total_findings']}</div>"
    )
    html.append(
        f"        <div class='stat'>Matched Findings: {validation_results['summary']['matched_findings']} ({validation_results['summary']['matched_findings'] / validation_results['summary']['total_findings']:.2%})</div>"
    )
    html.append("      </div>")
    html.append("      <div class='stats'>")
    html.append(
        f"        <div class='stat critical'>Critical Missing Fields: {validation_results['summary']['critical_missing_fields']}</div>"
    )
    html.append(
        f"        <div class='stat important'>Important Missing Fields: {validation_results['summary']['important_missing_fields']}</div>"
    )
    html.append(
        f"        <div class='stat informational'>Informational Missing Fields: {validation_results['summary']['informational_missing_fields']}</div>"
    )
    html.append("      </div>")
    html.append("    </div>")

    # Add scanner results table
    html.append("    <h2>Scanner Results</h2>")
    html.append("    <table class='field-table'>")
    html.append("      <tr>")
    html.append("        <th>Scanner</th>")
    html.append("        <th>Matched/Total</th>")
    html.append("        <th>Match Rate</th>")
    html.append("        <th>Critical Missing</th>")
    html.append("        <th>Important Missing</th>")
    html.append("        <th>Informational Missing</th>")
    html.append("      </tr>")

    for scanner, stats in validation_results["match_statistics"].items():
        match_rate = stats["field_preservation_rate"] * 100
        html.append("      <tr>")
        html.append(f"        <td>{scanner}</td>")
        html.append(
            f"        <td>{stats['matched_results']}/{stats['total_results']}</td>"
        )
        html.append(f"        <td>{match_rate:.2f}%</td>")
        html.append(
            f"        <td class='critical'>{stats.get('critical_fields_missing', 0)}</td>"
        )
        html.append(
            f"        <td class='important'>{stats.get('important_fields_missing', 0)}</td>"
        )
        html.append(
            f"        <td class='informational'>{stats.get('informational_fields_missing', 0)}</td>"
        )
        html.append("      </tr>")

    html.append("    </table>")
    html.append("  </div>")

    # SARIF Field Table Tab
    html.append("  <div id='SarifFieldTable' class='tabcontent'>")
    html.append("    <h2>SARIF Field Analysis Table</h2>")
    html.append("    <div class='search-container'>")
    html.append(
        "      <input type='text' id='fieldSearch' placeholder='Search for fields...' onkeyup='searchFields()'>"
    )
    html.append("    </div>")
    html.append("    <table class='field-table' id='sarifFieldTable'>")
    html.append("      <thead>")
    html.append("      <tr>")
    html.append("        <th class='sortable'>SARIF Field</th>")
    html.append("        <th class='sortable'>Supporting Scanners</th>")
    html.append("        <th class='sortable'>Field Type</th>")
    html.append("        <th class='sortable'>Aggregated Results Includes?</th>")
    html.append("        <th class='sortable'>Reporter Mappings</th>")
    html.append("      </tr>")
    html.append("      <tr class='filter-row'>")
    html.append("        <td><input type='text' placeholder='Filter by field...'></td>")
    html.append(
        "        <td><input type='text' placeholder='Filter by scanner...'></td>"
    )
    html.append("        <td><input type='text' placeholder='Filter by type...'></td>")
    html.append(
        "        <td><input type='text' placeholder='Filter by presence...'></td>"
    )
    html.append("        <td></td>")
    html.append("      </tr>")
    html.append("      </thead>")
    html.append("      <tbody>")

    # Get reporter mappings
    reporter_mappings = get_reporter_mappings()

    # Collect all fields from all scanners
    all_fields_by_path = {}

    # First, add fields from validation_results
    for scanner, importance_categories in validation_results["missing_fields"].items():
        for importance, fields in importance_categories.items():
            for field_info in fields:
                path = field_info["path"]
                if path not in all_fields_by_path:
                    all_fields_by_path[path] = {
                        "scanners": set([scanner]),
                        "type": set(),
                        "in_aggregate": False,  # It's missing from aggregate
                    }
                else:
                    all_fields_by_path[path]["scanners"].add(scanner)

    # Then, if field_presence is provided, add or update with that information
    if field_presence:
        for path, info in field_presence.items():
            # Ensure scanners is a list, not a string
            scanners = info.get("scanners", [])
            if isinstance(scanners, str):
                scanners = [scanners]

            if path not in all_fields_by_path:
                all_fields_by_path[path] = {
                    "scanners": set(scanners),
                    "type": set(info.get("type", [])),
                    "in_aggregate": info.get("in_aggregate", False),
                    "in_flat": info.get("in_flat", {}),
                    "reporter_mappings": info.get("reporter_mappings", {}),
                }
            else:
                # Update existing entry with more accurate information
                # Make sure to properly merge scanner lists
                all_fields_by_path[path]["scanners"].update(set(scanners))
                all_fields_by_path[path]["type"].update(set(info.get("type", [])))
                all_fields_by_path[path]["in_aggregate"] = info.get(
                    "in_aggregate", all_fields_by_path[path].get("in_aggregate", False)
                )
                all_fields_by_path[path]["in_flat"] = info.get(
                    "in_flat", all_fields_by_path[path].get("in_flat", {})
                )
                all_fields_by_path[path]["reporter_mappings"] = info.get(
                    "reporter_mappings",
                    all_fields_by_path[path].get("reporter_mappings", {}),
                )

    # Sort fields by path for better readability
    for path in sorted(all_fields_by_path.keys()):
        info = all_fields_by_path[path]
        scanners_list = ", ".join(sorted(info["scanners"]))

        # Determine field type - use a default if not available
        field_type = "unknown"
        if info["type"]:
            field_type = ", ".join(sorted(info["type"]))

        # Check for reporter mappings
        mappings_html = ""
        for reporter, mappings in reporter_mappings.items():
            if path in mappings:
                mappings_html += (
                    f"<div class='reporter-mapping'>{reporter}: {mappings[path]}</div>"
                )

        # Generate JQ query for this field
        from automated_security_helper.utils.meta_analysis.generate_jq_query import (
            generate_jq_query,
        )

        jq_query = generate_jq_query(path)

        # Find an example file that contains this field
        example_file = ".ash/ash_output/reports/ash.sarif"  # Default to aggregated file

        # If we have scanner information, use it to provide a more specific path
        if info["scanners"]:
            for scanner in info["scanners"]:
                if scanner != "ash-aggregated":  # Prefer original scanner files
                    # Use the correct path structure
                    example_file = f".ash/ash_output/scanners/{scanner}/**/*.sarif"
                    break

        # For fields that are only in the aggregated report
        if len(info["scanners"]) == 1 and "ash-aggregated" in info["scanners"]:
            example_file = ".ash/ash_output/reports/ash.sarif"

        jq_command = f"jq '{jq_query}' {example_file}"

        # Add row to table
        html.append("      <tr>")
        html.append(
            f"        <td class='field-path'>{path}<div class='jq-query'><code>{jq_command}</code></div></td>"
        )
        html.append(f"        <td>{scanners_list}</td>")
        html.append(f"        <td>{field_type}</td>")

        # In Aggregate column with proper styling
        in_agg_class = "present" if info.get("in_aggregate", False) else "missing"
        in_agg_text = "Yes" if info.get("in_aggregate", False) else "No"
        html.append(f"        <td class='{in_agg_class}'>{in_agg_text}</td>")

        # Reporter Mappings column
        mappings_html = ""

        # First, check for explicit reporter mappings in the field info
        if info.get("reporter_mappings"):
            for reporter, target_path in info["reporter_mappings"].items():
                mappings_html += (
                    f"<div class='reporter-mapping'>{reporter}: {target_path}</div>"
                )

        # Then check the global reporter mappings
        else:
            for reporter, mappings in reporter_mappings.items():
                if path in mappings:
                    mappings_html += f"<div class='reporter-mapping'>{reporter}: {mappings[path]}</div>"

        # Add flat report presence indicators if available
        if info.get("in_flat"):
            for report_type, present in info["in_flat"].items():
                presence_class = "present" if present else "missing"
                presence_text = "✓" if present else "✗"
                mappings_html += f"<div class='{presence_class}'>In {report_type}: {presence_text}</div>"

        html.append(f"        <td>{mappings_html}</td>")
        html.append("      </tr>")

    html.append("      </tbody>")
    html.append("    </table>")
    html.append("  </div>")

    # Add JavaScript for collapsible sections, tabs, and search
    html.append("  <script>")
    html.append("    // Collapsible sections")
    html.append("    var coll = document.getElementsByClassName('collapsible');")
    html.append("    for (var i = 0; i < coll.length; i++) {")
    html.append("      coll[i].addEventListener('click', function() {")
    html.append("        this.classList.toggle('active');")
    html.append("        var content = this.nextElementSibling;")
    html.append("        if (content.style.display === 'block') {")
    html.append("          content.style.display = 'none';")
    html.append("        } else {")
    html.append("          content.style.display = 'block';")
    html.append("        }")
    html.append("      });")
    html.append("    }")

    html.append("    // Tab functionality")
    html.append("    function openTab(evt, tabName) {")
    html.append("      var i, tabcontent, tablinks;")
    html.append("      tabcontent = document.getElementsByClassName('tabcontent');")
    html.append("      for (i = 0; i < tabcontent.length; i++) {")
    html.append("        tabcontent[i].style.display = 'none';")
    html.append("      }")
    html.append("      tablinks = document.getElementsByClassName('tablinks');")
    html.append("      for (i = 0; i < tablinks.length; i++) {")
    html.append(
        "        tablinks[i].className = tablinks[i].className.replace(' active', '');"
    )
    html.append("      }")
    html.append("      document.getElementById(tabName).style.display = 'block';")
    html.append("      evt.currentTarget.className += ' active';")
    html.append("    }")

    html.append("    // Search functionality")
    html.append("    function searchFields() {")
    html.append("      var input, filter, table, tr, td, i, txtValue;")
    html.append("      input = document.getElementById('fieldSearch');")
    html.append("      filter = input.value.toUpperCase();")
    html.append("      table = document.getElementById('sarifFieldTable');")
    html.append("      tr = table.getElementsByTagName('tr');")
    html.append(
        "      for (i = 2; i < tr.length; i++) {"
    )  # Start at 2 to skip header rows
    html.append(
        "        td = tr[i].getElementsByTagName('td')[0];"
    )  # Field path column
    html.append("        if (td) {")
    html.append("          txtValue = td.textContent || td.innerText;")
    html.append("          if (txtValue.toUpperCase().indexOf(filter) > -1) {")
    html.append("            tr[i].style.display = '';")
    html.append("          } else {")
    html.append("            tr[i].style.display = 'none';")
    html.append("          }")
    html.append("        }")
    html.append("      }")
    html.append("    }")

    # Add sorting functionality
    html.append("    // Sorting function")
    html.append("    function sortTable(table, column, asc = true) {")
    html.append("      const dirModifier = asc ? 1 : -1;")
    html.append("      const tBody = table.tBodies[0];")
    html.append("      const rows = Array.from(tBody.querySelectorAll('tr'));")
    html.append("      ")
    html.append("      // Sort each row")
    html.append("      const sortedRows = rows.sort((a, b) => {")
    html.append(
        "        const aColText = a.querySelector(`td:nth-child(${column + 1})`).textContent.trim();"
    )
    html.append(
        "        const bColText = b.querySelector(`td:nth-child(${column + 1})`).textContent.trim();"
    )
    html.append("        ")
    html.append(
        "        return aColText > bColText ? (1 * dirModifier) : (-1 * dirModifier);"
    )
    html.append("      });")
    html.append("      ")
    html.append("      // Remove all existing TRs from the table")
    html.append("      while (tBody.firstChild) {")
    html.append("        tBody.removeChild(tBody.firstChild);")
    html.append("      }")
    html.append("      ")
    html.append("      // Re-add the newly sorted rows")
    html.append("      tBody.append(...sortedRows);")
    html.append("      ")
    html.append("      // Remember how the column is currently sorted")
    html.append(
        "      table.querySelectorAll('th').forEach(th => th.classList.remove('asc', 'desc'));"
    )
    html.append(
        "      table.querySelector(`th:nth-child(${column + 1})`).classList.toggle('asc', asc);"
    )
    html.append(
        "      table.querySelector(`th:nth-child(${column + 1})`).classList.toggle('desc', !asc);"
    )
    html.append("    }")

    # Add event listeners for sorting and filtering
    html.append("    // Add event listeners when the page loads")
    html.append("    document.addEventListener('DOMContentLoaded', function() {")
    html.append("      const table = document.getElementById('sarifFieldTable');")
    html.append("      const headers = table.querySelectorAll('th.sortable');")
    html.append("      ")
    html.append("      headers.forEach((header, index) => {")
    html.append("        header.addEventListener('click', () => {")
    html.append("          const isAscending = header.classList.contains('asc');")
    html.append("          sortTable(table, index, !isAscending);")
    html.append("        });")
    html.append("      });")
    html.append("      ")
    html.append("      // Add filtering functionality")
    html.append(
        "      const filterInputs = document.querySelectorAll('.filter-row input');"
    )
    html.append("      filterInputs.forEach((input, index) => {")
    html.append("        input.addEventListener('keyup', function() {")
    html.append("          const filterValue = input.value.toUpperCase();")
    html.append("          const rows = table.querySelectorAll('tbody tr');")
    html.append("          ")
    html.append("          rows.forEach(row => {")
    html.append(
        "            const cell = row.querySelector(`td:nth-child(${index + 1})`);"
    )
    html.append("            if (cell) {")
    html.append("              const text = cell.textContent || cell.innerText;")
    html.append("              if (text.toUpperCase().indexOf(filterValue) > -1) {")
    html.append("                row.style.display = '';")
    html.append("              } else {")
    html.append("                row.style.display = 'none';")
    html.append("              }")
    html.append("            }")
    html.append("          });")
    html.append("        });")
    html.append("      });")
    html.append("    });")
    html.append("  </script>")

    html.append("</body>")
    html.append("</html>")

    # Write the HTML file
    with open(output_path, "w") as f:
        f.write("\n".join(html))
