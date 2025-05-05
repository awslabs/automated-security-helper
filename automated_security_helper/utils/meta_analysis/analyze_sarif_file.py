from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.meta_analysis import (
    SCANNER_NAME_MAP,
)
from automated_security_helper.utils.meta_analysis.extract_field_paths import (
    extract_field_paths,
)


import json
import os
from typing import Dict, Set, Tuple


def analyze_sarif_file(
    file_path: str, scanner_name: str = None
) -> Tuple[Dict[str, Dict[str, Set[str]]], str]:
    """
    Analyze a SARIF file and extract field paths.

    Args:
        file_path: Path to the SARIF file
        scanner_name: Optional scanner name to use (overrides auto-detection)

    Returns:
        Tuple of (field paths dict, scanner name)
    """
    try:
        with open(file_path, mode="r", encoding="utf-8") as f:
            sarif_data = json.load(f)

        # Extract scanner name from the file if not provided
        detected_scanner = "unknown"
        if (
            sarif_data.get("runs")
            and sarif_data["runs"][0].get("tool")
            and sarif_data["runs"][0]["tool"].get("driver")
        ):
            detected_scanner = sarif_data["runs"][0]["tool"]["driver"].get(
                "name", "unknown"
            )
            # Map scanner name to ASH configuration name if available
            detected_scanner = SCANNER_NAME_MAP.get(detected_scanner, detected_scanner)
        else:
            # Try to infer from filename
            base_name = os.path.basename(file_path)
            if "_" in base_name:
                detected_scanner = base_name.split("_")[0]
                # Map scanner name to ASH configuration name if available
                detected_scanner = SCANNER_NAME_MAP.get(
                    detected_scanner, detected_scanner
                )

        # Use provided scanner name if available, otherwise use detected name
        final_scanner_name = scanner_name if scanner_name else detected_scanner

        # Extract field paths
        field_paths = extract_field_paths(sarif_data)

        # Add scanner name to each field
        for path_info in field_paths.values():
            path_info["scanners"].add(final_scanner_name)

        return field_paths, final_scanner_name

    except Exception as e:
        ASH_LOGGER.error(f"Error processing {file_path}: {e}")
        return {}, "error"
