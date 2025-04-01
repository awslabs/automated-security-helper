from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Annotated, List, Dict, Literal


class ASHConfig(BaseModel):
    """Configuration model for Automated Security Helper."""
    """
    scan_config={
        "rules": ["security", "performance", "style"],
        "ignored_paths": ["tests/", "docs/"],
        "max_line_length": 100,
    }
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="allow",
    )

    ignored_paths: Annotated[
        List[str],
        Field(description="List of paths to ignore. Follows the same syntax as common .ignore files."),
    ] = []

    scanners: Annotated[
        List[
            Literal[
                "bandit",
                "jupyter",
                "cdk_nag",
                "cfn_nag",
                "checkov",
                "grype",
                "npm_audit",
                "semgrep",
                "syft",
            ]
        ],
        Field(
            description="List of scanners to use. Empty includes all scanners (default)."
        ),
    ] = []
    scan_type: Annotated[
        List[Literal["sast", "sbom"]],
        Field(description="Type of security scan to perform"),
    ] = ["sast", "sbom"]
    scan_options: Annotated[
        Dict[str, str], Field(description="Options for the security scan")
    ] = {}
