"""Models for Software Bill of Materials (SBOM)."""

from __future__ import annotations

import datetime
from typing import Any, List, Optional, Dict, Union
from typing_extensions import Annotated

from .core import ExportFormat
from ..schemas.data_interchange import DataInterchange

from pydantic import BaseModel, Field, ConfigDict, field_validator

__all__ = ["SBOMComponent", "SBOMMetadata", "SBOMReport", "SBOMPackage"]


class SBOMComponent(BaseModel):
    """Represents a software component in the SBOM."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
        extra="forbid",
    )

    name: Annotated[str, Field(..., min_length=1, description="Name of the component")]
    version: Annotated[
        str, Field(min_length=1, description="Version of the component")
    ] = None
    type: Annotated[
        str, Field(description="Type of the component (e.g., npm, pypi)")
    ] = None
    license: Annotated[str, Field(description="License of the component")] = None
    publisher: Annotated[str, Field(description="Publisher of the component")] = None
    metadata: Annotated[
        Dict[str, Any], Field(description="Additional metadata about the component")
    ] = {}
    dependencies: Annotated[
        List["SBOMComponent"],
        Field(default_factory=list, description="List of dependencies"),
    ]

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate component type."""
        valid_types = {"npm", "pypi", "maven", "nuget", "cargo", "composer", "docker"}
        if v.lower() not in valid_types:
            raise ValueError(f"Component type must be one of {sorted(valid_types)}")
        return v.lower()

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        """Validate version format."""
        if not v or not v.strip():
            raise ValueError("Version cannot be empty")
        return v.strip()


class SBOMMetadata(BaseModel):
    """Represents vulnerability correlation information for a component."""

    component: "SBOMComponent" = Field(
        ..., description="The component this metadata refers to"
    )
    known_vulnerabilities: Annotated[
        List[str], Field(description="Known vulnerabilities")
    ] = []
    version_constraints: Annotated[
        Dict[str, str], Field(description="Version constraints")
    ] = {}
    dependency_chain: Annotated[
        List["SBOMComponent"], Field(description="Chain of dependencies")
    ] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)


class SBOMPackage(SBOMComponent):
    """Extended model for SBOM package information."""

    package_dependencies: Annotated[
        List[Dict[str, str]], Field(description="List of package dependencies")
    ] = []
    metadata: Annotated[
        Dict[str, str], Field(description="Additional package metadata")
    ] = {}


class SBOMReport(DataInterchange):
    """Represents an SBOM report containing all components and their metadata."""

    project_name: Annotated[str, Field(None, description="Alias for name")] = None
    version: Annotated[str, Field(..., description="Version of the report")]
    generated_at: Annotated[str, Field()] = datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat(timespec="seconds")
    components: Annotated[List[SBOMComponent], Field(validation_alias="packages")] = []
    packages: Annotated[List[SBOMComponent], Field(None)] = None
    metadata: Annotated[List[SBOMMetadata], Field()] = []
    description: Annotated[Optional[str], Field(None)]

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="allow",
        ser_json_timedelta="iso8601",
        revalidate_instances="always",
        allow_methods=True,
    )

    def export(
        self, format: ExportFormat = ExportFormat.JSON
    ) -> Union[str, Dict[str, Any]]:
        """Export the SBOM report in the specified format."""
        if format == ExportFormat.JSON:
            return self.model_dump_json(indent=2, serialize_as_any=True)
        elif format == ExportFormat.YAML:
            import yaml

            return yaml.dump(self.model_dump())
        elif format == ExportFormat.CSV:
            import csv
            import io

            output = io.StringIO()
            if self.components:
                component_dicts = [comp.model_dump() for comp in self.components]
                writer = csv.DictWriter(output, fieldnames=component_dicts[0].keys())
                writer.writeheader()
                writer.writerows(component_dicts)
            return output.getvalue()
        elif format == ExportFormat.HTML:
            components_html = "\n".join(
                f"<li><strong>{c.name}</strong> (v{c.version}): {c.license}</li>"
                for c in self.components
            )
            return f"""
            <html>
            <body>
                <h1>SBOM Report: {self.name}</h1>
                <h2>Version: {self.version}</h2>
                <p>Generated: {self.generated_at}</p>
                <h3>Components:</h3>
                <ul>{components_html}</ul>
            </body>
            </html>
            """
        elif format == ExportFormat.DICT:
            return self.model_dump()
        elif format == ExportFormat.CYCLONEDX:
            return self.model_dump()
        elif format == ExportFormat.SPDX:
            return self.model_dump()

        raise ValueError(f"Unsupported export format: {format}")

    def get_dependency_tree(self) -> Dict[str, Any]:
        """Generate a tree structure of package dependencies."""

        def build_tree(component: SBOMComponent) -> Dict[str, Any]:
            tree = {
                "name": component.name,
                "version": component.version,
                "dependencies": {},
            }
            for dep in component.dependencies:
                tree["dependencies"][dep.name] = build_tree(dep)
            return tree

        result = {}
        packages = self.packages or []
        for package in packages:
            result[package.name] = build_tree(package)
        return result


# Initialize types at module level
SBOMComponent.model_rebuild()
SBOMMetadata.model_rebuild()
SBOMReport.model_rebuild()
