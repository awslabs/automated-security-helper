"""Module containing the PluginContext class for sharing context between plugins."""

from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, Optional


class PluginContext(BaseModel):
    """Context container for plugins to ensure consistent path information."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    source_dir: Annotated[Path, Field(description="Source directory to scan")]
    output_dir: Annotated[Path, Field(description="Output directory for results")]
    work_dir: Annotated[
        Path, Field(description="Working directory for temporary files")
    ] = None

    def __init__(
        self,
        source_dir: Path,
        output_dir: Path,
        work_dir: Optional[Path] = None,
        **data,
    ):
        """Initialize the plugin context with required paths.

        Args:
            source_dir: Source directory to scan
            output_dir: Output directory for results
            work_dir: Working directory for temporary files (defaults to output_dir/converted)
        """
        if work_dir is None:
            work_dir = output_dir.joinpath("converted")

        super().__init__(
            source_dir=source_dir, output_dir=output_dir, work_dir=work_dir, **data
        )
