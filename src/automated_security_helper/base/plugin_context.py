"""Module containing the PluginContext class for sharing context between plugins."""

from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Annotated, TYPE_CHECKING

from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugins.plugin_manager import AshPluginManager

# Import AshConfig only for type checking to avoid circular imports
if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig


class PluginContext(BaseModel):
    """Context container for plugins to ensure consistent path information."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    source_dir: Annotated[Path, Field(description="Source directory to scan")]
    output_dir: Annotated[
        Path, Field(description="Primary output directory for all ASH results")
    ]
    work_dir: Annotated[
        Path, Field(description="Working directory for temporary files")
    ] = None
    config: Annotated["AshConfig", Field(description="ASH configuration")] = None

    @field_validator("config")
    def validate_config(cls, value):
        from automated_security_helper.config.ash_config import AshConfig

        if value is None:
            return AshConfig()
        elif not isinstance(value, AshConfig):
            return AshConfig.model_validate(value)
        else:
            return value

    def model_post_init(self, context):
        if self.work_dir is None:
            self.work_dir = self.output_dir.joinpath(ASH_WORK_DIR_NAME)
        return super().model_post_init(context)


AshPluginManager.model_rebuild()
