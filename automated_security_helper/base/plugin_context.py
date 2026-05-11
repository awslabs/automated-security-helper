"""Module containing the PluginContext class for sharing context between plugins."""

from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
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
    ignore_suppressions: Annotated[
        bool, Field(description="Ignore all suppression rules")
    ] = False

    @field_validator("config")
    def validate_config(cls, value):
        from automated_security_helper.config.ash_config import AshConfig

        if value is None:
            return AshConfig()
        elif not isinstance(value, AshConfig):
            return AshConfig.model_validate(value)
        else:
            return value

    @model_validator(mode="after")
    def _derive_work_dir(self) -> "PluginContext":
        # Guard against re-validation of test mocks / spec'd instances that may
        # not expose ``work_dir`` or ``output_dir`` as real attributes.
        if getattr(self, "work_dir", None) is None:
            output_dir = getattr(self, "output_dir", None)
            if output_dir is not None:
                self.work_dir = Path(output_dir).joinpath(ASH_WORK_DIR_NAME)
        return self


AshPluginManager.model_rebuild()
