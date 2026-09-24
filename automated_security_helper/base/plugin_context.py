"""Module containing the PluginContext class for sharing context between plugins."""

import warnings
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing import Annotated, Any, TYPE_CHECKING

from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugins.plugin_manager import AshPluginManager

# Import AshConfig only for type checking to avoid circular imports
if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig


def _repoints(current: Any, value: Any) -> bool:
    """Whether assigning ``value`` over ``current`` moves the directory.

    Compared as paths rather than by ``!=`` because an assignment may spell the
    current value as a ``str`` while the stored value is a ``Path``, and those never
    compare equal; a plugin writing the same directory back would otherwise look
    like a move.
    """
    try:
        return Path(current) != Path(value)
    except TypeError:
        return True


# One PluginContext is built per run and handed to every converter, scanner and
# reporter, so an attribute assignment made by any one of them is seen by all the
# others. Both shipped example plugins used to repoint work_dir in model_post_init,
# which moved where the rest of the run looked for converted files;
# _derive_work_dir cannot restore it, because it is guarded on work_dir being None
# and so is a no-op once a value is present. Hence the __setattr__ below, which makes
# a repoint of work_dir visible.
#
# frozen=True is the end state and is not what this does: it would break every
# third-party plugin that mutates the context at the moment of upgrade, with no
# release in which the breakage is a warning first.
#
# validate_assignment was the other half of the gentler path and is deliberately NOT
# set, having been tried and reverted. Two of this model's fields declare a
# non-optional type and default to None -- work_dir: Path = None and
# config: "AshConfig" = None -- which pydantic tolerates only because defaults are
# not validated. Turning validate_assignment on makes those declarations
# enforceable, and `context.config = None` then raises instead of reaching
# validate_config below. That is a real caller and not only a test:
# ScanExecutionEngine.ensure_initialized assigns a possibly-non-AshConfig to
# _context.config and relies on its own isinstance check to produce the error,
# which pydantic would pre-empt with a different one. Making the two annotations
# honest is the prerequisite, and it is a wider change than this guard.
#
# All of the above is kept out of the class docstring deliberately: pydantic copies
# __doc__ into the generated schema description, and the committed AshConfig.json
# would then carry a paragraph about a deprecation cycle that goes stale when the
# cycle ends.
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

    def __setattr__(self, name: str, value: Any) -> None:
        """Make a repoint of ``work_dir`` visible instead of silent.

        Scoped to ``work_dir`` rather than to every path field. ASH's own setup
        assigns ``source_dir`` after construction, before any plugin exists, and a
        warning that fires on every run is one operators learn to ignore -- which
        would cost this guard the only thing it is for.

        Warns rather than refuses, and only on a change: ``_derive_work_dir``
        assigns ``work_dir`` itself on every context built without one, which is
        every context ASH builds.
        """
        if name == "work_dir":
            current = getattr(self, name, None)
            if current is not None and _repoints(current, value):
                warnings.warn(
                    f"Assigning to PluginContext.work_dir replaces {Path(current).as_posix()} "
                    f"with {Path(value).as_posix()} for every plugin in this run, not "
                    f"just for the one making the assignment. A plugin that needs its "
                    f"own directory should read the results_dir its base class derives "
                    f"under the shared work_dir. This assignment is deprecated and "
                    f"will be refused in a future release.",
                    DeprecationWarning,
                    stacklevel=2,
                )
        super().__setattr__(name, value)

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
