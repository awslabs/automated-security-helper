import threading
from typing import Annotated, Any, Literal, Set, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidatorFunctionWrapHandler
from pydantic import WrapValidator
from pydantic_core import PydanticUseDefault

from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL

# (key, value) pairs already warned about. A plugin's options are validated several
# times per scan (the config, its dump, each plugin instance), and one refusal
# should produce one warning.
_REFUSED_TOOL_VERSIONS: Set[Tuple[str, str]] = set()
_REFUSED_TOOL_VERSIONS_LOCK = threading.Lock()


def reset_refused_tool_version_warnings() -> None:
    """Forget which refusals were already logged (tests)."""
    with _REFUSED_TOOL_VERSIONS_LOCK:
        _REFUSED_TOOL_VERSIONS.clear()


def tool_version_constraint(key: str) -> WrapValidator:
    """Validator for a plugin's ``tool_version`` option, named ``key`` in warnings.

    The value becomes part of the requirement that uv or pip installs, so only a
    PEP 440 version specifier set is accepted (see
    ``utils/pre_installed_tool.validate_version_constraint``). Anything else is
    replaced by the option's default, with one warning naming ``key``, wherever the
    value came from: a config file, ``--config-overrides`` or Python.
    """

    def _validate(value: Any, handler: ValidatorFunctionWrapHandler, _info: Any) -> Any:
        from automated_security_helper.utils.pre_installed_tool import (
            validate_version_constraint,
        )

        value = handler(value)
        try:
            return validate_version_constraint(value)
        except ValueError as error:
            with _REFUSED_TOOL_VERSIONS_LOCK:
                first = (key, str(value)) not in _REFUSED_TOOL_VERSIONS
                _REFUSED_TOOL_VERSIONS.add((key, str(value)))
            if first:
                from automated_security_helper.utils.log import ASH_LOGGER

                ASH_LOGGER.warning(
                    f"Ignoring {key}: {error}. Using the default constraint instead."
                )
            raise PydanticUseDefault from None

    return WrapValidator(_validate)


class BuilderOptionsBase(BaseModel):
    """Base class for builder options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class PluginOptionsBase(BaseModel):
    """Base class for plugin options."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)


class ConverterOptionsBase(PluginOptionsBase):
    """Base class for converter options."""


class ScannerOptionsBase(PluginOptionsBase):
    """Base class for scanner options."""

    severity_threshold: Annotated[
        Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None,
        Field(
            description=f"Minimum severity level to consider findings as failures. This is a scanner-level override of the default severity-level within ASH of {ASH_DEFAULT_SEVERITY_LEVEL}."
        ),
    ] = None

    # Lives on the base rather than on individual scanners because the hang it
    # prevents is a property of the shared subprocess path, not of any one tool.
    # detect-secrets previously carried its own copy of this option, which is why
    # it was the only scanner that timed out cleanly while the rest could run
    # unbounded. 300 matches the default it chose.
    scan_timeout: Annotated[
        int | None,
        Field(
            description=(
                "Maximum time in seconds to allow this scanner's tool invocation "
                "to run before it is killed. Set to null to leave the scanner "
                "unbounded, which risks a scan that never completes."
            ),
            ge=1,
        ),
    ] = 1800


class ReporterOptionsBase(PluginOptionsBase):
    """Base class for reporter options."""
