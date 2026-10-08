import re
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


#: A release tag: an optional ``v``, dot-separated numbers, and optional ``-`` or
#: ``.`` separated alphanumeric parts (``v1.15.1``, ``1.2.0-rc1``). Nothing that can
#: change the path of the URL the tag is put into.
_RELEASE_TAG = re.compile(r"v?[0-9]+(\.[0-9]+)*([-.][0-9A-Za-z]+)*")


def release_tag(key: str) -> WrapValidator:
    """Validator for a version that names a release to download, named ``key``.

    The value is put into a download URL (opengrep's ``version``), so only a
    release tag is accepted, from any source. Anything else is replaced by the
    option's default, with one warning naming ``key``.
    """

    def _validate(value: Any, handler: ValidatorFunctionWrapHandler, _info: Any) -> Any:
        value = handler(value)
        if isinstance(value, str) and _RELEASE_TAG.fullmatch(value):
            return value
        _warn_once(
            key,
            str(value),
            f"Ignoring {key}: {value!r} is not a release tag such as 'v1.2.3'. "
            "Using the pinned version instead.",
        )
        raise PydanticUseDefault from None

    return WrapValidator(_validate)


def _warn_once(key: str, value: str, message: str) -> None:
    with _REFUSED_TOOL_VERSIONS_LOCK:
        first = (key, value) not in _REFUSED_TOOL_VERSIONS
        _REFUSED_TOOL_VERSIONS.add((key, value))
    if first:
        from automated_security_helper.utils.log import ASH_LOGGER

        ASH_LOGGER.warning(message)


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
            _warn_once(
                key,
                str(value),
                f"Ignoring {key}: {error}. Using the default constraint instead.",
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
