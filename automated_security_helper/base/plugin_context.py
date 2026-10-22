"""Module containing the PluginContext class for sharing context between plugins."""

import threading
import uuid
import warnings
from pathlib import Path
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)
from pydantic.json_schema import SkipJsonSchema
from typing import Annotated, Any, Dict, Optional, TYPE_CHECKING

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
    # This run's plugin import failures (plugins.loader.PluginLoadRecord),
    # keyed by module path, one entry per real module (keying by the shown
    # form made every env-read entry share the one '<value>' key). The keys
    # reach no surface: the field is excluded from dumps (ScanPhase copies it
    # into metadata.plugin_load_errors, the recorded form, and a configured
    # failure refuses the run before any metadata is written), from repr
    # (which shows excluded fields too), and from the JSON schema, which
    # otherwise described a field no dump emits; the refusal prints shown
    # labels, never keys. On the context because the context is the one
    # object built per run and shared with every phase: a module-global
    # record poisoned every later run in the same interpreter.
    plugin_load_record: Annotated[
        SkipJsonSchema[Dict[str, Any]],
        Field(
            default_factory=dict,
            exclude=True,
            repr=False,
            description="This run's plugin import failures, by module path",
        ),
    ]
    run_id: Annotated[
        Optional[str],
        Field(
            description=(
                "The ID of the scan this context belongs to, under which its scan "
                "set is written to the output directory and read back"
            )
        ),
    ] = None
    workspace_output_dir: Annotated[
        Optional[Path],
        Field(
            description=(
                "In a workspace scan, the workspace's output directory, which holds "
                "this project's output directory and every other project's: ASH's "
                "own output, left out of the scan like the output directory"
            )
        ),
    ] = None

    # Each of these resolves the "AshConfig" forward reference first; see
    # _resolve_forward_refs at the bottom of this module.
    def __init__(self, /, **data: Any) -> None:
        _resolve_forward_refs()
        super().__init__(**data)

    @classmethod
    def model_validate(cls, *args: Any, **kwargs: Any) -> "PluginContext":
        _resolve_forward_refs()
        return super().model_validate(*args, **kwargs)

    @classmethod
    def model_validate_json(cls, *args: Any, **kwargs: Any) -> "PluginContext":
        _resolve_forward_refs()
        return super().model_validate_json(*args, **kwargs)

    @classmethod
    def model_rebuild(cls, *args: Any, **kwargs: Any) -> bool | None:
        _resolve_forward_refs()
        return super().model_rebuild(*args, **kwargs)

    @classmethod
    def model_json_schema(cls, *args: Any, **kwargs: Any) -> dict[str, Any]:
        _resolve_forward_refs()
        return super().model_json_schema(*args, **kwargs)

    # Private, so it is in no schema and no serialized context. See scan_id.
    _scan_id: str = PrivateAttr(default_factory=lambda: uuid.uuid4().hex)

    @property
    def scan_id(self) -> str:
        """A random id for the run this context was built for, fixed for its life.

        For state kept per scan in a process that outlives the scan, such as the
        once-per-scan content database refresh (utils/content_db_refresh.py) in the
        MCP server. Not ``id(self)``: an address is reused once the context is
        freed, so a later scan's context could inherit an earlier scan's state.
        """
        return self._scan_id

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
        if name in ("work_dir", "output_dir", "workspace_output_dir", "config"):
            _record_derived_roots_on_config(self)

    def model_copy(self, *, update: Any = None, deep: bool = False) -> "PluginContext":
        """A copy whose directories are recorded on its configuration too.

        ``model_copy`` runs neither the validators nor ``__setattr__``, the two
        places a built context records its output, work and workspace output
        directories (``_record_derived_roots_on_config``), so a copy that
        moves one of them would leave it unrecorded."""
        copied = super().model_copy(update=update, deep=deep)
        _record_derived_roots_on_config(copied)
        return copied

    # The pydantic mypy plugin types model_construct per model, field by field;
    # this override takes the fields as **values and passes them on unchanged.
    @classmethod
    def model_construct(  # type: ignore[override]
        cls, _fields_set: Optional[set[str]] = None, **values: Any
    ) -> "PluginContext":
        """A context built without validation, its directories recorded on its
        configuration as a validated one's are (``model_construct`` skips the
        validators that record them)."""
        built = super().model_construct(_fields_set, **values)
        _record_derived_roots_on_config(built)
        return built

    @model_validator(mode="after")
    def _guard_output_dir(self) -> "PluginContext":
        # ASH's own writes below the output directory never follow a symlink, with
        # or without a sandbox: the default output directory is inside the
        # scanned tree. See utils/sandbox/fs_guard.py:open_for_write.
        # Registered for as long as this context exists: released when it is
        # collected, or when the scan that made it ends (fs_guard.run_roots), so a
        # process that runs many scans does not keep every output directory it ever
        # had registered.
        output_dir = getattr(self, "output_dir", None)
        if output_dir is not None:
            from automated_security_helper.utils.sandbox.fs_guard import (
                register_writable_root,
                release_with_holder,
            )

            release_with_holder(self, register_writable_root(output_dir))
        return self

    @model_validator(mode="after")
    def _derive_work_dir(self) -> "PluginContext":
        # Guard against re-validation of test mocks / spec'd instances that may
        # not expose ``work_dir`` or ``output_dir`` as real attributes.
        if getattr(self, "work_dir", None) is None:
            output_dir = getattr(self, "output_dir", None)
            if output_dir is not None:
                self.work_dir = Path(output_dir).joinpath(ASH_WORK_DIR_NAME)
        # Last, so the output and work directories are both settled.
        _record_derived_roots_on_config(self)
        return self


def _record_derived_roots_on_config(context: Any) -> None:
    """Record the context's output and work directories on its config.

    ``path_trust.honored_path`` reads them from the config, so a caller that
    passes no ``derived_dirs`` still has the clause run. Called after the
    context is built and again whenever ``output_dir``, ``work_dir``,
    ``workspace_output_dir`` or ``config`` is assigned. The workspace output
    directory is recorded because each workspace project scans with its own
    config: one project's repository config can name a file under another
    project's slice of the workspace output, which is derived from that other
    repository, and when the workspace output sits outside the workspace root
    the tree clause never sees it. A context or config that cannot hold the
    record (a spec'd test double, no config) is left alone.
    """
    from automated_security_helper.config.path_trust import record_derived_roots

    config = getattr(context, "config", None)
    if config is None:
        return
    try:
        record_derived_roots(
            config,
            getattr(context, "output_dir", None),
            getattr(context, "work_dir", None),
            getattr(context, "workspace_output_dir", None),
        )
    except (AttributeError, TypeError, OSError):
        return


# PluginContext.config is annotated "AshConfig" as a string: config.ash_config
# imports this module, so importing it here would be a cycle. The model is
# incomplete until the reference is resolved against the real class. The last lines
# of config/ash_config.py do that when that module is imported, but importing
# models.asharp_model does not import it (that would load every built-in plugin
# group from inside a half-imported module), so a process that has imported the
# models but not the config would fail on its first PluginContext with
# PydanticUserError. So the reference is also resolved
# on first use, the way models/asharp_model.py resolves AshAggregatedResults'; the
# comments there explain the binding into globals() and the lock.
_forward_refs_lock = threading.RLock()
_forward_refs_resolved = False


def _resolve_forward_refs() -> None:
    """Bind AshConfig into this module and rebuild PluginContext on it.

    Cheap to call repeatedly, and a no-op while AshConfig is still unimportable
    (config.ash_config is mid-import and has not defined it yet).
    """
    global _forward_refs_resolved
    if _forward_refs_resolved:
        return

    with _forward_refs_lock:
        if _forward_refs_resolved:
            return
        try:
            from automated_security_helper.config.ash_config import AshConfig
        except ImportError:
            return

        globals()["AshConfig"] = AshConfig
        # The base class's rebuild: PluginContext.model_rebuild would call this
        # function again.
        super(PluginContext, PluginContext).model_rebuild()
        _forward_refs_resolved = True


AshPluginManager.model_rebuild()
