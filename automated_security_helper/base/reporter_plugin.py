"""Module containing the ReporterPlugin base class.

Workspace mode, and why a reporter has to declare what it does
--------------------------------------------------------------
A workspace scan produces one SARIF run per project, all in one
``AshAggregatedResults``. That shape is new: every reporter in this repository
was written when there was exactly one run, and several of them read
``runs[0]`` and stop. ``github_ghas_reporter`` is the clearest case -- against an
N-run model it emits the first project's findings and drops the rest, with no
error, no warning, and a smaller output file that looks entirely plausible. A
security reporter that under-reports in silence is the worst outcome workspace
mode can have, and it is why no workspace-level report was emitted at all before
this contract existed.

The fix is not to make every reporter merge. Merging is genuinely wrong for
some: an SBOM for N independently versioned deliverables is N SBOMs, and a
reporter that publishes to a shared destination would double-publish. So instead
each reporter *states* what it does with an N-project model, via
:class:`ReporterWorkspaceBehaviour`, and
``automated_security_helper.workspace.reporting`` holds it to that statement.

The default is ``PER_PROJECT``, deliberately
--------------------------------------------
An undeclared reporter -- a third-party plugin, or a new built-in whose author
did not think about workspaces -- gets ``PER_PROJECT``. That is the fail-closed
choice and it is not a refusal: the reporter's per-project artefacts under
``projects/<key>/reports/`` are still produced and still correct, because each
project is scanned as a complete single-project run. All the default withholds
is a workspace-level file the reporter has not said it can produce correctly,
and the driver writes a manifest recording that withholding, so nothing is
silent.

``MERGED`` was rejected as the default because it is fail-open: it hands an
unprepared reporter a shape it has never seen and trusts it. ``UNSUPPORTED`` was
rejected because it would fail an entire workspace run for any external plugin.
"""

import os
import threading
from abc import abstractmethod
from collections.abc import Iterator
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Collection,
    Generic,
    Iterable,
    Optional,
    Set,
    Tuple,
    TypeVar,
    cast,
)
from typing_extensions import Self

from pydantic import (
    Field,
    ValidationError,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticUseDefault

from automated_security_helper.base.options import ReporterOptionsBase, _warn_once
from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_config import (
    PluginConfigBase,
    config_validated_by_declared_model,
    plugin_config_key,
)
from automated_security_helper.base.plugin_config import (
    declared_config_model as plugin_declared_config_model,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP


class ReporterWorkspaceBehaviour(str, Enum):
    """What a reporter does when the model covers more than one project.

    A ``str`` Enum so a declaration reads as its own documentation in a log line
    and in the workspace report manifest, without a lookup table.

    The four members are exhaustive over the useful answers, and each is a
    different claim about *why*:

    ``MERGED``
        One workspace-level artefact covering every project, with the project
        carried inside it -- a column, a field, a section, or a SARIF run. The
        reporter has been shown to handle N runs.

    ``PER_PROJECT``
        No workspace-level artefact. The per-project files the projects' own
        report phases already wrote are the answer. Chosen when merging would be
        wrong rather than merely unimplemented: the consumer ingests against a
        single repository root, or the artefact is an independently versioned
        deliverable, or the reporter publishes a side effect that a second
        invocation would duplicate.

    ``WORKSPACE_SCOPED``
        A workspace-level artefact that is *not* a merge -- it reports on
        workspace-level state only. Distinct from ``MERGED`` because a consumer
        must not read it as covering the projects. ``unused_suppressions`` is the
        only one: merged, it would read the unified file's empty
        ``used_suppressions`` and declare every suppression unused, which is a
        false report rather than an incomplete one.

    ``UNSUPPORTED``
        The reporter refuses to run at workspace level, and the refusal fails the
        run. Reserved for a reporter that can produce neither a correct merged
        artefact nor a meaningful per-project one; no reporter shipped in this
        repository is in that position today. It exists because "silently emit
        nothing" is the defect this whole contract prevents, so a reporter that
        genuinely cannot participate needs a way to say so loudly.
    """

    MERGED = "merged"
    PER_PROJECT = "per-project"
    WORKSPACE_SCOPED = "workspace-scoped"
    UNSUPPORTED = "unsupported"


class ReporterPluginConfigBase(PluginConfigBase):
    SECTION_SEGMENT: ClassVar[str] = "reporters"
    GENERIC_SECTION: ClassVar[bool] = True

    options: Annotated[ReporterOptionsBase, Field(description="Reporter options")] = (
        ReporterOptionsBase()
    )
    extension: str | None = None

    @field_validator("extension", mode="wrap")
    @classmethod
    def _extension_is_a_filename_suffix(
        cls, value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
    ) -> Any:
        """The report is written to ``ash.<extension>`` in the reports directory.

        So the value is a filename suffix, from every source: one with a path
        separator, a colon, ``..`` or NUL is replaced by the reporter's default,
        with one warning naming the key. Declared here so it covers every
        reporter's ``extension``, including those that redeclare the field.
        """
        value = handler(value)
        if value is None or is_filename_suffix(value):
            return value
        name = (info.data or {}).get("name")
        # A section validated against this generic class has no name, and the
        # class name is no key of any config, so it is not put in the key's place.
        key = (
            f"reporters.{name}.extension"
            if name
            else "the extension of a reporters section"
        )
        # The key and the rule, not the value: a value can be one read from the
        # environment, and the warning goes to the console and ash.log.
        _warn_once(
            key,
            str(value),
            f"Ignoring {key}: the value is not a filename suffix such as 'json'. "
            "The report is written to ash.<extension> in the reports directory, so "
            "it cannot contain '/', '\\', ':', '..' or NUL. Using the default "
            "instead.",
        )
        raise PydanticUseDefault from None


def is_filename_suffix(value: object) -> bool:
    """Whether ``value`` can follow ``ash.`` in a file name without leaving its directory.

    The file-name rule is ``is_report_file_name``'s, asked of ``ash.<value>``, so
    the two cannot drift apart: a colon (on NTFS ``ash.json:stream`` is a stream
    of the file ``ash.json``, another reporter's) was missing from a second
    copy of it once. A ``..`` is refused as well.
    """
    from automated_security_helper.utils.report_path_links import is_report_file_name

    return (
        isinstance(value, str)
        and ".." not in value
        and is_report_file_name(f"ash.{value}")
    )


def confined_report_path(report_dir: Path, filename: str) -> Optional[Path]:
    """``report_dir / filename``, or None when that is not a file in ``report_dir``.

    Checked on the resolved path, so a ``..`` or a symlink that leads out of the
    directory is refused, whatever produced the name. So is any name while
    ``report_dir`` itself is a symlink or a directory junction, which it can
    become after the run's own check (utils/report_path_links.py), so each write
    checks it again. So is a name that is not one file name by the rule the run's
    own check applies (``is_report_file_name``): one holding a colon, which on
    NTFS names a stream of another file, or a NUL, which no file system takes.
    """
    from automated_security_helper.utils.report_path_links import (
        is_report_file_name,
        link_kind,
    )

    # Refused by name: whether resolve() raises on a NUL in the directory, and
    # as which error, is the Python version's to decide.
    if "\x00" in str(report_dir):
        return None
    if link_kind(Path(report_dir)) is not None:
        return None
    if not is_report_file_name(filename):
        return None
    target = Path(report_dir) / filename
    try:
        if target.resolve().parent != Path(report_dir).resolve():
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    return target


def write_report_file(report_dir: Path, filename: str, content: str) -> Optional[Path]:
    """Write a reporter's own file in ``report_dir``, or log why not and return None.

    For the files a reporter writes beside the one ``ReportPhase`` writes. The name
    has to pass ``confined_report_path``, and the write replaces the file rather
    than writing through it, so a symlink at that name is not followed. A reporter
    that calls this declares the names in ``companion_file_names``, so that a link
    already at one of them, or a name that is not a file in ``report_dir``, refuses
    the run before any reporter writes. A link that is at the name by the time of
    the write, or that ``report_dir`` itself has become, is refused and the refusal
    raised (``fs_guard.OutputLinkRefused``, or ``OutputDirLinkRefused`` for a
    directory junction), as for any other output file, rather than skipped with a
    warning. The write itself opens ``report_dir`` without following a link, so
    nothing swapped in after those checks is written through.

    An ``OSError`` from the write (a read-only directory, a directory at the name)
    is logged and answered with None. Any other failure, such as content that
    cannot be encoded as UTF-8, is raised for the caller to record against the
    reporter.
    """
    from automated_security_helper.utils.atomic_write import write_text_atomically
    from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused
    from automated_security_helper.utils.report_path_links import (
        is_report_file_name,
        link_kind,
    )
    from automated_security_helper.utils.sandbox.fs_guard import OutputLinkRefused

    directory = Path(report_dir)
    named = directory / filename
    links = [directory]
    # The run's own name rule, not a path-shape test: a name holding a NUL would
    # reach ``link_kind``'s lstat, which raises ValueError before
    # ``confined_report_path`` can refuse the name.
    if is_report_file_name(filename):
        links.append(named)
    for link in links:
        kind = link_kind(link)
        if kind == "a symlink":
            raise OutputLinkRefused(named, link)
        if kind is not None:
            raise OutputDirLinkRefused(f"{link.as_posix()} is {kind}")
    target = confined_report_path(report_dir, filename)
    if target is None:
        ASH_LOGGER.warning(
            f"Not writing {filename!r}: it is not a file in {report_dir}."
        )
        return None
    try:
        write_text_atomically(target, content, root=directory)
    except OutputDirLinkRefused:
        raise
    except OSError as error:
        ASH_LOGGER.warning(f"Could not write {target}: {error}")
        return None
    return target


T = TypeVar("T", bound=ReporterPluginConfigBase)


def declared_config_model(
    reporter_class: type,
) -> Optional[type[ReporterPluginConfigBase]]:
    """The config model a reporter declares with ``ReporterPluginBase[XConfig]``.

    None for a reporter that declares no model, or declares
    ``ReporterPluginConfigBase`` itself. See ``plugin_config.declared_config_model``.
    """
    return cast(
        Optional[type[ReporterPluginConfigBase]],
        plugin_declared_config_model(reporter_class, ReporterPluginConfigBase),
    )


def reporter_format_name(instance: "ReporterPluginBase") -> str | None:
    """The name ``--output-formats`` selects this reporter by.

    This is the reporter's configured ``name`` -- ``markdown``, ``sarif``,
    ``flat-json`` -- which is the string an operator writes on the command line
    and which every built-in reporter pins as a ``Literal``.

    Deliberately *not* the ``extension``. The two happen to be equal for four
    reporters (``csv``, ``html``, ``sarif``, ``yaml``) and differ for the rest:
    the markdown reporter's extension is ``summary.md``, ocsf's is ``ocsf.json``.
    Selecting on extension therefore matched only the four coincidences and
    silently skipped everything else -- see :func:`reporter_matches_requested_formats`.

    Returns ``None`` for a reporter whose config carries no name, which cannot be
    selected by name at all. Callers treat that as "does not match any explicit
    request" rather than as "matches everything", so an unnameable reporter is
    never emitted on the strength of a format the operator asked for by name.
    """
    return getattr(getattr(instance, "config", None), "name", None)


def reporter_file_name(instance: object) -> str:
    """The file in the reports directory that ``ReportPhase`` writes this reporter's report to.

    ``ash.<extension>``, or ``ash.txt`` for a reporter without an extension. The
    workspace report step names a workspace-level report the same way.
    """
    extension = getattr(getattr(instance, "config", None), "extension", None)
    return f"ash.{extension}" if extension else "ash.txt"


def reporter_companion_file_names(instance: object) -> Tuple[str, ...]:
    """The files this reporter writes itself in the reports directory, from its declaration.

    See ``ReporterPluginBase.companion_file_names``. Only file names are kept: a
    string, or a path-like object written as its string. A declaration that
    answers one string names that one file, not one file per character, and one
    that answers None names none. A declaration that raises propagates: the
    pre-write checks cannot vouch for the files of a reporter whose files are
    unknown, so the run is refused rather than going on without them.
    """
    declared = getattr(instance, "companion_file_names", None)
    if not callable(declared):
        return ()
    answer = declared()
    if answer is None:
        return ()
    if isinstance(answer, (str, os.PathLike)):
        answer = (answer,)
    names = []
    for name in answer:
        if isinstance(name, os.PathLike):
            name = os.fspath(name)
        if isinstance(name, str):
            names.append(name)
    return tuple(names)


def reporter_file_names(instance: object) -> Tuple[str, ...]:
    """Every file this reporter's run writes in the reports directory.

    Its report's file, then the files it writes itself, without repeats. This is
    what ``ReportPhase`` and the workspace report step check for links before any
    reporter runs (utils/report_path_links.py).
    """
    names = (reporter_file_name(instance), *reporter_companion_file_names(instance))
    return tuple(dict.fromkeys(names))


def reporter_matches_requested_formats(
    instance: "ReporterPluginBase", output_formats: "Collection[object]"
) -> bool:
    """Whether ``--output-formats`` selected this reporter.

    Why this function exists
    ------------------------
    Both ``ReportPhase`` and ``workspace.reporting`` filter reporters against the
    operator's requested formats, and both used to do it inline by comparing
    ``config.extension`` against the requested list. That comparison is wrong,
    because the requested list holds :class:`ExportFormat` *values* (format
    names) and an extension is a filename suffix. Of the fifteen reporters only
    four have an extension equal to their name, so ``--output-formats markdown``
    matched no reporter, the run exited 0, and ``reports/`` was empty with no
    warning.

    The obvious-looking alternative -- setting each reporter's ``extension`` to
    its format name -- was rejected: the extension also builds the output
    filename (``ash.{extension}``), so that would rename ``ash.summary.md`` to
    ``ash.markdown`` and break every consumer, document and test that reads the
    current names. Selection and filename are two different concerns that were
    being served by one field, so selection moved to ``name`` and the filename
    kept ``extension``.

    Shared rather than duplicated because the two call sites diverging would be
    invisible: a reporter could be selected by a single-directory scan and
    skipped by a workspace scan of the same directory, with nothing to say why.

    Args:
        instance: The reporter being considered.
        output_formats: What the operator asked for. Accepts ``ExportFormat``
            members as well as plain strings, because ``ScanExecutionEngine``
            threads the enum through unconverted while the CLI paths convert to
            ``.value`` first. Normalised here so neither caller has to. A
            collection that can be read again for the next reporter (a list or a
            tuple), not an iterator: an iterator is always truthy, so an empty
            one would read as a request for nothing, and a full one is spent by
            the first reporter asked about it, so every later reporter would be
            matched against an empty request. One string names one format, not
            one format per character.

    Returns:
        ``True`` if this reporter should run. An empty request means every
        reporter runs -- an operator who passed no ``--output-formats`` asked for
        the configured default set, not for nothing.

    Raises:
        TypeError: ``output_formats`` is an iterator, or bytes.
    """
    if isinstance(output_formats, Iterator):
        raise TypeError(
            "output_formats must be a collection such as a list or a tuple, not "
            f"an iterator ({type(output_formats).__name__}), which only the first "
            "reporter asked about could read."
        )
    if isinstance(output_formats, (bytes, bytearray)):
        raise TypeError(
            "output_formats must be a collection of format names, not "
            f"{type(output_formats).__name__}."
        )
    if isinstance(output_formats, str):
        # A string is a collection of its characters: read as one, "markdown"
        # asked for "m", "a", "r" and the rest, and every reporter was dropped.
        # An empty string is still an empty request.
        output_formats = (output_formats,) if output_formats else ()
    if not output_formats:
        return True
    requested = {str(getattr(fmt, "value", fmt)) for fmt in output_formats}
    name = reporter_format_name(instance)
    return name is not None and str(name) in requested


def off_host_reporter_refused(reporter_class: type, plugin_config: object) -> bool:
    """Whether a reporter that sends findings off the host is not enabled to run.

    A reporter class that sets ``sends_off_host`` sends findings to a remote
    service with the host's credentials, so it runs only when its section of the
    config says ``enabled: true``. Its own default does not count: a reporter from
    any package that declares itself off-host and ships enabled still needs the
    operator to turn it on. ``ash report``, the report phase and the workspace
    report step all ask this. ``plugin_config`` is what
    ``AshConfig.get_plugin_config`` returns, a dict or None.
    """
    if getattr(reporter_class, "sends_off_host", False) is not True:
        return False
    return not (
        isinstance(plugin_config, dict) and plugin_config.get("enabled") is True
    )


#: Config keys of the off-host reporters already named by
#: :func:`warn_off_host_section_without_enabled` in this process. A run reads a
#: reporter's section more than once (each workspace project's report phase reads
#: the same one), and one section should produce one warning.
_UNENABLED_SECTIONS_WARNED: Set[str] = set()
_UNENABLED_SECTIONS_LOCK = threading.Lock()


def reset_unenabled_off_host_section_warnings() -> None:
    """Forget which reporters were already named (tests)."""
    with _UNENABLED_SECTIONS_LOCK:
        _UNENABLED_SECTIONS_WARNED.clear()


def _sets_something(value: object) -> bool:
    return value not in (None, "", {}, [])


def warn_off_host_section_without_enabled(
    reporter_class: type, plugin_config: object
) -> None:
    """Warn, once per process, that an off-host reporter's section leaves it off.

    The AWS reporters ship ``enabled: false``. A config written for a release in
    which they shipped on sets their options and no ``enabled``, so it now uploads
    nothing; this names the reporter and the key that turns it on. It changes
    nothing: the reporter still does not run, so a section in the scanned
    repository's own config gains nothing from it. Only the reporter's config
    key is logged, never an option value (a bucket name, an account id). It is
    logged with markup off, so a reporter key that reads as markup is shown as
    written.

    Call it where an off-host reporter that the run would otherwise use is left
    out because :func:`off_host_reporter_refused` says so. ``plugin_config`` is
    what ``AshConfig.get_plugin_config`` returns: a section with ``enabled`` in
    it (true or false), or with nothing set, is not named.
    """
    if getattr(reporter_class, "sends_off_host", False) is not True:
        return
    if not isinstance(plugin_config, dict):
        return
    key = plugin_config_key(reporter_class)
    if "enabled" in plugin_config:
        # A section that sets 'enabled' to anything but a bool (the string
        # "true", 1, "yes") is refused by off_host_reporter_refused, which
        # admits only the boolean true. Left silent, `ash merge` and the
        # workspace report step dropped a reporter the operator had tried to
        # turn on with no message. The value's TYPE is named, never the
        # value: a config file can read it from the environment.
        value = plugin_config["enabled"]
        if isinstance(value, bool):
            return
        kind = "null" if value is None else f"a {type(value).__name__}"
        message = (
            f"Reporter '{key}' sends findings off the host and is not run: its "
            f"config section sets enabled to {kind}, and only the boolean true "
            f"turns it on (reporters.{key}.enabled). To run it, set "
            f"reporters.{key}.enabled: true in the operator's config, or pass "
            f"--config-overrides reporters.{key}.enabled=true."
        )
    else:
        if not any(_sets_something(value) for value in plugin_config.values()):
            return
        message = (
            f"Reporter '{key}' sends findings off the host and is disabled by "
            "default. Its config section sets options but not 'enabled': it does "
            "not set enabled: true, so it does not run. "
            f"To run it, set reporters.{key}.enabled: true in the operator's "
            f"config, or pass --config-overrides reporters.{key}.enabled=true."
        )
    with _UNENABLED_SECTIONS_LOCK:
        if key in _UNENABLED_SECTIONS_WARNED:
            return
        _UNENABLED_SECTIONS_WARNED.add(key)
    ASH_LOGGER.warning(message, extra=NO_MARKUP)


def reporter_classes_for_run(
    plugin_modules: Iterable[object], *, manager: Any = None
) -> list:
    """The reporter classes one run may use: ASH's built-ins and the modules it names.

    The plugin registry is process-wide, and a module registers its reporters the
    first time anything in the process imports it: an earlier scan, an MCP
    session, a test. Reading the whole registry gave a run every reporter the
    process had ever loaded, and the run then built, checked and ran the enabled
    ones, a dependency check that calls STS included. A scan's engine keeps to its
    own modules (``loader.plugins_of``); workspace reporting, ``ash report`` and
    ``ash merge`` take their candidates from here, with the modules their run
    names (``ash_plugin_modules`` in its configuration, plus any it was given on
    the command line). A report phase runs only the list its caller gives it.

    Which of them run is decided after this, in the same order at every site:
    enabled (and, for an off-host reporter, enabled by its section,
    ``off_host_reporter_refused``), then selected by the requested output
    formats, then the dependency check, for those alone.

    ``manager`` is the plugin manager to read, ``ash_plugin_manager`` by default;
    a caller passes the one it imported so a test that stands in for it sees
    this call too.
    """
    from automated_security_helper.plugins.loader import plugins_of

    if manager is None:
        from automated_security_helper.plugins import ash_plugin_manager

        manager = ash_plugin_manager
    return list(
        manager.plugin_modules("reporter", filter_callback=plugins_of(plugin_modules))
    )


def _as_given(value: Any, outer_location: Any = None) -> Any:
    """The handler ``configure`` passes where the field validator is passed pydantic's.

    The value a plugin's own model already holds needs no second pass.
    """
    return value


class ReporterPluginBase(PluginBase, Generic[T]):
    """Base reporter plugin with some methods of the IReporter abstract class
    implemented for convenience.
    """

    config: T | ReporterPluginConfigBase | None = None
    dependencies_satisfied: bool = True

    #: What this reporter does with a multi-project model. See the module
    #: docstring for why the default is ``PER_PROJECT`` and not ``MERGED``.
    #:
    #: A ``ClassVar`` rather than a pydantic field, for two reasons. It is a
    #: property of the reporter *class*, not of an instance's configuration, so
    #: it must be readable before instantiation -- the workspace driver decides
    #: whether to build the instance at all. And ``PluginBase`` sets
    #: ``use_enum_values=True``, which would coerce a field holding an enum down
    #: to its bare string on assignment; a ClassVar is untouched by that, so
    #: identity comparisons against enum members keep working.
    workspace_behaviour: ClassVar[ReporterWorkspaceBehaviour] = (
        ReporterWorkspaceBehaviour.PER_PROJECT
    )

    #: Whether this reporter sends findings off the host (to a remote service,
    #: with the host's credentials). Such a reporter runs only when its config
    #: section sets ``enabled: true``; see :func:`off_host_reporter_refused`. A
    #: class attribute, so it is known before the reporter is built and does not
    #: depend on which package the reporter comes from.
    sends_off_host: ClassVar[bool] = False

    #: Options that choose where findings are sent or written, or which
    #: credentials send them: a region, an account, a bucket, an endpoint, a
    #: profile, an output path. Also any other option that is the operator's for
    #: the same reason: what is sent along with the findings, or how long the
    #: reporter keeps calling its service. Named as the options model's fields;
    #: an alias of one is covered too. When the config was built from a file inside the
    #: scanned tree, or from one an MCP client delivered, these options come from
    #: the trusted base instead: the defaults, an operator config outside the
    #: tree, and ``--config-overrides`` (config/reporter_trust.py). A ``ClassVar``
    #: for the same reason as ``workspace_behaviour``: it is read from the class,
    #: after the plugin modules are imported and before any reporter is built.
    destination_options: ClassVar[Tuple[str, ...]] = ()

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        """Read a ``sends_off_host`` that is not a bool as the bool it is truthy as.

        Every test of it, here and in the config trust and merge code, is
        ``is True``, so a reporter declaring ``sends_off_host = 1`` or ``"yes"``
        was run as a local one, without ``enabled: true``, and its destination
        options were not confined. Declared as the bool at class creation, the
        declaration is read the same way at every one of those sites. Read off
        the class, not its ``__dict__``: a plain mixin's ``sends_off_host = 1``
        is inherited, and is converted here and set on this class.

        A declaration that cannot be read off the class (a ``property``, which
        the class returns as the property object) is truthy, so it reads as
        ``True``: a reporter whose answer is not known before it is built is
        run as one that sends findings off the host, which needs ``enabled:
        true``, never as a local one.
        """
        super().__pydantic_init_subclass__(**kwargs)
        declared = getattr(cls, "sends_off_host", False)
        if not isinstance(declared, bool):
            cls.sends_off_host = bool(declared)

    @field_validator("config", mode="wrap")
    @classmethod
    def _config_is_validated_by_the_declared_model(
        cls, value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
    ) -> Any:
        """A reporter that declares a config model is configured by that model.

        A section it refuses, such as an AWS reporter's ``max_delay`` over its
        60-second cap, is a ValidationError: ``ReportPhase`` and the workspace
        report step log it, with the option and the limit, and go on without this
        reporter. The declared model validates under the validation context the
        field was given. See ``plugin_config.config_validated_by_declared_model``.
        """
        return config_validated_by_declared_model(
            cls, ReporterPluginConfigBase, value, handler, info
        )

    @classmethod
    def _declared_config_model(cls) -> Optional[type[ReporterPluginConfigBase]]:
        """The config model this reporter class declares, or None.

        Read from the class itself: a class taken from a value (``type(self)``)
        handed to a call is what the shown-text guard refuses in the package.
        """
        return declared_config_model(cls)

    @classmethod
    def _validated_by_declared_model(
        cls, config: Any, handler: ValidatorFunctionWrapHandler
    ) -> Any:
        """``config`` validated by the model this reporter class declares.

        The class is the caller here for the same reason as above. Named
        without a ``_config`` prefix: ``configure`` calls it, and the public
        ``config`` field is the only ``config`` attribute its source names.
        """
        return config_validated_by_declared_model(
            cls, ReporterPluginConfigBase, config, handler
        )

    @model_validator(mode="after")
    def setup_paths(self) -> Self:
        """Set up default paths and initialize plugin configuration."""
        # Use context if provided, otherwise fall back to instance attributes
        if self.context is None:
            raise ScannerError(f"No context provided for {self.__class__.__name__}!")
        ASH_LOGGER.trace(f"Using provided context for {self.__class__.__name__}")
        if self.config is None:
            # A reporter built with no config section runs on the defaults its
            # declared model states: its enabled default, its name and its
            # extension. Left None, the enabled filter was skipped, the report
            # was written as the base's "ash.txt", and the reporter could not be
            # selected by name. A reporter that declares no model keeps None.
            # So does one whose model has a required field: it states no default
            # to run on, and building it with no config used to be allowed, so
            # the refusal does not fail its construction (the section is checked
            # where one is given, by ``configure`` and the ``config`` field).
            declared = self._declared_config_model()
            if declared is not None:
                try:
                    self.config = declared()
                except ValidationError:
                    ASH_LOGGER.debug(
                        f"{self.__class__.__name__} declares a config model with a "
                        "required field, so it is built with no config",
                        extra=NO_MARKUP,
                    )
        return self

    def configure(
        self,
        config: ReporterPluginConfigBase | None = None,
    ) -> None:
        """Configure the reporter with provided configuration.

        The config is held to the reporter's declared model as the ``config``
        field holds one given at construction: a section it refuses is a
        ValidationError, and one of another class is read through the declared
        model. Assignment alone is not validated here.
        """
        if config:
            config = self._validated_by_declared_model(config, _as_given)
            self.config = config

    def companion_file_names(self) -> Tuple[str, ...]:
        """The files this reporter writes itself in the reports directory, beside its report.

        Empty by default. A reporter that writes files with ``write_report_file``
        returns the names it would write with its current options. ``ReportPhase``
        and the workspace report step refuse the run, before any reporter writes,
        when one of them is already a link.
        """
        return ()

    def _pre_report(self) -> None:
        self.start_time = datetime.now(timezone.utc)

    def _post_report(self) -> None:
        self.end_time = datetime.now(timezone.utc)

    @staticmethod
    def sarif_field_mappings() -> dict[str, str] | None:
        """
        Get mappings from SARIF fields to this reporter's output format.

        This method should be implemented by reporter classes to provide
        information about how SARIF fields map to their specific output format.

        Returns:
            Optional[Dict[str, str]]: Dictionary mapping SARIF field paths to
                                     reporter-specific field paths, or None if
                                     no mappings are available.
        """
        return None

    def validate_plugin_dependencies(self) -> bool:
        """Validate reporter configuration and requirements.

        Defaults to returning True as most reporter plugins are entirely Python based."""
        return self.dependencies_satisfied

    ### Methods that require implementation by plugins.
    @abstractmethod
    def report(self, model: AshAggregatedResults) -> str | None:
        """Execute the reporter against the aggregated AshAggregatedResults.

        Returns a string containing the report or the response from the remote
        receiving the report.
        """
