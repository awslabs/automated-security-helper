# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import functools
import importlib
import re
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock, local
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Annotated,
    Iterable,
    Iterator,
    List,
    Literal,
    Mapping,
    NamedTuple,
    Sequence,
    Set,
    Tuple,
)
from pydantic import BaseModel, Field, ConfigDict, PrivateAttr

from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP


def callback_display_name(callback: Any, *, strict: bool = False) -> str:
    """A name for a log line that no callback shape can make raise: a
    functools.partial has no ``__name__``, and a descriptor can raise on
    reading it (``hasattr`` passes only AttributeError through). The loader's
    registration arm and ``notify`` below name callbacks through this one
    helper.

    Even the fallback ``type(callback).__name__`` can raise (a metaclass
    property), and a callback can reach the handler list without the loader's
    validation (``subscribe`` directly), so the display ends in a fixed
    "anonymous" rather than breaking ``notify`` for every subscriber of the
    event. With ``strict`` the fallback's own error propagates instead: the
    loader validates a declared ``ASH_EVENT_HANDLERS`` mapping with it, so a
    handler it cannot truthfully name is refused with the mapping."""
    try:
        name = getattr(callback, "__name__", None)
    except Exception:  # noqa: BLE001 -- a display name must never raise
        name = None
    if isinstance(name, str):
        return name
    if strict:
        return type(callback).__name__
    try:
        name = type(callback).__name__
    except Exception:  # noqa: BLE001 -- a display name must never raise
        name = None
    return name if isinstance(name, str) else "anonymous"


def callable_module(callback: Any) -> str | None:
    """The module name *callback* was defined in, or ``None``, never raising.

    Unwraps a ``functools.partial`` chain to its function (a partial reports
    ``functools`` as its own ``__module__``; the wrapped function is what was
    defined somewhere) and reads ``__module__`` under an exception guard: the
    attribute read can raise (a descriptor or a metaclass property), and a
    value that is not a ``str`` is no module name. Returns ``None`` when the
    name is unreadable or not a ``str``. Callers decide what ``None`` means at
    their own site -- owned or not, admitted or left out -- so this helper
    takes no side.
    """
    target = callback
    while isinstance(target, functools.partial):
        target = target.func
    try:
        name = getattr(target, "__module__", None)
    except Exception:  # noqa: BLE001 -- a module read for a filter must never raise
        name = None
    return name if isinstance(name, str) else None


#: The forms of the module names the code now running must not print, set by
#: :func:`masked_module_names`. A ContextVar, not module state: it holds for
#: one load or one registry read on the calling thread and is restored when
#: the block ends, so no run, thread or test sees another's names.
_MASKED_MODULE_FORMS: ContextVar[Tuple[str, ...]] = ContextVar(
    "ash_masked_module_forms", default=()
)


def masked_form_identity(form: str) -> Tuple[Any, ...]:
    """What makes two masked-module forms one entry.

    Their text, their type, whether they are matched as a whole component,
    whether they are exempt inside a traceback frame line of ASH's or the
    import machinery, and their variant pattern. A plain value and a needle of
    the same text are matched differently, and so are two needles that differ
    in any of the other three, so the one that is dropped from a join is never
    the stricter of two.
    """
    return (
        str(form),
        type(form),
        getattr(form, "whole_component", False),
        getattr(form, "frame_exempt", False),
        getattr(form, "pattern", None),
    )


@contextmanager
def masked_module_names(forms: Iterable[str]) -> Iterator[None]:
    """Inside the block, :func:`without_masked_modules` hides *forms*.

    *forms* are ``plugins.loader.masked_module_scope`` of the module names a
    config read from the environment, which a log line names by their mask:
    each masked name as a plain value, hidden inside a longer module name too,
    and the forms derived from it, hidden as whole components.
    The lines that print a module path they did not get from the config (a
    plugin's ``__module__``, a registration's path, an import error's text)
    cannot see the run's names map, so the loader sets this around an import
    and the engine and the workspace around their registry reads. Blocks nest:
    an inner block adds its forms to the outer one's, and nothing outlives the
    outermost. An exact repeat is dropped, so the same scope entered twice, or
    a registration made inside such a block, holds each form once. Two entries
    are the same only when :func:`masked_form_identity` says so: a plain value
    and a module-form needle of the same text compare equal as strings but are
    matched differently (the plain value anywhere, the needle as a whole
    component), and the redaction gives the plain value precedence, so keeping
    only the first of the two would let an outer needle hide an inner block's
    plain value.
    """
    added = tuple(forms)
    if not added:
        yield
        return
    held = _MASKED_MODULE_FORMS.get()
    distinct: Dict[Tuple[Any, ...], str] = {}
    for form in (*held, *added):
        distinct.setdefault(masked_form_identity(form), form)
    token = _MASKED_MODULE_FORMS.set(tuple(distinct.values()))
    try:
        yield
    finally:
        _MASKED_MODULE_FORMS.reset(token)


def without_masked_modules(text: str) -> str:
    """*text* with the masked module names in scope hidden, as a failure's text is.

    The same needles and the same redaction as the loader's failure line
    (``text_without_values``), so a module name reads the same in a log line
    here as in the load's own. Outside a :func:`masked_module_names` block, or
    in one given no forms, *text* is returned as it is.
    """
    forms = _MASKED_MODULE_FORMS.get()
    if not forms:
        return text
    # Imported here: the config modules import the plugin packages, which
    # import this module.
    from automated_security_helper.utils.error_text import text_without_values

    return text_without_values(text, forms)


if TYPE_CHECKING:
    from automated_security_helper.base.plugin_context import PluginContext


class AshPluginRegistration(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )

    name: Annotated[str, Field(description="The name of the plugin")]
    plugin_module_path: Annotated[
        str,
        Field(
            description="The module path containing the plugin. This module will be imported at the start of ASH to identify plugins to use. Example: `automated_security_helper.plugin_modules.ash_builtin.scanners`"
        ),
    ]
    description: Annotated[
        str | None, Field(description="A description of the plugin")
    ] = None
    version: Annotated[str | None, Field(description="The version of the plugin")] = (
        None
    )
    author: Annotated[str | None, Field(description="The author of the plugin")] = None
    enabled: Annotated[bool, Field(description="Whether the plugin is enabled")] = True
    #: The forms :func:`masked_module_names` held when this registration was made
    #: (the loader's import, which runs the decorators, sets them). Not part of
    #: the model's data: a private attribute is never dumped, validated or put in
    #: the schema. It is compared, though: pydantic's equality reads private
    #: attributes, so two registrations made inside and outside a scope compare
    #: unequal. Nothing compares registrations (the resolution cache is keyed by
    #: name, module path and enabled flag, and the untrusted-import record by
    #: identity), so the names are kept on the registration itself.
    _masked_forms: Tuple[str, ...] = PrivateAttr(default=())

    def hide_masked_modules(self, text: str) -> str:
        """*text* with the module names this registration was made under a mask
        for hidden, besides those in force where it is read.

        :meth:`AshPluginManager.plugin_modules` re-resolves every registration
        whenever any changes, so the warning for a registration whose module
        does not import is written when the next reader asks, in that reader's
        scope, which can be another session's or none. The registration
        carries its own names so that the line hides them whoever resolves.
        """
        with masked_module_names(self._masked_forms):
            return without_masked_modules(text)


class AshPluginLibrary(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    converters: Annotated[
        Dict[str, AshPluginRegistration],
        Field(
            description="A dictionary of converters to register with the plugin manager"
        ),
    ] = {}
    scanners: Annotated[
        Dict[str, AshPluginRegistration],
        Field(
            description="A dictionary of scanners to register with the plugin manager"
        ),
    ] = {}
    reporters: Annotated[
        Dict[str, AshPluginRegistration],
        Field(
            description="A dictionary of scanners to register with the plugin manager"
        ),
    ] = {}
    event_handlers: Annotated[
        Dict[AshEventType, List[Callable]],
        Field(
            description="A dictionary of event handlers to register with the plugin manager"
        ),
    ] = {}


class _Resolution(NamedTuple):
    """What ``plugin_modules`` resolved one plugin kind to, and from what."""

    #: (name, module path, enabled) of each registration, in registry order.
    registrations: Tuple[Tuple[str, str, bool], ...]
    classes: List[type]


class AshPluginManager(BaseModel):
    model_config = ConfigDict(extra="allow")

    plugin_library: Annotated[AshPluginLibrary, Field()] = AshPluginLibrary()
    context: Any = None
    #: plugin kind -> _Resolution. Reused only while the kind's registrations are
    #: the ones it was resolved from; see plugin_modules.
    _resolved_plugins: dict = PrivateAttr(default_factory=dict)
    #: Guards the registry dicts: registration's check-and-insert, and the copy of
    #: them plugin_modules resolves from. Workspace mode registers and resolves from
    #: several threads at once. Imports run outside it: an import registers
    #: plugins, which takes this lock.
    _registry_lock: Lock = PrivateAttr(default_factory=Lock)
    #: Guards the shared event-handler lists. This manager is a module-level
    #: singleton (``plugins/__init__.py``) and workspace mode runs several
    #: differently-configured scans against it concurrently, so subscribe and
    #: notify cannot both touch the same list unsynchronised.
    _event_lock: Lock = PrivateAttr(default_factory=Lock)
    #: ``id(callback)`` -> (module path, callback) for every handler a plugin
    #: module declared through ``ASH_EVENT_HANDLERS`` (the loader subscribes
    #: those with ``declared_by``). A handler's ``__module__`` says where its
    #: function was defined, not which plugin module listed it: a plugin module
    #: may list a function from a helper library, or a functools.partial, and a
    #: scan's handler filter has to know that such a handler belongs to a plugin
    #: module (one this scan did or did not name) rather than to the program
    #: running the scan. The callback is kept beside its owner so a reused id
    #: is never read as a record of a different object. Guarded by
    #: ``_event_lock``, with the handler lists it describes.
    _declared_handler_modules: dict = PrivateAttr(default_factory=dict)
    #: Which registrations an untrusted import made, so a scan is offered only
    #: the classes its own modules load (``plugins_loaded_by``). By plugin type
    #: and name: the module imported for an untrusted source, and the
    #: registration, so a later registration under the same name is not taken
    #: for it.
    _untrusted_registrations: dict = PrivateAttr(default_factory=dict)
    #: Every module the operator named in this process (``trust_plugin_modules``).
    _operator_modules: set = PrivateAttr(default_factory=set)
    _provenance_lock: Lock = PrivateAttr(default_factory=Lock)
    #: The module ``untrusted_import`` is importing on this thread, if any.
    _importing: local = PrivateAttr(default_factory=local)

    def set_context(self, context: "PluginContext"):
        """Set the plugin context for this plugin manager.

        Args:
            context: The PluginContext to use for plugin discovery and operations
        """
        self.context = context
        # The directories only: the context's config is the resolved one, with
        # every value its files read from the environment, and --debug prints
        # this line to the console and to ash.log.
        ASH_LOGGER.debug(
            "Plugin manager context set: "
            f"source_dir={getattr(context, 'source_dir', None)}, "
            f"output_dir={getattr(context, 'output_dir', None)}, "
            f"work_dir={getattr(context, 'work_dir', None)}",
            extra=NO_MARKUP,
        )

    def subscribe(self, event_type, callback, *, declared_by: str | None = None):
        """Subscribe a callback to a specific event type, at most once.

        ``declared_by`` names the plugin module whose ``ASH_EVENT_HANDLERS``
        listed the callback, when the loader is the caller; it is recorded for
        :meth:`handler_declared_by`, so a scan's handler filter can tell a
        handler a plugin module declared (admitted only when the scan names
        that module, wherever its function was defined) from one the program
        running the scan subscribed itself. A callback already recorded keeps
        its first owner.

        Idempotent, and locked, because both properties are load-bearing once
        more than one differently-configured scan runs in a process:

        * ``load_internal_plugins()`` runs per ``ScanExecutionEngine``, so a
          workspace of five projects previously ended up with five copies of
          every handler and fired each one five times. Harmless while the
          handlers only log, and a verdict bug as soon as one touches results --
          which is exactly what the reporter and workspace-policy phases add.
        * The old ``not in``-then-assign was unsynchronised, so two threads could
          each build a fresh list for the same event and one would clobber the
          other, silently dropping the subscription it had just made.

        Identity is decided by ``==``, which for a plain function is identity and
        for a bound method compares both the instance and the function -- the
        right granularity, since two instances of a handler class are genuinely
        two subscribers.

        Still returns the callback so decorator usage is unchanged.
        """
        with self._event_lock:
            if isinstance(declared_by, str) and declared_by:
                self._declared_handler_modules.setdefault(
                    id(callback), (declared_by, callback)
                )
            handlers = self.plugin_library.event_handlers.setdefault(event_type, [])
            if callback in handlers:
                ASH_LOGGER.debug(
                    f"Callback already subscribed to event {event_type}; skipping "
                    f"the duplicate. Total subscribers: {len(handlers)}"
                )
                return callback
            handlers.append(callback)
            total = len(handlers)
        ASH_LOGGER.debug(
            f"Subscribed callback to event {event_type}. Total subscribers for this event: {total}"
        )
        return callback  # Return for decorator usage

    def handler_declared_by(self, callback: Any) -> str | None:
        """The plugin module whose ``ASH_EVENT_HANDLERS`` declared *callback*, or None.

        None for a callback the program running the scan subscribed itself, and
        for one no loader has subscribed with ``declared_by``. Matched by
        identity: a record whose callback is a different object with a reused
        id is no record of this one.
        """
        with self._event_lock:
            entry = self._declared_handler_modules.get(id(callback))
        if entry is None or entry[1] is not callback:
            return None
        return entry[0]

    def notify(
        self,
        event_type,
        *args,
        handler_filter: Callable[[Callable], bool] | None = None,
        _scope: Callable[[Any], bool] | None = None,
        **kwargs,
    ):
        """Notify the subscribers of an event: those the given filters accept.

        Args:
            event_type: The event to notify.
            handler_filter: Which subscribers this notification reaches. A scan
                passes its own (``plugins.loader.scan_handler_filter``), so a
                handler registered by a plugin module only another scan named is
                not called for it. None notifies every subscriber.
            _scope: The filter for a scan's own plugin modules
                (``loader.plugins_of``). Subscriptions are process-wide, so
                without it an event handler that another scan's modules
                subscribed ran in this one, and was handed this run's context
                and results. ``_scope`` is not passed on to the handlers.
                With both filters given, a subscriber is notified only when
                both accept it.
        """
        if not hasattr(self.plugin_library, "event_handlers"):
            ASH_LOGGER.debug(
                f"No event handlers dictionary exists for event {event_type}"
            )
            return []

        if event_type not in self.plugin_library.event_handlers:
            ASH_LOGGER.debug(f"No subscribers for event {event_type}")
            return []

        # Snapshot under the lock. A callback subscribed from another project's
        # thread while this loop ran would otherwise raise "list changed size
        # during iteration", and the same handler list is shared by every project
        # in a workspace.
        with self._event_lock:
            handlers = list(self.plugin_library.event_handlers[event_type])
        if handler_filter is not None:
            handlers = [callback for callback in handlers if handler_filter(callback)]
        if _scope is not None:
            handlers = [callback for callback in handlers if _scope(callback)]

        ASH_LOGGER.debug(f"Notifying {len(handlers)} subscribers of event {event_type}")
        results = []
        for callback in handlers:
            ASH_LOGGER.debug(
                f"Calling subscriber callback {callback_display_name(callback)}"
            )
            results.append(callback(*args, **kwargs))

        return results

    def register_plugin_module(
        self,
        plugin_type: Literal["converter", "scanner", "reporter"],
        plugin_module_class,
        plugin_module_path: str,
        plugin_module_version: str | None = None,
        plugin_module_enabled: bool = True,
    ):
        """Register a plugin module with the plugin manager.

        A registration is identified by its module path and name. Registering the
        same pair again adds nothing. A class whose name is already registered
        from another module path is registered as well, under a key that adds its
        module path (``<module path>:<name>``), so a plugin package with a class
        named like another package's, or like one of ASH's built-in plugins, does
        not keep either class from resolving, whichever registers first. No
        registration is ever replaced.

        Args:
            plugin_type: Type of plugin (converter, scanner, reporter)
            plugin_module_class: The plugin class to register
            plugin_module_path: Path to the module containing the plugin
            plugin_module_version: Optional version of the plugin
            plugin_module_enabled: Whether the plugin is enabled
        """
        # If plugin_module_class is a string, use it directly as the name
        if isinstance(plugin_module_class, str):
            plugin_module_name = plugin_module_class
        else:
            plugin_module_name = getattr(plugin_module_class, "__name__", "Unknown")

        if plugin_module_name == "ash-default" and not re.match(
            pattern=r"^automated_security_helper\.(converters|scanners|reporters)\.ash_default$",
            string=plugin_module_path,
        ):
            ASH_LOGGER.error(
                without_masked_modules(
                    f"ash-default is a protected plugin_module_name. Plugin module at path '{plugin_module_path}' should register with a different name."
                )
            )
            return

        registrations = self._registrations(plugin_type)
        with self._registry_lock:
            key = plugin_module_name
            existing = None
            if registrations is not None:
                existing = registrations.get(key)
                if (
                    existing is not None
                    and existing.plugin_module_path != plugin_module_path
                ):
                    key = f"{plugin_module_path}:{plugin_module_name}"
                    existing = registrations.get(key)
            already_registered = existing is not None
            if registrations is not None and not already_registered:
                registration = AshPluginRegistration(
                    name=plugin_module_name,
                    plugin_module_path=plugin_module_path,
                    version=plugin_module_version,
                    enabled=plugin_module_enabled,
                )
                registration._masked_forms = _MASKED_MODULE_FORMS.get()
                registrations[key] = registration
        if already_registered:
            ASH_LOGGER.warning(
                without_masked_modules(
                    f"Plugin module '{plugin_module_name}' from "
                    f"'{plugin_module_path}' already registered. Skipping."
                )
            )
            return

        # By the key it was registered under, which plugins_loaded_by reads back.
        untrusted = getattr(self._importing, "module", None)
        if untrusted is not None and registrations is not None:
            with self._provenance_lock:
                self._untrusted_registrations[(plugin_type, key)] = (
                    untrusted,
                    registrations[key],
                )

        ASH_LOGGER.verbose(f"Registered plugin module '{plugin_module_name}'")

    def registration_snapshot(self) -> tuple:
        """What is registered right now, for :meth:`undo_registrations_since`.

        The loader takes one before importing a configured plugin module: the
        import runs the module's decorators and the loader subscribes what the
        module declares, and a module refused at the registration stage must
        not leave any of that in this process-wide registry. Shallow copies of
        the three registration dicts and of each event's handler list, each
        under its own lock; the registrations and callbacks themselves are
        shared, which is what makes the undo an identity comparison."""
        with self._registry_lock:
            kinds = (
                dict(self.plugin_library.converters),
                dict(self.plugin_library.scanners),
                dict(self.plugin_library.reporters),
            )
        with self._event_lock:
            events = {
                event_type: list(handlers)
                for event_type, handlers in self.plugin_library.event_handlers.items()
            }
        return (kinds, events)

    def undo_registrations_since(self, snapshot: tuple, owner: str) -> None:
        """Remove what the refused module *owner* registered or subscribed
        after *snapshot* was taken.

        A removal of the refused module's own additions, never a wholesale
        restore: everything the snapshot holds is left exactly as it is now,
        and an addition made in the window is removed only when it is the
        refused module's -- a registration whose ``plugin_module_path`` is
        *owner* or under it, or a handler defined there (its ``__module__``,
        read never-raising, a functools.partial unwrapped to its function).
        Another thread can load a GOOD plugin module inside the refused
        module's import window (the MCP server runs scans as threads of one
        process), and the refused module can first-import a plugin module
        that stays loaded: undoing either's registration would lose it for
        the process, because the cached import never runs its decorators
        again.

        The residual limit: a handler whose ``__module__`` is another
        module's (a foreign function the refused import subscribes directly)
        is not read as the refused module's, and survives the refusal."""

        def _owned_registration(registration: Any) -> bool:
            path = getattr(registration, "plugin_module_path", "") or ""
            return path == owner or path.startswith(owner + ".")

        def _owned_handler(callback: Any) -> bool:
            name = callable_module(callback)
            if name is None:
                return False
            return name == owner or name.startswith(owner + ".")

        kinds_before, events_before = snapshot
        registries = (
            self.plugin_library.converters,
            self.plugin_library.scanners,
            self.plugin_library.reporters,
        )
        with self._registry_lock:
            for registry, before in zip(registries, kinds_before):
                for name in [key for key in registry if key not in before]:
                    if _owned_registration(registry[name]):
                        registry.pop(name, None)
        with self._event_lock:
            handlers_by_event = self.plugin_library.event_handlers
            removed: List[Any] = []
            for event_type in list(handlers_by_event):
                kept = events_before.get(event_type, [])
                remaining = []
                for callback in handlers_by_event[event_type]:
                    if any(callback is held for held in kept) or not _owned_handler(
                        callback
                    ):
                        remaining.append(callback)
                    else:
                        removed.append(callback)
                handlers_by_event[event_type] = remaining
                if (
                    not handlers_by_event[event_type]
                    and event_type not in events_before
                ):
                    del handlers_by_event[event_type]
            # The declared-by record of a removed handler goes with it: the
            # refused module's declarations are undone whole, and a callback
            # object subscribed again later is recorded again by that load.
            still_subscribed = {
                id(callback)
                for callbacks in handlers_by_event.values()
                for callback in callbacks
            }
            for callback in removed:
                if id(callback) not in still_subscribed:
                    self._declared_handler_modules.pop(id(callback), None)

    def remove_plugin_module_registration(
        self,
        plugin_type: Literal["converter", "scanner", "reporter"],
        plugin_module_name: str,
    ) -> bool:
        """Remove one plugin-module registration; True when it was there.

        The inverse of :meth:`register_plugin_module`, for a test that
        registered a module of its own and puts the registry back, through the
        manager's API rather than its state. Under the same lock as
        registration, and the resolved memo follows the registrations, so no
        cache needs touching.
        """
        registry = self._registrations(plugin_type)
        if registry is None:
            return False
        with self._registry_lock:
            return registry.pop(plugin_module_name, None) is not None

    def _registrations(self, plugin_type) -> Dict[str, AshPluginRegistration] | None:
        """The registration dict for *plugin_type*, or None for an unknown type."""
        if plugin_type == "converter":
            return self.plugin_library.converters
        if plugin_type == "scanner":
            return self.plugin_library.scanners
        if plugin_type == "reporter":
            return self.plugin_library.reporters
        return None

    @contextmanager
    def untrusted_import(self, module_name: str) -> Iterator[None]:
        """Attribute what this thread registers inside the block to ``module_name``.

        For importing a module the operator did not name: one that a config
        file inside the scanned tree, or a config an MCP client delivered, lists
        in ``ash_plugin_modules``, or one an MCP client's request loads.
        Registration lasts for the rest of the process, and the MCP server and a
        workspace run build several scans in one process, so
        ``plugins_loaded_by`` leaves these registrations' classes out of a scan
        that does not itself load the module.

        Per thread, because the decorators register a class on the thread that
        runs its module's code, which is the thread importing it; a scan
        importing on another thread at the same time is not attributed here. A
        module already imported registers nothing again, so what an earlier
        import of it registered keeps its earlier attribution.
        """
        previous = getattr(self._importing, "module", None)
        self._importing.module = module_name
        try:
            yield
        finally:
            self._importing.module = previous

    def trust_plugin_modules(self, module_names: Iterable[str]) -> None:
        """Record ``module_names`` as modules the operator loaded.

        ``--ash-plugin-modules``, ``ASH_PLUGIN_MODULES``, or the operator's
        configuration. ``plugins_loaded_by`` does not drop what their imports
        registered, even when an untrusted import registered it first: the
        operator loading a module first would have left it untracked, and the
        order two scans load a module in does not decide what a later scan is
        offered. That widens nothing a scan selects beyond its own modules: the
        scan's filter (``plugins.loader.scan_plugin_filter``) runs first and
        leaves out every module the scan does not name, so a module the
        operator named for one scan takes no part in a later scan that does not
        name it.
        """
        with self._provenance_lock:
            self._operator_modules.update(name for name in module_names if name)

    def plugins_loaded_by(
        self,
        plugins: Mapping[str, Sequence[type]],
        module_names: Iterable[str],
    ) -> Dict[str, List[type]]:
        """``plugins`` without the classes only another scan's untrusted imports brought in.

        A class is left out when every registration that brings it into
        ``plugin_modules`` was made inside ``untrusted_import`` of a module that
        neither ``module_names`` (the modules this scan loads) nor a module the
        operator named (``trust_plugin_modules``) is, and none of those modules
        defines the class, is a package around its module, has it as an
        attribute, or lists it in ``ASH_SCANNERS``, ``ASH_REPORTERS`` or
        ``ASH_CONVERTERS``. Those last checks cover a module this scan names that
        an untrusted import already imported along the way: importing it again
        registers nothing. Every other class is kept, including one embedding
        code registered through ``register_plugin_module`` itself.

        The resolved list ``plugin_modules`` caches stays as it is; this filters
        what one scan takes from it.

        Args:
            plugins: The classes ``plugin_modules`` resolved, by plugin type.
            module_names: The plugin modules this scan loads: the operator's and
                those its own config names.

        Returns:
            The classes to select, by plugin type, in their original order.
        """
        selected = {kind: list(classes) for kind, classes in plugins.items()}
        with self._provenance_lock:
            tracked = dict(self._untrusted_registrations)
            names = set(module_names) | self._operator_modules
        if not tracked:
            return selected
        dropped: Dict[type, Set[str]] = {}
        # The names each importing module's registrations were made under a
        # mask for: the line below hides them whoever reads it, as a
        # registration's own warning does (hide_masked_modules).
        origin_forms: Dict[str, List[str]] = {}
        for kind, classes in selected.items():
            registry = self._registry(kind)
            if registry is None:
                continue
            untracked_classes: Set[type] = set()
            origins: Dict[type, Set[str]] = {}
            # A copy: a registration on another thread must not resize the dict
            # this loop walks.
            for name, registration in dict(registry).items():
                if not registration.enabled:
                    continue
                found = self._registered_classes(kind, registration, imported_only=True)
                entry = tracked.get((kind, name))
                if entry is None or entry[1] is not registration:
                    untracked_classes.update(found)
                    continue
                origin_forms.setdefault(entry[0], []).extend(registration._masked_forms)
                for cls in found:
                    origins.setdefault(cls, set()).add(entry[0])
            kept: List[type] = []
            for cls in classes:
                if (
                    cls in untracked_classes
                    or cls not in origins
                    or origins[cls] & names
                    or _named_module_provides(names, cls)
                ):
                    kept.append(cls)
                else:
                    dropped[cls] = origins[cls]
            selected[kind] = kept
        if dropped:

            def hidden(module: str) -> str:
                with masked_module_names(origin_forms.get(module, ())):
                    return without_masked_modules(module)

            described = ", ".join(
                f"{getattr(cls, '__name__', cls)!r} (imported with "
                f"{', '.join(hidden(m) for m in sorted(modules))})"
                for cls, modules in dropped.items()
            )
            ASH_LOGGER.verbose(
                f"Plugin classes {described} are not selected: this process "
                "registered them while importing a module for another scan's "
                "config file inside its scanned tree, a config an MCP client "
                "delivered, or an MCP client's request, and neither this scan nor "
                "the operator loads that module."
            )
        return selected

    def masked_forms_of_module(
        self, plugin_type: str, module_path: str
    ) -> Tuple[str, ...]:
        """The names the registrations of *module_path* were made under a mask for.

        A line that prints a registered plugin's module (the scan's debug list
        of plugins it does not use) hides these besides the names in force
        where it is written: the registry is the process's, so the plugin can
        come from a module that another run's scope masked.

        A registration is one of *module_path* when its path is that module or
        a package around it (``a.b`` for ``a.b.c``, not for ``a.bc``): the
        resolution lists every plugin class of a registered module, so an
        undecorated subclass defined in a submodule is listed under the path
        its parent class registered.
        """
        registry = self._registry(plugin_type)
        if registry is None:
            return ()
        with self._registry_lock:
            registrations = list(registry.values())
        return tuple(
            form
            for registration in registrations
            if module_path == registration.plugin_module_path
            or module_path.startswith(registration.plugin_module_path + ".")
            for form in registration._masked_forms
        )

    def _registry(self, plugin_type: str) -> Dict[str, AshPluginRegistration] | None:
        return {
            "converter": self.plugin_library.converters,
            "scanner": self.plugin_library.scanners,
            "reporter": self.plugin_library.reporters,
        }.get(plugin_type)

    @staticmethod
    def _registered_classes(
        plugin_type: str,
        registration: AshPluginRegistration,
        imported_only: bool = False,
    ) -> List[type]:
        """The ``plugin_type`` classes in the module ``registration`` names.

        Every class there with that ``ash_plugin_type``, not only the registered
        one, which is how ``plugin_modules`` has always resolved a registration.
        With ``imported_only``, a module not yet imported gives none and nothing
        is imported: every class ``plugin_modules`` resolved came from a module it
        imported.
        """
        path = registration.plugin_module_path
        if imported_only:
            imported = sys.modules.get(path)
            if imported is None:
                return []
            module = imported
        else:
            try:
                # A package the loader refused is gone from sys.modules, so this
                # import runs its body and its decorators again, and the debug
                # line and the "already registered" warning they write name
                # its path under this reader's scope, which can be empty. They
                # are written under the names the registration was made under.
                with masked_module_names(registration._masked_forms):
                    # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
                    module = importlib.import_module(path)
            except ImportError as e:
                ASH_LOGGER.warning(
                    registration.hide_masked_modules(
                        f"Failed to import plugin module {path}: {e}"
                    )
                )
                return []
        found: List[type] = []
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and hasattr(attr, "ash_plugin_type")
                and attr.ash_plugin_type == plugin_type
                and attr not in found
            ):
                found.append(attr)
        return found

    def filter_plugin_modules(self, items: List, callback: Callable, *args, **kwargs):
        filtered = []
        for item in items:
            if callback(item, *args, **kwargs):
                filtered.append(item)
        return filtered

    def plugin_modules(
        self,
        plugin_type: Literal["converter", "scanner", "reporter"],
        filter_callback: Callable = lambda x: True,
        *args,
        **kwargs,
    ):
        """Get plugin modules of a specific type.

        The resolved class list is memoised per kind together with the
        registrations it came from, and reused only while those are unchanged,
        so a config that loads more plugin modules later (``ash report`` with
        ``ash_plugin_modules``, or a later request to a long-lived MCP server)
        gets a list with them.

        The registrations are copied under ``_registry_lock`` and the loop runs
        over the copy. A module registered by another thread while this one
        imports (workspace mode) cannot change the dict being iterated; it is
        picked up by the next resolution.

        Args:
            plugin_type: The type of plugin to get (IConverter, IScanner, IReporter)
            filter_callback: Optional callback to filter plugins

        Returns:
            List of plugin class implementations (not registration objects)
        """
        # Normalize plugin_type to a string key
        cache_key = plugin_type if isinstance(plugin_type, str) else None
        registrations = self._registrations(plugin_type) if cache_key else None
        if registrations is None:
            ASH_LOGGER.warning(f"Unknown plugin type: {plugin_type}")
            return []

        # Copied under the lock: another thread importing a plugin module registers
        # into this dict, and iterating it while that happens raises
        # "dictionary changed size during iteration".
        with self._registry_lock:
            registered = list(registrations.items())
        resolved_from = tuple(
            (name, registration.plugin_module_path, registration.enabled)
            for name, registration in registered
        )
        cached = self._resolved_plugins.get(cache_key)
        if cached is not None and cached.registrations == resolved_from:
            return self.filter_plugin_modules(
                cached.classes, filter_callback, *args, **kwargs
            )

        plugins: List[type] = []
        for _name, registration in registered:
            if not registration.enabled:
                continue
            try:
                # Under the names the registration was made under, as in
                # _registered_classes: a refused package's decorators run again
                # in this import and write its path under the reader's scope.
                with masked_module_names(registration._masked_forms):
                    # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
                    module = importlib.import_module(registration.plugin_module_path)
                # Find the plugin classes in the module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and getattr(attr, "ash_plugin_type", None) == plugin_type
                        and attr not in plugins  # Avoid duplicates
                    ):
                        plugins.append(attr)
            except ImportError as e:
                ASH_LOGGER.warning(
                    registration.hide_masked_modules(
                        f"Failed to import plugin module {registration.plugin_module_path}: {e}"
                    )
                )

        # Memoise the unfiltered result, keyed by the registrations it came from,
        # so repeat calls skip the import work until something new registers
        self._resolved_plugins[cache_key] = _Resolution(resolved_from, plugins)

        # Apply filter callback
        return self.filter_plugin_modules(plugins, filter_callback, *args, **kwargs)


#: The module attributes that list a plugin package's classes.
_PLUGIN_LISTS = ("ASH_SCANNERS", "ASH_REPORTERS", "ASH_CONVERTERS")


def _named_module_provides(module_names: Set[str], cls: type) -> bool:
    """Whether one of ``module_names`` defines ``cls``, or has it or lists it.

    Defines it: the name is ``cls.__module__`` or a package around it. Has it: an
    imported module of that name has it as the attribute of its name. Lists it:
    that module's ``ASH_SCANNERS``, ``ASH_REPORTERS`` or ``ASH_CONVERTERS``
    includes it.
    """
    defined_in = getattr(cls, "__module__", "") or ""
    for name in module_names:
        if defined_in == name or defined_in.startswith(name + "."):
            return True
        imported = sys.modules.get(name)
        if imported is None:
            continue
        if getattr(imported, getattr(cls, "__name__", ""), None) is cls:
            return True
        for attribute in _PLUGIN_LISTS:
            if any(entry is cls for entry in getattr(imported, attribute, None) or []):
                return True
    return False
