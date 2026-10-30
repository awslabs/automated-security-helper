# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reporter and scanner options only the operator's own configuration may set.

aws-security-hub's ``findings_scope`` decides which findings in the operator's
account a scan updates and archives, and ``archive_resolved_findings`` whether it
archives the ones the scan no longer reports. A config file inside the scanned
tree was written by the repository under scan: a pull request that deletes files
and sets ``archive_resolved_findings: true`` in ``.ash/.ash.yaml`` archived that
scope's findings in the operator's account, with the operator's credentials.

So what a config file inside the scanned tree writes for one of these options
(``config/sandbox_grants.files_inside`` decides which files those are, as it does
for the sandbox grants and ``ash_plugin_modules``) is left out of the
configuration as the chain is read, before anything is validated
(``RepositorySettings``): a value the option would refuse does not make the
configuration unloadable, and the warning is the same for any value. The option
then has the value the rest of the chain gives it, where a file outside the tree
sets it (the operator's file, which may ``extends`` the repository's), and
otherwise the operator's: ``--config-overrides``, or the trusted base the other
confinements use (the defaults, ASH_CONFIG's file, or the operator's config file
outside the tree). Where that is not what the repository's file wrote, one
warning names the option and the chain's files inside the tree, the one that
wrote it among them. A ``findings_scope`` left
unset makes the reporter refuse before any AWS call; an unset
``archive_resolved_findings`` is False.

Which file set an option is read from each file's own document, never from the
merged configuration, which cannot tell the operator's file from the one it
extends, or a value a file set from one an override round-trip validated.

The loads that know the scanned tree leave these values out: resolve_config,
``ash config validate``'s check of a file, and the scan's read of its exit-code
fields. That includes their load of the file ASH_CONFIG names
(get_default_config), which a scan reads first and which is its configuration
when no config file is selected: a file of that chain inside the tree has these
values left out as it is read, once, so what is recorded as left out is what the
configuration was built without. A command that loads the ASH_CONFIG file
without a scanned tree (the MCP server's defaults, ``ash scanners``) reads it
whole, as the operator's.

``ash merge`` builds its reporters from the configuration the shards recorded,
which a file in each shard's scanned repository could have written, so it drops
these options from that configuration (``drop_recorded_operator_only_options``).

Off-host reporters
------------------
The same holds for every reporter that sends findings off the host
(``ReporterPluginBase.sends_off_host``: the four AWS reporters, or any plugin's),
and for its whole section: whether it runs, and where it sends (a bucket and key
prefix, a log group and stream, a model, a Region, a profile). A repository's own
``.ash/.ash.yaml`` that named the AWS plugins and enabled S3 with its own bucket
made a scan of it upload the findings there with the host's credentials; so did a
config an MCP client uploaded.

The set is the reporter classes that declare ``sends_off_host``, not a list kept
here, so a plugin's off-host reporter is covered too; which of its options name a
destination cannot be listed for it, so none of its section is taken from the
repository. ``resolve_config`` records on a config built from such a file the
configuration as the operator set it (``record_operator_reporters``): the trusted
base with the operator's ``reporters`` overrides applied. ``reporter_section``
then gives an off-host reporter its section from that record, and every other
reporter its section as resolved. The report phase, ``ash report`` and
``ash merge`` read reporter sections through it.

Scanner options
---------------
A scanner option that bounds what a scan may cost the host is the operator's too
(``OPERATOR_ONLY_SCANNER_OPTIONS``). detect-secrets' ``max_worker_output_mib`` is
how much of its worker's output file ASH reads back, at most 4096 MiB, and the
read holds about three times the file's size in memory. Each is confined as the
reporter options are. ``ash merge`` runs no scanner, so the shards' recorded
configuration keeps them.
"""

from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path, PurePath
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    Collection,
    Dict,
    List,
    Literal,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from pydantic import TypeAdapter

from automated_security_helper.config.config_sources import resolve_override_segment
from automated_security_helper.config.confinement_remedy import (
    KEEP_A_SETTING,
    KEEP_A_SETTING_BESIDE_A_LOCATED_FILE,
    LET_THE_WALK_FINISH,
)
from automated_security_helper.config.plugin_section_names import (
    declared_section_names,
    folded_section_name,
)
from automated_security_helper.config.sandbox_grants import (
    checkout_judgment,
    confined_files,
    confinement_membership,
    described,
)
from automated_security_helper.utils.error_text import config_environment_values
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.terminal_text import shown_on_one_line

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.environment_record import (
        EnvironmentReference,
    )

#: Reporter section name -> the options in it only the operator may set.
OPERATOR_ONLY_OPTIONS: Dict[str, Tuple[str, ...]] = {
    "aws-security-hub": ("findings_scope", "archive_resolved_findings"),
}

#: Scanner section name -> the options in it only the operator may set. Each
#: section is a declared scanner's (``ScannerConfigSegment``), whose spellings
#: are folded into it at load, so the scanner reads that one section.
OPERATOR_ONLY_SCANNER_OPTIONS: Dict[str, Tuple[str, ...]] = {
    "detect-secrets": ("max_worker_output_mib",),
}

#: (reporter section name, option) -> the value the option has where no section
#: sets it, for the options in OPERATOR_ONLY_OPTIONS. Listed here because the
#: reporters' models are in a plugin package this module does not import; a unit
#: test holds each value equal to the reporter's options model. A repository
#: file that writes the value an unset option already has changes nothing, so
#: the settle step does not report it as ignored.
OPERATOR_ONLY_DEFAULTS: Dict[Tuple[str, str], Any] = {
    ("aws-security-hub", "findings_scope"): None,
    ("aws-security-hub", "archive_resolved_findings"): False,
}

_MISSING = object()


def _sections(config: "AshConfig", reporter: str) -> List[Tuple[str, Dict[str, Any]]]:
    """Every reporters section ``get_plugin_config`` can read as *reporter*'s.

    Any spelling the lookup accepts (``aws_security_hub``, ``AwsSecurityHub``)
    reaches the reporter, so each is confined, not only the one it reads first.
    """
    extra = getattr(config.reporters, "__pydantic_extra__", None) or {}
    return _sections_in(extra, reporter)


def _sections_in(
    reporters: Dict[str, Any], reporter: str
) -> List[Tuple[str, Dict[str, Any]]]:
    """The sections of *reporters*, a key-to-section mapping, read as *reporter*'s."""
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )

    wanted = reduced_plugin_name(reporter)
    # A key that is not a string (a YAML `1:` under reporters in a file the
    # repository wrote) is no spelling of any reporter: skipped, where the name
    # lookup would raise and abort a scan that should only skip the file.
    return [
        (key, section)
        for key, section in reporters.items()
        if isinstance(key, str)
        and isinstance(section, dict)
        and (key == reporter or wanted in plugin_key_lookup_names(key))
    ]


def _set_by_override(
    reporters: Dict[str, Any],
    section_key: str,
    option: str,
    config_overrides: Optional[Sequence[str]],
    *,
    kind: str = "reporters",
    environment_values: Sequence[str] = (),
) -> bool:
    """Whether an override writes ``<kind>.<section_key>.options.<option>``.

    *reporters* is the resolved config's sections of *kind*, ``reporters`` or
    ``scanners``. An override of the section, its options, or all of *kind*
    writes it too. Each segment of the override's key is resolved as
    ``apply_config_overrides`` resolves it (``resolve_override_segment``: the key
    as written if the config has it, else its other '-'/'_' spelling, else a
    spelling of a declared plugin's section folded to that section), against the
    keys of *reporters*, the resolved config's sections. One resolver for the
    apply and this gate, so a respelled override that applies is one the gate
    counted. Treating the two spellings as one key whenever they compared equal
    counted an override that wrote an empty decoy section, ``aws_security_hub``,
    as an override of the ``aws-security-hub`` section next to it, which the
    scan reads. The key is not stripped either: the override is applied to the
    key exactly as written.
    """
    section = reporters.get(section_key)
    options = section.get("options") if isinstance(section, dict) else None
    containers: List[Dict[str, Any]] = [
        {kind: reporters},
        reporters,
        section if isinstance(section, dict) else {},
        options if isinstance(options, dict) else {},
    ]
    parents = [None, kind, section_key, "options"]
    target = [kind, section_key, "options", option]
    for override in config_overrides or []:
        key_path = override.partition("=")[0].removesuffix("+")
        parts = key_path.split(".")
        if not parts or len(parts) > len(target):
            continue
        if all(
            resolve_override_segment(container, parent, part, environment_values)
            == want
            for container, parent, part, want in zip(containers, parents, parts, target)
        ):
            return True
    return False


#: An operator-only option confinement gave the trusted base's value (or left
#: unset where that base has none): ``(kind, plugin, option)``, kind
#: ``"reporters"`` or ``"scanners"``.
SettledOption = Tuple[str, str, str]


def _locations(
    config: "AshConfig",
) -> List[Tuple[SettledOption, Tuple[str, str, str, str]]]:
    """Each operator-only option, and where *config*'s dump holds it:
    ``("reporters", section key, "options", option)`` for each section any
    spelling of the reporter's name reaches, and ``("scanners", scanner,
    "options", option)``."""
    return [
        (("reporters", reporter, option), ("reporters", key, "options", option))
        for reporter, names in OPERATOR_ONLY_OPTIONS.items()
        for key, _ in _sections(config, reporter)
        for option in names
    ] + [
        (("scanners", scanner, option), ("scanners", scanner, "options", option))
        for scanner, names in OPERATOR_ONLY_SCANNER_OPTIONS.items()
        for option in names
    ]


def operator_only_locations(config: "AshConfig") -> List[Tuple[str, str, str, str]]:
    """Where *config*'s dump holds an option in OPERATOR_ONLY_OPTIONS or
    OPERATOR_ONLY_SCANNER_OPTIONS (``_locations``)."""
    return [location for _option, location in _locations(config)]


def settled_locations(
    config: "AshConfig", settled: Collection[SettledOption]
) -> List[Tuple[str, str, str, str]]:
    """Where *config*'s dump holds each option *settled* names. Each config is
    read by its own spellings, so the trusted base's references to a settled
    option are found under its keys and the resolved config's under its own."""
    return [location for option, location in _locations(config) if option in settled]


def _scanner_options(config: "AshConfig", scanner: str) -> Any:
    """The options model of the declared scanner section *scanner* names, or None.

    The section is a typed model on ``config.scanners``, and every other
    spelling of its key was folded into it at load, so it is the one the scanner
    reads.
    """
    segment = config.scanners
    for name, field in type(segment).model_fields.items():
        if scanner in (name, field.alias):
            return getattr(getattr(segment, name, None), "options", None)
    return None


def _as_the_model_reads(options: Any, option: str, value: Any) -> Any:
    """*value*, the raw text or number a file wrote for *option*, as the
    scanner's options model reads it (``"256"`` is 256), so it is compared with
    the typed value the trusted base holds. A value the model refuses is
    returned as written: it is not the trusted base's."""
    try:
        return getattr(type(options).model_validate({option: value}), option)
    except (AttributeError, TypeError, ValueError):
        return value


def _differs(value: Any, operator: Any, default: Any = _MISSING) -> bool:
    """Whether the scan uses a value other than *value*, which the repository's
    files wrote. *operator* is the trusted base's value; where the base has
    none (``_MISSING``) the option is unset, and unset is *default* when the
    option has a known one."""
    if operator is _MISSING:
        return default is _MISSING or value != default
    return value != operator


def _scanner_sections_in(
    scanners: Dict[str, Any], scanner: str
) -> List[Tuple[str, Dict[str, Any]]]:
    """The sections of *scanners*, a document's ``scanners`` mapping, the model
    reads as the declared scanner section *scanner*: that key, or a spelling
    that folds to it (``plugin_section_names``). A spelling that does not fold
    is a section of its own, which the scanner never reads."""
    declared = declared_section_names("scanners")
    return [
        (key, section)
        for key, section in scanners.items()
        if isinstance(key, str)
        and isinstance(section, dict)
        and (key == scanner or declared.get(folded_section_name(key)) == scanner)
    ]


#: Each kind of plugin section with options only the operator may set: the
#: listed options, and how a document's sections are read as a plugin's.
_CONFINED_KINDS = (
    ("scanners", OPERATOR_ONLY_SCANNER_OPTIONS, _scanner_sections_in),
    ("reporters", OPERATOR_ONLY_OPTIONS, _sections_in),
)


def _client_delivered(path: Path) -> bool:
    """Whether *path* is a file an MCP client delivered, as named and as resolved
    (``cli/mcp/sandbox.config_is_client_supplied``). Imported when called: that
    module imports the config package."""
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    return config_is_client_supplied(path)


def found_place(entry: Tuple[str, str, str, str, Any]) -> str:
    """The place string of a ``RepositorySettings.found`` entry; never its value."""
    kind, _plugin, key, option, _value = entry
    return f"{kind}.{key}.options.{option}"


class RepositorySettings:
    """What the files the scanned repository could write set for the
    operator-only options, left out of the configuration as its chain is read.

    ``confine`` is ``resolve_config_document``'s hook. For a file of the chain
    that is the repository's (inside the scanned tree by its resolved path or
    the name that reached it, ``sandbox_grants.files_inside``; one an MCP client
    delivered, wherever it sits; inside any checkout, with ``any_checkout`` (on
    by default); or every file, with ``every_file``, for a config an MCP client
    supplied), it gives back the
    document the file resolved to without any option in OPERATOR_ONLY_OPTIONS
    or OPERATOR_ONLY_SCANNER_OPTIONS, under any section spelling the
    configuration reads as that plugin's, and records what it left out. The
    document a file resolved to holds what its own bases set and what its
    ``patch`` wrote, so those are left out too. Every value is left out, one
    the option's model would refuse included, so what the repository writes for
    these options never makes its configuration unloadable.

    ``document`` is the last document the hook gave back: the chain's root,
    the merged document the configuration is validated from, since
    resolve_config_document hands each file to the hook after its bases. So an
    instance records one chain read once: every caller builds its own for the
    chain it reads (resolve_config one for the selected file and one for the
    ASH_CONFIG file, ``ash config validate`` one for the checked file, MCP
    get_config one for what a file's chain wrote), and one used for a second
    chain would mix the two chains' records and keep the second's root.
    """

    def __init__(
        self,
        trees: Sequence[Path],
        every_file: bool = False,
        any_checkout: bool = True,
    ) -> None:
        self.trees = list(trees)
        self.every_file = every_file
        #: Also treat a chain file inside ANY checkout as the repository's
        #: (``sandbox_grants.in_a_checkout``), not only one inside *trees*. On
        #: by default: a file in a checkout other than the scanned one is never
        #: the operator's, for these options as for the sandbox grants, so a
        #: loader that builds its settings from the trees alone reads the same
        #: file as the scan does. ``scan_repository_settings`` is the named
        #: constructor of that membership; False asks for the trees alone.
        self.any_checkout = any_checkout
        #: (kind, plugin, section key, option, value) for each option a file of
        #: the repository wrote, in the order the chain resolved its files: the
        #: last for an option is what the repository's files merged it to.
        self.found: List[Tuple[str, str, str, str, Any]] = []
        #: The chain's files that are the repository's, resolved, whether or not
        #: they wrote any of these options.
        self.repository_files: List[Path] = []
        #: The places (``found_place``) an option was left out of whose file is
        #: the repository's only because resolving its name stopped before the
        #: walk finished, so a sentence naming them cannot claim a location. A
        #: place a file with an established location also left out is not one.
        self.undecided_places: Set[str] = set()
        #: The places a file with an established location left an option out of.
        self._located_places: Set[str] = set()
        self.document: Any = None

    def _membership(self, real: Path, named: Path) -> Tuple[bool, bool]:
        """Whether the file is the repository's, and whether that rests on a
        link walk that never finished (the fail-closed answer, undecided)."""
        if self.every_file:
            return True, False
        confined = confined_files([real], self.trees, [named])
        if confined.members:
            # A walk that stopped makes the file undecided only when the resolved
            # path is not itself a member by where it is.
            real_decided = real in confined.members and real not in confined.undecided
            return True, bool(confined.undecided) and not real_decided
        # A file an MCP client delivered is the client's wherever it sits, in a
        # checkout or not: the same delivery judgment the rest of the chain's
        # membership uses (resolve_config._delivered_by_a_client).
        if _client_delivered(real) or _client_delivered(named):
            return True, False
        if not self.any_checkout:
            return False, False
        for path in (real, named):
            judgment = checkout_judgment(path)
            if judgment.verdict:
                return True, not judgment.decided
        return False, False

    def is_repository_file(self, real: Path, named: Path) -> bool:
        return self._membership(real, named)[0]

    def confine(self, real: Path, named: Path, data: Any) -> Any:
        member, undecided = self._membership(real, named)
        if member:
            self.repository_files.append(real)
            first = len(self.found)
            data = self._without_operator_only(data)
            places = {found_place(entry) for entry in self.found[first:]}
            if undecided:
                self.undecided_places.update(places - self._located_places)
            else:
                self._located_places.update(places)
                self.undecided_places.difference_update(places)
        self.document = data
        return data

    def _without_operator_only(self, data: Any) -> Any:
        """A copy of *data* without the operator-only options, each recorded;
        *data* itself when it has none."""
        if not isinstance(data, dict):
            return data
        places = [
            (kind, plugin, key, option)
            for kind, listed, sections_of in _CONFINED_KINDS
            if isinstance(data.get(kind), dict)
            for plugin, names in listed.items()
            for key, section in sections_of(data[kind], plugin)
            if isinstance(section.get("options"), dict)
            for option in names
            if option in section["options"]
        ]
        if not places:
            return data
        stripped = copy.deepcopy(data)
        # A YAML anchor can make two sections, or two sections' options, ONE
        # mapping, and deepcopy keeps that sharing in the copy, so the second
        # section's pop would raise KeyError on the mapping the first already
        # popped -- an operator-only write must never make the file
        # unloadable. Give each confined section its own mapping first: each
        # place then pops its own copy and records its own value, exactly as
        # the alias-free spelling of the same document does.
        for kind, key in {(kind, key) for kind, _plugin, key, _option in places}:
            section = dict(stripped[kind][key])
            section["options"] = dict(section["options"])
            stripped[kind][key] = section
        for kind, plugin, key, option in places:
            value = stripped[kind][key]["options"].pop(option)
            self.found.append((kind, plugin, key, option, value))
        return stripped

    def written(self, kind: str) -> Dict[Tuple[str, str, str], Any]:
        """By (plugin, section key, option) of *kind*: the value the
        repository's files merged it to. A scanner's spellings are one section
        (the model folds them), keyed by the plugin's name; a reporter's are
        each their own key, as the configuration keeps them."""
        by_place: Dict[Tuple[str, str, str], Any] = {}
        for found_kind, plugin, key, option, value in self.found:
            if found_kind == kind:
                by_place[(plugin, plugin if kind == "scanners" else key, option)] = (
                    value
                )
        return by_place

    def ignored_against(self, trusted: "AshConfig") -> List[str]:
        """The options the repository's files wrote a value for that *trusted*
        does not hold: what a scan whose trusted base is *trusted* reports
        ignored, an override or another file of the chain aside. A scanner
        option is named by its scanner, a reporter option by the section key
        the file wrote."""
        places: List[str] = []
        for (scanner, _key, option), value in self.written("scanners").items():
            options = _scanner_options(trusted, scanner)
            if options is not None and _differs(
                _as_the_model_reads(options, option, value),
                getattr(options, option),
            ):
                places.append(f"scanners.{scanner}.options.{option}")
        for (reporter, key, option), value in self.written("reporters").items():
            operator = _trusted_value(trusted, key, option)
            default = OPERATOR_ONLY_DEFAULTS.get((reporter, option), _MISSING)
            if _differs(value, operator, default):
                places.append(f"reporters.{key}.options.{option}")
        return places

    def set_elsewhere(self, kind: str, plugin: str, option: str) -> bool:
        """Whether a file of the chain other than the repository's sets the
        option: the merged document still holds it, under any of the plugin's
        section spellings."""
        return self.elsewhere_value(kind, plugin, option) is not _MISSING

    def elsewhere_value(self, kind: str, plugin: str, option: str) -> Any:
        """The value a file of the chain other than the repository's set the
        option to (the merged document's, under any of the plugin's section
        spellings; the last section read wins), or ``_MISSING``. The settle
        writes this value back: the configuration may hold another by the time
        it runs (an override applied to the model before the confinement), and
        skipping the option because a file outside the tree set it kept that
        other value instead of the file's."""
        sections = self.document.get(kind) if isinstance(self.document, dict) else None
        if not isinstance(sections, dict):
            return _MISSING
        sections_of = _scanner_sections_in if kind == "scanners" else _sections_in
        value: Any = _MISSING
        for _key, section in sections_of(sections, plugin):
            options = section.get("options")
            if isinstance(options, dict) and option in options:
                value = options[option]
        return value


class _Settling(NamedTuple):
    """An operator-only option a file of the repository wrote that neither an
    override nor a file outside the tree keeps: it takes the trusted base's
    value."""

    kind: str
    plugin: str
    #: The section key: the scanner's name, or the reporter section the file
    #: wrote.
    key: str
    option: str
    #: What the repository's files merged it to.
    value: Any
    #: The trusted base's value, or _MISSING where it has none; the value a
    #: file outside the tree wrote where ``from_elsewhere`` is set.
    operator: Any
    #: What the option is where nothing sets it, or _MISSING where not known.
    default: Any = _MISSING
    #: Set when a file outside the tree wrote the option: ``operator`` is that
    #: file's value, which the configuration takes as the operator's own, and
    #: the option is neither settled to the trusted base nor reported.
    from_elsewhere: bool = False

    @property
    def place(self) -> str:
        return f"{self.kind}.{self.key}.options.{self.option}"

    @property
    def ignored(self) -> bool:
        """Whether the value the scan uses is not the one the files wrote."""
        if self.from_elsewhere:
            return False
        return _differs(self.value, self.operator, self.default)


def scan_repository_settings(
    trees: Sequence[Path],
    every_file: bool = False,
) -> RepositorySettings:
    """The ONE RepositorySettings every loader of a scan's chain confines with.

    A chain file is the repository's when it sits inside *trees*, inside ANY
    git checkout, or when an MCP client delivered it; with *every_file* every
    file is. A config file in a checkout other than the scanned one is never
    the operator's, so the options only the operator sets are left out of it
    wherever the chain is read: a local scan, container mode, the workspace
    loader, the container's sandbox-mode floor, the trusted base,
    the validator's ASH_CONFIG check and MCP ``get_config``. One constructor,
    so those reads cannot disagree on which files count as a repository's;
    ``RepositorySettings`` itself defaults to the same membership, so a loader
    that builds it by hand from the trees alone gets it too.
    """
    return RepositorySettings(trees, every_file=every_file, any_checkout=True)


def repository_settings_for_root(
    root: Optional[Path],
    every_file: bool = False,
) -> RepositorySettings:
    """The settings a load confines with for *root*, the scanned root.

    With a root, its scanned trees and every checkout. With none -- the
    working directory was deleted while the process runs
    (``sandbox_grants.working_directory``) -- no tree is known, so only the
    checkout rule applies: a load that cannot tell whose tree it serves must
    not apply what a checkout's file wrote for the operator-only options; the
    cost is an operator whose own config sits in a checkout losing them while
    the working directory is deleted, the direction a scan of that checkout
    takes anyway.
    """
    from automated_security_helper.config.sandbox_grants import scanned_trees

    return scan_repository_settings(
        [] if root is None else scanned_trees(root), every_file=every_file
    )


def _environment_values_of(
    config: "AshConfig", trusted: "AshConfig"
) -> Tuple[str, ...]:
    # For the resolver's refusal text: a section key either config read from
    # the environment is a value, redacted where the refusal is raised.
    return (*config_environment_values(config), *config_environment_values(trusted))


#: One place of a joined list of place strings: its kind and ``.``, its key, and
#: the ``.options.<option>`` that follows the key of an option's place.
_PLACE_SHAPE = re.compile(
    r"(?:^|(?<=, ))(?P<kind>(?:reporters|scanners)\.)"
    r"(?P<key>.*?)"
    r"(?P<option>\.options\.[^.,\s]+)?"
    r"(?=, (?:reporters|scanners)\.|\Z)",
    re.DOTALL,
)


def redacted_places(text: str, key_values: Collection[str]) -> str:
    """*text*, a joined list of place strings, with every env-read KEY in
    *key_values* hidden in both its separator spellings.

    The ONE redaction for every warning that prints place strings (the settle
    warnings here and resolve_config's fail-closed warning), so the two
    voices cannot disagree on what a place shows. Keys only, at a
    one-character minimum: a place string is built from mapping keys alone,
    so a read VALUE cannot appear in one, and redacting against values hid
    parts of fixed option names. Both spellings, since the found record folds
    "-" and "_" and a place can print either.

    Only the key of each place is searched (``reporters.<key>.options.<option>``
    or ``reporters.<key>``): the kind, ``options`` and the option's name are
    fixed words, so a short key read from the environment elsewhere in the
    configuration does not hide them. Text that is not in that shape is
    searched whole."""
    from automated_security_helper.config.config_validator import redact_values

    values = tuple(
        dict.fromkeys(
            spelling
            for value in key_values
            if value
            for spelling in (
                value,
                value.replace("-", "_"),
                value.replace("_", "-"),
            )
        )
    )

    def hidden(piece: str) -> str:
        return redact_values(piece, values, min_length=1) if piece else piece

    parts: List[str] = []
    position = 0
    for place in _PLACE_SHAPE.finditer(text):
        parts.append(hidden(text[position : place.start()]))
        parts.append(place["kind"])
        parts.append(hidden(place["key"]))
        parts.append(place["option"] or "")
        position = place.end()
    parts.append(hidden(text[position:]))
    return "".join(parts)


def _scanner_options_to_settle(
    config: "AshConfig",
    trusted: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    repository: RepositorySettings,
) -> List[_Settling]:
    """The options in OPERATOR_ONLY_SCANNER_OPTIONS a file of the repository
    wrote that take the trusted base's value: neither an override, which is
    the operator's, nor a file outside the tree sets them. One a file outside
    the tree set is listed too, ``from_elsewhere``, with that file's value, for
    ``_confine_scanner_options`` to write back. Changes nothing: ``ash config
    validate`` reads the list through ``ignored_operator_only_options``."""
    found: List[_Settling] = []
    sections = config.scanners.model_dump(by_alias=True)
    environment_values = _environment_values_of(config, trusted)
    for (scanner, _key, option), value in repository.written("scanners").items():
        options = _scanner_options(config, scanner)
        operator_options = _scanner_options(trusted, scanner)
        if options is None or operator_options is None:
            continue
        if _set_by_override(
            sections,
            scanner,
            option,
            config_overrides,
            kind="scanners",
            environment_values=environment_values,
        ):
            continue
        elsewhere = repository.elsewhere_value("scanners", scanner, option)
        if elsewhere is not _MISSING:
            # A file outside the tree set it: that file's value holds, not
            # whatever the configuration holds by now (an override applied to
            # the model before the confinement).
            found.append(
                _Settling(
                    "scanners",
                    scanner,
                    scanner,
                    option,
                    value,
                    elsewhere,
                    from_elsewhere=True,
                )
            )
            continue
        found.append(
            _Settling(
                "scanners",
                scanner,
                scanner,
                option,
                _as_the_model_reads(operator_options, option, value),
                getattr(operator_options, option),
            )
        )
    return found


def _reporter_options_to_settle(
    config: "AshConfig",
    trusted: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    repository: RepositorySettings,
) -> List[_Settling]:
    """The same for OPERATOR_ONLY_OPTIONS, in its reporters' order."""
    found: List[_Settling] = []
    reporters = getattr(config.reporters, "__pydantic_extra__", None) or {}
    environment_values = _environment_values_of(config, trusted)
    written = repository.written("reporters")
    for reporter in OPERATOR_ONLY_OPTIONS:
        for (plugin, key, option), value in written.items():
            if plugin != reporter:
                continue
            if _set_by_override(
                reporters,
                key,
                option,
                config_overrides,
                environment_values=environment_values,
            ):
                continue
            if repository.set_elsewhere("reporters", reporter, option):
                continue
            found.append(
                _Settling(
                    "reporters",
                    reporter,
                    key,
                    option,
                    value,
                    _trusted_value(trusted, key, option),
                    OPERATOR_ONLY_DEFAULTS.get((reporter, option), _MISSING),
                )
            )
    return found


def ignored_operator_only_options(
    config: "AshConfig",
    trusted: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    repository: RepositorySettings,
) -> List[str]:
    """The options a scan's warning names as ignored: each the repository's
    files wrote that takes a trusted base's value other than the one written
    (confine_operator_only_options). For ``ash config validate``, which judges
    a file against the same trusted base, overrides and chain as a scan does.
    Changes nothing."""
    return [
        settling.place
        for settling in (
            *_scanner_options_to_settle(config, trusted, config_overrides, repository),
            *_reporter_options_to_settle(config, trusted, config_overrides, repository),
        )
        if settling.ignored
    ]


def _confine_scanner_options(
    config: "AshConfig",
    trusted: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    repository: RepositorySettings,
    settled: Optional[Set[SettledOption]] = None,
) -> List[_Settling]:
    """Settle each option in OPERATOR_ONLY_SCANNER_OPTIONS for a configuration
    the repository's files are part of; return the ones a file of the
    repository wrote a value for that is not the one kept.

    The option keeps an override's value, which is the operator's, and the
    value a file outside the tree gives it; otherwise it takes the trusted
    base's, and is added to *settled* -- whether or not a repository file
    wrote it. A scanner option bounds what a scan may cost the host, so the
    operator's own bound binds a repository that says nothing too: a lower
    limit the trusted base sets would otherwise come back as the default.
    Only a value the repository wrote, and that is not kept, is reported.
    """
    if settled is None:
        settled = set()
    replaced: List[_Settling] = []
    for settling in _scanner_options_to_settle(
        config, trusted, config_overrides, repository
    ):
        options = _scanner_options(config, settling.plugin)
        _set_scanner_option(options, settling.option, settling.operator)
        if settling.from_elsewhere:
            # A file outside the tree set it: its value is written back, and
            # the option is neither the trusted base's nor reported.
            continue
        settled.add(("scanners", settling.plugin, settling.option))
        if settling.ignored:
            replaced.append(settling)
    sections = config.scanners.model_dump(by_alias=True)
    environment_values = _environment_values_of(config, trusted)
    repository_wrote = {
        (plugin, option) for (plugin, _key, option) in repository.written("scanners")
    }
    for scanner, names in OPERATOR_ONLY_SCANNER_OPTIONS.items():
        options = _scanner_options(config, scanner)
        operator_options = _scanner_options(trusted, scanner)
        if options is None or operator_options is None:
            continue
        for option in names:
            if (scanner, option) in repository_wrote:
                # Written by a repository file: settled above, or kept there
                # by an override or a file outside the tree.
                continue
            if _set_by_override(
                sections,
                scanner,
                option,
                config_overrides,
                kind="scanners",
                environment_values=environment_values,
            ):
                continue
            elsewhere = repository.elsewhere_value("scanners", scanner, option)
            if elsewhere is not _MISSING:
                # A file outside the tree set it: that file's value holds, not
                # whatever the configuration holds by now.
                _set_scanner_option(options, option, elsewhere)
                continue
            _set_scanner_option(options, option, getattr(operator_options, option))
            settled.add(("scanners", scanner, option))
    return replaced


def _set_scanner_option(options: Any, option: str, value: Any) -> None:
    """Set ``options.option`` to ``value`` as the options model reads it, when
    it differs from what the model holds.

    A value a file outside the tree wrote is the document's: an environment
    reference (``!ENV``, ``${VAR}``) is a string there where the model holds a
    number, so compared raw it always differed and was stored as a string. The
    value is read through the option's own field first (lax, as a plugin's
    options are read at load; the field's annotation with its constraints), so
    what is stored is the model's type and the comparison is like with like.
    The one field, not the whole model: validating ``{option: value}`` as a
    model raised for any options model with another required field, or a
    model validator reading several fields, on a value the field accepts. The
    trusted base's value is the model's already. A name the model declares no
    field for is set as given.
    """
    field = type(options).model_fields.get(option)
    if field is None:
        typed = value
    else:
        annotation: Any = field.annotation
        if field.metadata:
            annotation = Annotated[(annotation, *field.metadata)]
        typed = TypeAdapter(annotation).validate_python(value)
    if getattr(options, option) != typed:
        setattr(options, option, typed)


def _trusted_value(trusted: "AshConfig", section_key: str, option: str) -> Any:
    section = trusted.get_plugin_config(plugin_type="reporter", plugin_name=section_key)
    options = section.get("options") if isinstance(section, dict) else None
    if isinstance(options, dict) and option in options:
        return options[option]
    return _MISSING


def confine_operator_only_options(
    config: "AshConfig",
    trusted: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
    operator_record: Optional["AshConfig"] = None,
    environment_paths: Collection[Path] = frozenset(),
    repository: Optional[RepositorySettings] = None,
    *,
    # The four wording flags carry no defaults, as confine_plugin_modules'
    # do not: a default is a guess about the caller's membership, and every
    # caller stating them feeds the three warning voices the same values.
    checkout_membership: bool,
    client_supplied: bool = False,
    mixed_membership: bool,
    given_root_membership: bool,
    undecided_membership: bool,
    outside_membership: bool = False,
) -> Set[SettledOption]:
    """Settle the options in OPERATOR_ONLY_OPTIONS and
    OPERATOR_ONLY_SCANNER_OPTIONS that the repository's files wrote; return
    the ones that took the trusted base's value.

    Each option one of them wrote keeps an override's value, which is the
    operator's, or the value a file outside the tree gives it; otherwise it
    takes the trusted base's, and is left unset where that base has none.
    Where that is not what the repository's files wrote, one warning names the
    option and the repository's files of the chain it came through.

    The options returned are the only ones whose value is now the trusted
    base's, so they are the only ones whose references resolve_config takes
    from that base (``_take_confined_references``). An option kept, or one no
    file of the repository wrote, keeps the references the configuration's
    own files made.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted: The trusted base ``resolve_config`` built for the sandbox
            settings: the defaults, ASH_CONFIG's file, or the operator's config
            outside the tree.
        config_overrides: ``--config-overrides``. A value one of them writes is
            the operator's and is kept.
        in_tree: The config files inside the tree, named in the warning.
        operator_record: The configuration ``record_operator_reporters``
            records. Every reporter in OPERATOR_ONLY_OPTIONS sends findings off
            the host, so where its section, these options settled, still differs
            from the operator's, ``reporter_section`` ignores the rest of it as
            well. The one warning then names the section too, and
            ``reporter_section`` does not warn again.
        environment_paths: Those of *in_tree* the environment chose, named
            ``<value>`` (``sandbox_grants.described``).
        repository: What the repository's files wrote for these options, which
            ``config`` was built without (``RepositorySettings``). Without it
            nothing was recorded, and nothing is settled.
        checkout_membership: The *in_tree* files are in a checkout: the
            any-checkout rule added them (the caller knows no tree is
            scanned; trees may still resolve from its source directory), or
            the load has no tree at all and each file is there by the
            host's mark, which is the host's checkout verdict
            (``resolve_config``'s ``rootless_wording``). The warnings then
            explain the drop by the checkout rule -- the scanned-tree
            wording would contradict it. The plugin-module drop warning
            keys its own arms on its own judgment (root-based when a root is
            given), and agrees on the membership half of the sentence.
            These warnings are also the ONE
            voice on that path: the fail-closed ASH_CONFIG warning stays
            quiet where this settle step speaks (resolve_config's no-config
            branch).
        client_supplied: The *in_tree* files are there because the session's
            client supplied their content, not by any checkout or tree
            membership, so the warnings say so (``confinement_membership``).
        mixed_membership: *in_tree* holds files of BOTH memberships, so the
            warnings use the mixed sentence that names each file's own
            (``confinement_membership``).
        given_root_membership: The load declared no scanned tree but gave a
            root, and files_inside added the *in_tree* files against that
            root's trees, so the warnings speak the given root
            (``confinement_membership``): the scanned-tree wording would
            claim a tree the caller said does not exist, the same reason
            the plugin-module line speaks the given root there. Yields to
            every flag above.
        undecided_membership: Some of *in_tree* are there only because
            resolving their name stopped before the walk finished
            (``confined_files``'s or ``checkout_judgment``'s undecided
            answer), so the warnings say the walk stopped
            (``confinement_membership``) instead of stating a location it
            never established. Wording only; the settle itself is unchanged.
        outside_membership: Some of *in_tree* sit in a git checkout other
            than the scanned tree, on a load that has a scanned tree, or an
            MCP client delivered them (``resolve_config``'s outside files),
            so the warnings name every membership
            (``confinement_membership``). Wording only; the settle itself is
            unchanged.
    """
    if repository is None:
        # Nothing was recorded, so no option is known to be the repository's
        # and none is settled.
        return set()
    membership = confinement_membership(
        checkout_membership=checkout_membership,
        client_supplied=client_supplied,
        mixed=mixed_membership,
        given_root=given_root_membership,
        undecided=undecided_membership,
        outside=outside_membership,
    )

    def how_to_keep(what: str) -> str:
        # A file whose name walk stopped is not known to be in the tree, so "a
        # config file outside the tree" is no way to keep a setting from it
        # either: what keeps it is a walk that can finish. Beside a file that was
        # located, that one still moves out. Only ``mixed_membership`` says a
        # located file stands beside it, as ``_tier_two_source`` reads it: a file
        # that only the any-checkout walk could not place sets
        # ``outside_membership`` too, with nothing located beside it.
        if undecided_membership:
            if mixed_membership:
                return KEEP_A_SETTING_BESIDE_A_LOCATED_FILE
            return f"Set {what} with --config-overrides, or {LET_THE_WALK_FINISH}."
        # A file in another checkout is already outside the tree, so "a config
        # file outside the tree" is no way to keep a setting from it.
        if outside_membership:
            return KEEP_A_SETTING
        return f"Set {what} with --config-overrides or a config file outside the tree."

    def shown_places(text: str) -> str:
        # A section KEY an entry of the chain read from the environment IS
        # what the variable holds, so the place strings are redacted against
        # the KEY references of both configs' reads, each in the "-" and "_"
        # spellings the fold registers. Keys only: a place string is built
        # from mapping keys alone, so a read VALUE (a region, a partition
        # name) cannot appear in one, and redacting against values hid parts
        # of fixed option names -- an env-read "aws" turned
        # reporters.aws-security-hub into its redacted form. One place
        # redaction for every warning (redacted_places), so this voice and
        # the fail-closed one cannot disagree on what a place shows.
        return redacted_places(
            text,
            [
                reference.value
                for source in (config, trusted)
                for reference in getattr(source, "_environment_references", ())
                if getattr(reference, "key", False) and getattr(reference, "value", "")
            ],
        )

    settled: Set[SettledOption] = set()
    scanner_options = _confine_scanner_options(
        config, trusted, config_overrides, repository, settled
    )
    if scanner_options:
        # The paths are the repository's: the whole message is shown, once and on
        # one line, and not read as markup.
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"Ignoring {shown_places(', '.join(s.place for s in scanner_options))} from "
                f"{described(in_tree, environment_paths)}: {membership}, and "
                "this option bounds how much of a scanner's output ASH reads into "
                f"memory. {how_to_keep('it')}"
            ),
            extra=NO_MARKUP,
        )
    ignored: List[_Settling] = []
    whole_sections: List[str] = []
    to_settle = _reporter_options_to_settle(
        config, trusted, config_overrides, repository
    )
    for reporter in OPERATOR_ONLY_OPTIONS:
        dropped = len(ignored)
        for settling in to_settle:
            if settling.plugin != reporter:
                continue
            for section_key, section in _sections(config, reporter):
                options = section.get("options")
                if section_key != settling.key or not isinstance(options, dict):
                    continue
                if settling.operator is _MISSING:
                    options.pop(settling.option, None)
                else:
                    options[settling.option] = settling.operator
            settled.add(("reporters", reporter, settling.option))
            if settling.ignored:
                ignored.append(settling)
        if (
            operator_record is not None
            and len(ignored) > dropped
            and not _section_within(
                _reporter_section_of(config, reporter),
                _reporter_section_of(operator_record, reporter),
            )
        ):
            whole_sections.append(reporter)
            config._off_host_sections_warned.append(reporter)
    if not ignored:
        return settled
    places = shown_places(", ".join(settling.place for settling in ignored))
    files = described(in_tree, environment_paths)
    # The keys and paths are the repository's: the whole message is shown, once
    # and on one line, and not read as markup.
    if whole_sections:
        rest = shown_places(
            ", ".join(f"reporters.{reporter}" for reporter in whole_sections)
        )
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"Ignoring {places} and the rest of {rest} from "
                f"{files}: {membership}, and this reporter sends "
                "findings off the host with this host's credentials, so only the "
                "operator turns it on, chooses where it sends, and decides which "
                f"findings in the account it updates and archives. {how_to_keep('them')}"
            ),
            extra=NO_MARKUP,
        )
        return settled
    ASH_LOGGER.warning(
        shown_on_one_line(
            f"Ignoring {places} from "
            f"{files}: {membership}, "
            "and these options decide which findings in the operator's account "
            f"are updated and archived. {how_to_keep('them')}"
        ),
        extra=NO_MARKUP,
    )
    return settled


def drop_recorded_operator_only_options(config: "AshConfig") -> "AshConfig":
    """A copy of *config*, a configuration the shards recorded, without those options.

    For ``ash merge``. A shard records the configuration its scan resolved, and a
    file in the repository that shard scanned could have set these options; the
    merged results would then be imported into, and archive findings of, a scope
    the repository chose, with this host's credentials. *config* itself is left
    as recorded.
    """
    confined = copy.deepcopy(config)
    dropped: List[str] = []
    for reporter, names in OPERATOR_ONLY_OPTIONS.items():
        for key, section in _sections(confined, reporter):
            options = section.get("options")
            if not isinstance(options, dict):
                continue
            for option in names:
                if options.pop(option, _MISSING) is not _MISSING:
                    dropped.append(f"reporters.{key}.options.{option}")
    if dropped:
        # The keys are what the shards recorded: the whole message is shown, once
        # and on one line, and not read as markup.
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"Ignoring {', '.join(dropped)} in the configuration the shards "
                "recorded: a file in a shard's scanned repository could have set "
                "them, and they decide which findings in this host's account are "
                "updated and archived. ash merge takes them only from the "
                "operator's own --config, the configuration its off-host reporters "
                "run with."
            ),
            extra=NO_MARKUP,
        )
    return confined


def _marker_value(
    value: Any,
    kind: str,
    key: str,
    option: str,
    references: Sequence["EnvironmentReference"],
) -> str:
    """How the ignored marker shows *value*, what the chain wrote at
    ``kind.key.options.option``: a value the chain read from the environment
    as the reference it was written as (``<from ${VAR}>``), never the value
    itself; any other value as JSON, on one line.

    A value is read from the environment when a reference of *references*
    (the chain's ``environment_references``, every read included, the ones at
    places the load left out too) sits at that place, under any spelling of
    the section, and resolved to it. The loader records a reference at every
    place a read value lands: a YAML alias's place included, and a ``patch``
    value at the place the operation puts it (``copy`` and ``move`` are not
    allowed ops), so no read value reaches one of these places without one.
    A literal a later file wrote over a read value is shown as the literal. A
    mapping key the file read from the environment (a key reference, recorded
    at the mapping's place) is shown as its reference too.
    """
    from automated_security_helper.config.environment_record import (
        environment_marker,
    )

    wanted = (kind, folded_section_name(key), "options", option)

    def at_place(reference: Any, *, within: bool) -> bool:
        # The option's own place, or (``within``) a place under it: an entry
        # of a list or a mapping the option holds, which the loader records at
        # the place the read value landed.
        path = tuple(reference.path)
        return (
            (len(path) == 4 or (within and len(path) > 4))
            and path[0] == kind
            and isinstance(path[1], str)
            and folded_section_name(path[1]) == wanted[1]
            and path[2:4] == ("options", option)
        )

    def read_as(text: Any, *, within: bool, key: bool = False) -> Optional[str]:
        # ``key``: the text is a mapping key, matched against the references
        # the file read keys from (their path is the mapping's), never against
        # the ones it read values from, and the other way round.
        if not isinstance(text, str):
            return None
        for reference in references:
            if (
                bool(reference.key) == key
                and reference.resolved == text
                and at_place(reference, within=within)
            ):
                return environment_marker(reference.written)
        return None

    if isinstance(value, str):
        marker = read_as(value, within=False)
        if marker is not None:
            return marker
        return shown_on_one_line(json.dumps(value))

    # A list or mapping the file wrote holds its read values as leaves: each
    # leaf a reference at or under this place resolved to is shown as the
    # reference, never the value. A mapping key is shown the same way, and as
    # text: ``json.dumps`` applies ``default=`` to values only, so a date or
    # other non-JSON key a YAML file writes would raise out of the marking.
    def shown_key(name: Any) -> str:
        text = name if isinstance(name, str) else str(name)
        marker = read_as(text, within=True, key=True)
        return text if marker is None else marker

    def shown_leaves(node: Any) -> Any:
        if isinstance(node, dict):
            return {shown_key(name): shown_leaves(item) for name, item in node.items()}
        if isinstance(node, (list, tuple)):
            return [shown_leaves(item) for item in node]
        if isinstance(node, str):
            marker = read_as(node, within=True)
            return node if marker is None else marker
        return node

    # A date, time, bytes or set a YAML or TOML file writes is not JSON: it is
    # shown as text (``default=str``) instead of raising out of the marking.
    return shown_on_one_line(json.dumps(shown_leaves(value), default=str))


def mark_operator_only_options(
    data: Dict[str, Any],
    written: Optional[RepositorySettings] = None,
    references: Sequence["EnvironmentReference"] = (),
) -> Dict[str, Any]:
    """A copy of *data*, a dumped AshConfig, with these options shown as ignored.

    For the MCP get_config shapes that mark their answer. A file in a checkout
    the session's scan target does not hold was resolved as an operator's own
    file is, so the options it sets here were shown as applied, while a scan
    of the repository that holds it ignores them
    (``confine_operator_only_options``). Each marked option is shown as
    ``<operator only; ignored from this file: VALUE>`` instead, VALUE as JSON.
    The marker is only as wide as the callers and *written* make it: a shape
    whose load already dropped an option and whose record does not carry it
    answers without the option and without a marker, so a caller-named file's
    dropped reporter options read as an empty options table.

    *written* is what the file's chain wrote for these options (a
    ``RepositorySettings`` that read the chain): only those are marked, with
    the value that chain's repository files wrote -- the dump may no longer
    hold it, since the load left it out -- and a marker is written in even
    where the load left the option out of the dump. A place a file of the
    chain outside a checkout still sets (``set_elsewhere``) is not marked:
    a scan keeps that file's value. A dump holds a scanner's typed options
    whether a file wrote them or not, so the limit a file never named is the
    configuration's own, and is shown as it is. Without *written*, every one
    *data* holds is marked, with the dump's value.

    VALUE is shown as ``_marker_value`` shows it: a value the chain read from
    the environment (*references*, its ``environment_references``) as the
    reference the file wrote, ``<from ${VAR}>``, never the value; a literal
    as JSON on one line, the repository's own text.
    """
    marked = copy.deepcopy(data)
    for kind, listed in (
        ("reporters", OPERATOR_ONLY_OPTIONS),
        ("scanners", OPERATOR_ONLY_SCANNER_OPTIONS),
    ):
        sections = marked.get(kind)
        if not isinstance(sections, dict):
            continue
        wrote = None if written is None else written.written(kind)
        if wrote is not None and kind == "reporters":
            # The record keys a reporter section by the spelling the file that
            # wrote it used, and the dump by the spelling the merged chain kept,
            # which another file may have written differently. Both are looked
            # up by the folded spelling.
            wrote = {
                (plugin, folded_section_name(key), option): value
                for (plugin, key, option), value in wrote.items()
            }
        # A scanners section is read as the model reads it: the declared
        # section, or a spelling that folds to it (_scanner_sections_in); the
        # reporter lookup would also mark an extra scanner section the plugin
        # never reads and show its values as plain JSON.
        sections_in = _scanner_sections_in if kind == "scanners" else _sections_in
        for plugin, names in listed.items():
            for key, section in sections_in(sections, plugin):
                options = section.get("options")
                if not isinstance(options, dict):
                    continue
                for option in names:
                    place = (
                        plugin,
                        plugin if kind == "scanners" else folded_section_name(key),
                        option,
                    )
                    if wrote is None:
                        if option not in options:
                            continue
                        value = options[option]
                    else:
                        if place not in wrote:
                            continue
                        if written is not None and written.set_elsewhere(
                            kind, plugin, option
                        ):
                            continue
                        value = wrote[place]
                    shown = _marker_value(value, kind, key, option, references)
                    options[option] = (
                        f"<operator only; ignored from this file: {shown}>"
                    )
    return marked


def record_operator_reporters(
    config: "AshConfig",
    operator: "AshConfig",
    repository_files: Sequence[Path],
    environment_paths: Collection[Path] = frozenset(),
    scanner_views: Optional[List[Any]] = None,
    membership: Optional[str] = None,
    *,
    given_root_membership: bool = False,
    rootless_wording: bool = False,
) -> None:
    """Record on *config* the configuration as the operator set it.

    Args:
        config: The resolved AshConfig, built from *repository_files* among
            others; changed in place.
        operator: The trusted base ``resolve_config`` uses for the other
            confinements, with the operator's ``reporters`` overrides applied.
        repository_files: The config files the scanned repository could write
            (or an MCP client supplied), named in the warning.
        environment_paths: Those of them the environment chose, which the
            warning names ``<value>`` (``sandbox_grants.described``).
        scanner_views: The operator views a scanner's configured path is
            judged against; defaults to ``[operator]``. Recorded here, beside
            the reporters view, so every path that records one records both
            and no caller falls back to the narrow view by omission.
        membership: Why those files are not the operator's, in the sentence
            ``confinement_membership`` gives the other warnings, which the
            reporter's own warning repeats. None records the sentence for
            files outside the trees (the file is inside a git checkout, or an
            MCP client delivered it, with the scanned tree named only when the
            load has one): *given_root_membership* and *rootless_wording* are
            the load's wording flags, so a load with no scanned tree never
            claims one.

    A reporter that sends findings off the host runs with its section from
    *operator* (``reporter_section``), so each value or key *operator*'s files
    read from the environment under ``reporters`` is one the scan's messages
    can quote: it joins the values *config* redacts.
    """
    config._operator_reporters = operator
    config._operator_scanner_views = (
        list(scanner_views) if scanner_views else [operator]
    )
    config._repository_config_files = list(repository_files)
    config._repository_config_environment_paths = frozenset(
        Path(path) for path in environment_paths
    )
    config._repository_config_membership = membership or confinement_membership(
        checkout_membership=rootless_wording,
        given_root=given_root_membership,
        outside=True,
    )
    held = list(config._environment_values or [])
    for rewrite in getattr(operator, "_written_references", None) or []:
        if not rewrite.path or rewrite.path[0] != "reporters":
            continue
        for value in (rewrite.resolved, rewrite.environment_part):
            if value and value not in held:
                held.append(value)
    config._environment_values = held


def operator_wrote_value(
    config: Optional["AshConfig"],
    plugin_type: Literal["converter", "scanner", "reporter"],
    plugin_name: str,
    option_keys: Sequence[str],
    value: Any,
    *,
    config_from_context: bool = True,
) -> bool:
    """Whether *value* at *option_keys* of the plugin's section is the operator's.

    The configuration as the operator set it is recorded whenever a file the
    scanned repository could write joined the chain
    (``record_operator_reporters``): the trusted base, the ``reporters`` and
    ``scanners`` sections of the operator's own chain files, and the operator's
    ``--config-overrides`` under those two. A value is the operator's when that
    view holds an equal value at the same place; with no such view recorded,
    every file was the operator's. A key on the walk whose node is a list reads
    the remaining keys from each entry, so a list option compares entry by
    entry.

    *config_from_context* says where the plugin's own configuration came from:
    True (the default) when it was read from *config*, as a scan does; False
    when the embedding caller built it. A caller-built configuration is the
    operator's by construction only while the resolved section does NOT hold
    the value at the same place: a typed object built from the resolved
    section (``model_validate`` of ``get_plugin_config``, or another plugin's
    own ``config`` re-wrapped) carries the section's values, and the type of
    the object is not provenance, so such a value is judged by the walk like
    any section the scan handed over. A configuration read from *config* is
    judged by the walk, and the walk fails closed: a value the resolved
    section does not hold at that place (a miss of the exact keys, a section
    the lookup does not find) is not shown to be the operator's, so it is not.
    """
    if config is None:
        return True
    recorded = getattr(config, "_operator_reporters", None)
    if recorded is None:
        return True
    # The scanner views exist for the scanners sections only; a reporter or
    # converter judgment reads the recorded operator configuration itself
    # (the file view has no reporters/converters segments to answer with).
    views = (
        getattr(config, "_operator_scanner_views", None)
        if plugin_type == "scanner"
        else None
    ) or [recorded]
    wanted = _comparable(value)
    resolved_holds = [
        _comparable(held)
        for held in _option_values(config, plugin_type, plugin_name, option_keys)
    ]
    if not config_from_context:
        if not _holds(wanted, resolved_holds):
            return True
        # The resolved section holds this very value: judged by the
        # operator's view below, whatever Python type carried it here.
    elif not _holds(wanted, resolved_holds):
        return False
    return any(
        _holds(
            wanted,
            [
                _comparable(held)
                for held in _option_values(view, plugin_type, plugin_name, option_keys)
            ],
        )
        for view in views
    )


def _comparable(value: Any) -> Any:
    """*value* in a form two views of one option compare equal in: a path as
    its text, a model as its dump."""
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if hasattr(value, "model_dump"):
        return value.model_dump()
    return value


def _holds(wanted: Any, held: Sequence[Any]) -> bool:
    """Whether *held* holds *wanted*: equal as given, or equal as one path.

    The dump of an untyped section holds the file's raw text while a typed
    model holds the form it normalized that text to (a doubled or dotted
    separator folded away), and a spelling difference between those two is
    not provenance in either direction. One membership comparison decides
    every arm of :func:`operator_wrote_value`, so a respelled path can
    neither pass as the caller's own write nor be refused as nobody's."""
    if wanted in held:
        return True
    return any(_same_path_spelling(wanted, value) for value in held)


def _same_path_spelling(first: Any, second: Any) -> bool:
    """Whether two option values are one path under the folding a typed path
    model applies: doubled separators, ``.`` segments and a trailing
    separator folded away, and nothing else.

    A ``..`` segment is never folded: the tool is handed the resolved real
    path, which follows a link before it applies ``..``, so ``a/link/../b``
    and ``a/b`` can name different files and are different values here.
    Compared when EITHER side is path-shaped, so ``./a.yaml`` and ``a.yaml``
    meet by one rule. Pure text folding (``pathlib.PurePath``); the
    ownership judgment never reads the filesystem.

    A URL-shaped value folds only past its scheme: ``file:///x/p.py`` is the
    absolute ``/x/p.py`` while ``file://x/p.py`` is ``x/p.py`` relative to the
    source directory, and folding the ``//`` after the scheme would read the
    two as one file."""
    if not isinstance(first, str) or not isinstance(second, str):
        return False
    if not first or not second:
        return False
    if not (_path_shaped(first) or _path_shaped(second)):
        return False
    return _folded_spelling(first) == _folded_spelling(second)


def _folded_spelling(value: str) -> str:
    """*value* with its path folded, past a ``scheme://`` prefix if it has one.

    A prefix counts as a scheme only when *value* starts with an RFC 3986
    scheme of two or more characters followed by ``://``. That leaves a
    single drive letter (``C://dir``) and a separator past the first segment
    (``x/y://z``) folding as the paths they are. A ``Path``-typed field
    holding a URL has already collapsed the separator after the scheme
    (``file:///a/b`` reads back as ``file:/a/b``), so its text folds whole
    here and meets the collapsed spelling, never the raw ``scheme://``
    one."""
    if not re.match(r"[A-Za-z][A-Za-z0-9+.-]+://", value):
        return os.fspath(PurePath(value))
    scheme, separator, rest = value.partition("://")
    return f"{scheme}{separator}{os.fspath(PurePath(rest)) if rest else rest}"


def _path_shaped(value: str) -> bool:
    """Whether *value* holds a path separator."""
    return "/" in value or "\\" in value


def _option_values(
    config: "AshConfig",
    plugin_type: Literal["converter", "scanner", "reporter"],
    plugin_name: str,
    option_keys: Sequence[str],
) -> List[Any]:
    """Every value at *option_keys* of the plugin's section; a list node on
    the walk reads the remaining keys from each of its entries."""
    section = config.get_plugin_config(plugin_type=plugin_type, plugin_name=plugin_name)
    nodes: List[Any] = [section]
    for option_key in option_keys:
        next_nodes: List[Any] = []
        for node in nodes:
            for entry in node if isinstance(node, list) else [node]:
                if isinstance(entry, dict) and option_key in entry:
                    next_nodes.append(entry[option_key])
        nodes = next_nodes
    held: List[Any] = []
    for node in nodes:
        held.extend(node if isinstance(node, list) else [node])
    return held


def _reporter_section_of(config: Optional["AshConfig"], key: str) -> Any:
    if config is None:
        return None
    return config.get_plugin_config(plugin_type="reporter", plugin_name=key)


def _section_within(section: Any, operator_section: Any) -> bool:
    """Whether everything *section*, the resolved config's reporter section,
    holds is in *operator_section*, the one the reporter runs with.

    The run uses the operator's section whole, so the warning fires only when
    the resolved section holds something that will not run: a key or value of
    the repository's. An operator section that holds MORE (the trusted base's
    settings, which the config file never mentioned) ignores nothing.

    A mapping that holds no value (the ``options`` table left empty after the
    operator-only options were taken out of it) holds nothing that will not
    run, so the operator's section need not have it."""
    if isinstance(section, dict) and isinstance(operator_section, dict):
        return all(
            (
                _section_within(value, operator_section[key])
                if key in operator_section
                else _holds_no_value(value)
            )
            for key, value in section.items()
        )
    if isinstance(section, dict) and operator_section is None:
        return _holds_no_value(section)
    return section is None or section == operator_section


def _holds_no_value(section: Any) -> bool:
    """Whether *section* is a mapping with nothing in it, or only mappings that
    have nothing in them."""
    return isinstance(section, dict) and all(
        _holds_no_value(value) for value in section.values()
    )


def reporter_section(config: Optional["AshConfig"], reporter_class: type) -> Any:
    """The config section *reporter_class* runs with: what get_plugin_config gives.

    For a reporter that sends findings off the host, when *config* was built from
    a file the scanned repository could write (``record_operator_reporters``), the
    section comes from the operator's configuration instead, whole: its
    ``enabled`` and every option. Where the repository's file set it differently,
    one warning says so, naming the remedy.
    """
    from automated_security_helper.base.plugin_config import plugin_config_key

    key = plugin_config_key(reporter_class)
    section = _reporter_section_of(config, key)
    if config is None or getattr(reporter_class, "sends_off_host", False) is not True:
        return section
    operator = getattr(config, "_operator_reporters", None)
    if operator is None:
        return section
    operator_section = _reporter_section_of(operator, key)
    if (
        not _section_within(section, operator_section)
        and key not in config._off_host_sections_warned
    ):
        config._off_host_sections_warned.append(key)
        files = described(
            config._repository_config_files,
            config._repository_config_environment_paths,
        )
        # The same sentence the settle and sandbox warnings give for these
        # files, and the same remedy: record_operator_reporters recorded it from
        # the load's own wording flags, so a load with no scanned tree never
        # claims one. Where nothing recorded it, the sentence names no tree.
        membership = config._repository_config_membership or confinement_membership(
            checkout_membership=True, outside=True
        )
        # The paths are the repository's: the whole message is shown, once and on
        # one line, and not read as markup.
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"Ignoring reporters.{key} from {files}: {membership}, and this "
                "reporter sends findings off the host with this host's credentials, "
                "so only the operator turns it on and chooses where it sends. "
                f"{KEEP_A_SETTING}"
            ),
            extra=NO_MARKUP,
        )
    return operator_section
