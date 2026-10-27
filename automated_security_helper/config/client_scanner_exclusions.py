# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A delivered config's scanner exclusions are reported, not applied.

Why this exists
---------------
A config an MCP client delivered may set its own suppressions and ignore paths,
as a repository's config may on the CLI, and each one it supplies is marked
``client_supplied``: a finding it hides is kept in the results, suppressed and
marked, so the results show what the client's config hid
(``config/client_config_policy.py``). Several scanners also take exclusions in
their own options, and those keep files away from the scanner altogether, so
before this nothing in the results showed what a client's config had left out.

For each option in ``SCANNER_EXCLUSION_OPTIONS``, an entry the operator did not
supply is removed from a delivered config before the scanner runs, and is
recorded on the config (``AshConfig._client_scanner_exclusions``). After the
scan, ``utils/sarif_utils.apply_suppressions_to_sarif`` suppresses and marks
each finding of that scanner the entry would have kept out, the same way it
handles a client-supplied ignore path. Syft writes an SBOM rather than
findings, so a syft entry instead marks each SBOM component it would have
dropped (``mark_sbom_components``).

An entry is the operator's when the option's default has it, the trusted config
has it, or a file of the chain that no client delivered has it. Those stay in
the option and apply as before.

opengrep, semgrep and trivy-repo are among the scanners whose whole section a
client may not set (the always-denied floor in ``ash_config.ALWAYS_DENIED_PATHS``).
For them too the denied-fields check of a delivered file sees the section as the
move leaves it: the floor's whole-section entry does not refuse an option the
move empties of client values (``moved_exclusion_pointers``), and every other
value the file sets in the section is still refused. An operator's own
``denied_paths`` entry for the option still refuses it. The runtime-override
gate on ``select_profile``'s ``patch_ops`` and ``override_yaml`` and the
workspace tools' ``config_overrides`` leaves these options to resolution the
same way (``runtime_patch._writes_a_moved_exclusion``). A client's list may
leave out some of the operator's entries; the scanner then scans those files
too.

Options that exclude by something other than a path (``exclude_rule``, a
detect-secrets baseline, or a whole category such as checkov's
``skip_frameworks`` or ferret-scan's ``checks``) have no file to scan instead,
so they are in the default ``denied_paths`` and a delivered config that changes
one is refused. ``test_every_option_that_may_filter_findings_is_classified``
keeps every scanner option of that kind in one list or the other.

Matching
--------
Each entry is matched the way its scanner reads it, as closely as can be done
on a finding's path after the fact:

* bandit ``excluded_paths``: ASH passes bandit ``**/<path>/**``, which bandit
  matches with ``fnmatch`` against the file's path. The same pattern is matched
  against the finding's absolute path.
* checkov ``skip_path``: as checkov's own filter reads it, a regular
  expression found in, or a substring of, the absolute path of the file or of a
  directory above it (``checkov_skips``).
* opengrep and semgrep ``exclude``, ferret-scan ``exclude_patterns``, syft
  ``exclude``: a glob that excludes a file when it matches the file's path or
  any directory or run of directories in it, as semgrep documents it. A leading
  ``/`` anchors it at the scan root, and a leading ``./`` or ``**/`` is
  optional.
* trivy and trivy-repo ``ignore_file``: the file lists finding IDs. Each
  unexpired ID becomes an entry that matches a finding of that scanner with
  that rule ID (an ``AVD-`` prefix on either side is ignored); in a
  ``.trivyignore.yaml`` an entry's ``paths`` limit it further. The file is read
  only when it is a regular file inside the tree being scanned, opened without
  following a link (``utils/scanned_tree.open_in_scanned_tree``). A file
  elsewhere, or a link to one, is not read, since its contents would then reach
  the results, and its entries are not applied; the scan's warnings say so
  without quoting it.

Known limitations
-----------------
* A tool can also leave files or findings out through a config or ignore file
  of its own. Those config files are the operator's: checkov's and
  ferret-scan's config files, detect-secrets' plugin files and trivy-repo's
  secret file are honored only from outside the scanned tree
  (``config/path_trust.py``), bandit's, grype's and syft's come only from the
  trusted config (``config/tool_config_trust.py``), those of actionlint,
  cfn-guard, cfn-lint, gitleaks, trivy and zizmor only from the operator
  (``utils/config_trust.py``), and the default ``denied_paths`` refuse a
  delivered config that names one. An ignore file a
  tool reads from the tree on its own (such as a ``.semgrepignore``) is not
  re-applied here.
* The glob matching above is an approximation of each tool's own rules. A
  finding it misses is reported unsuppressed, which can fail a scan the
  client's exclusion would have passed; it is never hidden.

Rejected alternatives
---------------------
* Converting each entry into a ``global_settings.suppressions`` entry. A
  suppression path is matched with ASH's glob rules and applies to every
  scanner's findings, which neither checkov's regular expressions nor a
  one-scanner exclusion fit.
* Denying these options outright. The user's decision was that a delivered
  config's exclusions are honored and marked, as its suppressions are.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath
from typing import (
    Any,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from pydantic import BaseModel, ConfigDict

from automated_security_helper.utils.log import ASH_LOGGER

ExclusionKind = Literal["bandit", "checkov", "glob", "trivy-ignore-file"]

#: A trivy ignore file larger than this is not read.
_MAX_IGNORE_FILE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ScannerExclusionOption:
    """One scanner option that keeps files or findings away from its scanner."""

    #: The scanner's config name, which its results carry as ``scanner_name``.
    scanner: str
    #: The option's field name under ``scanners.<scanner>.options``.
    option: str
    kind: ExclusionKind
    #: The option's default entries (patterns), which are ASH's own.
    default: Tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return f"scanners.{self.scanner}.options.{self.option}"


#: The options whose client-supplied entries are re-applied as marked
#: suppressions. ``test_the_table_defaults_are_the_scanners_defaults`` checks
#: ``default`` against each scanner's own option default.
SCANNER_EXCLUSION_OPTIONS: Tuple[ScannerExclusionOption, ...] = (
    ScannerExclusionOption("bandit", "excluded_paths", "bandit"),
    ScannerExclusionOption("checkov", "skip_path", "checkov"),
    ScannerExclusionOption(
        "opengrep", "exclude", "glob", ("*-converted.py", "*_report_result.txt")
    ),
    ScannerExclusionOption(
        "semgrep", "exclude", "glob", ("*-converted.py", "*_report_result.txt")
    ),
    ScannerExclusionOption("syft", "exclude", "glob"),
    ScannerExclusionOption("ferret-scan", "exclude_patterns", "glob"),
    ScannerExclusionOption("trivy-repo", "ignore_file", "trivy-ignore-file"),
    ScannerExclusionOption("trivy", "ignore_file", "trivy-ignore-file"),
)


class ClientScannerExclusion(BaseModel):
    """An exclusion a delivered config gave one scanner, applied after the scan."""

    model_config = ConfigDict(frozen=True)

    scanner: str
    option: str
    kind: ExclusionKind
    #: The path pattern, regular expression, or (for trivy) finding ID.
    pattern: str
    reason: str
    #: For a trivy ID from a ``.trivyignore.yaml``: the paths it is limited to.
    paths: Tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return f"scanners.{self.scanner}.options.{self.option}"

    def applies_to(self, scanner_name: Optional[str]) -> bool:
        """Whether a finding reported by ``scanner_name`` is this exclusion's scanner's."""
        from automated_security_helper.config.ash_config import reduced_plugin_name

        if not scanner_name:
            return False
        return reduced_plugin_name(scanner_name) == reduced_plugin_name(self.scanner)

    def hides(self, *, relative: str, absolute: str, rule_id: Optional[str]) -> bool:
        """Whether the scanner would have left out a finding at this location."""
        if self.kind == "bandit":
            return fnmatch.fnmatch(
                absolute, str(PurePosixPath("**").joinpath(self.pattern, "**"))
            )
        if self.kind == "checkov":
            return checkov_skips(self.pattern, absolute, relative)
        if self.kind == "glob":
            return glob_excludes(self.pattern, relative)
        if not rule_id or not _same_trivy_id(rule_id, self.pattern):
            return False
        if not self.paths:
            return True
        return any(glob_excludes(path, relative) for path in self.paths)

    def justification(self) -> str:
        what = (
            f"ignore file entry '{self.pattern}'"
            if self.kind == "trivy-ignore-file"
            else f"entry '{self.pattern}'"
        )
        return (
            f"(ASH, client-supplied config) Suppressing finding excluded by "
            f"{self.key} {what} with reason: {self.reason}"
        )


def checkov_skips(pattern: str, absolute: str, relative: str) -> bool:
    """Whether checkov's ``--skip-path`` ``pattern`` leaves out the file at ``absolute``.

    As checkov 3's ``filter_ignored_paths`` decides it while walking the tree:
    the path of the file, or of any directory above it inside the scan, is left
    out when the pattern, compiled as a regular expression with ``.terraform``
    escaped, is found in it, or when the pattern is a substring of it. A pattern
    that is not a valid regular expression is used only as a substring.
    """
    candidates = [absolute]
    parts = [part for part in relative.replace("\\", "/").split("/") if part]
    base = absolute[: len(absolute) - len("/".join(parts))].rstrip("/")
    for end in range(1, len(parts)):
        candidates.append(f"{base}/{'/'.join(parts[:end])}")
    try:
        compiled: Optional[re.Pattern[str]] = re.compile(
            pattern.replace(".terraform", r"\.terraform")
        )
    except re.error:
        compiled = None
    return any(
        (compiled is not None and compiled.search(candidate) is not None)
        or pattern in candidate
        for candidate in candidates
    )


def glob_excludes(pattern: str, relative: str) -> bool:
    """Whether glob ``pattern`` excludes the file at ``relative`` (from the scan root).

    True when it matches the path or any directory or run of directories in it.
    A leading ``/`` anchors the pattern at the scan root; a leading ``./`` and a
    leading ``**/`` are optional.
    """
    candidate = pattern.strip().replace("\\", "/")
    while candidate.startswith("./"):
        candidate = candidate[2:]
    anchored = candidate.startswith("/")
    candidate = candidate.strip("/")
    if not candidate:
        return False
    variants = {candidate}
    while candidate.startswith("**/"):
        candidate = candidate[3:]
        variants.add(candidate)
    parts = [
        part for part in relative.replace("\\", "/").split("/") if part not in ("", ".")
    ]
    starts = range(1) if anchored else range(len(parts))
    for start in starts:
        for end in range(start + 1, len(parts) + 1):
            joined = "/".join(parts[start:end])
            if any(fnmatch.fnmatchcase(joined, variant) for variant in variants):
                return True
    return False


def _same_trivy_id(rule_id: str, entry: str) -> bool:
    """Whether trivy reads ignore-file ID ``entry`` as finding ``rule_id``'s."""

    def bare(value: str) -> str:
        value = value.strip()
        return value[4:] if value.upper().startswith("AVD-") else value

    return bare(rule_id).upper() == bare(entry).upper()


def exclusion_option_at(
    segments: Sequence[str],
) -> Optional[Tuple[ScannerExclusionOption, bool]]:
    """The exclusion option a config path names, and whether it names one entry of it.

    ``segments`` is a path split into keys: ``scanners``, the scanner's key in
    any spelling the plugin lookup reads, ``options``, and the option with ``-``
    or ``_``, then for a list option ``-`` or an index to name one entry.
    """
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )

    if len(segments) not in (4, 5) or segments[0] != "scanners":
        return None
    if segments[2] != "options":
        return None
    names = plugin_key_lookup_names(str(segments[1]))
    option = str(segments[3]).replace("-", "_")
    for spec in SCANNER_EXCLUSION_OPTIONS:
        if spec.option != option or reduced_plugin_name(spec.scanner) not in names:
            continue
        if len(segments) == 4:
            return spec, False
        last = str(segments[4])
        if spec.kind != "trivy-ignore-file" and (last == "-" or last.isdigit()):
            return spec, True
        return None
    return None


def moves_all_of(spec: ScannerExclusionOption, value: Any, *, entry: bool) -> bool:
    """Whether resolution takes all of ``value``, written at ``spec``'s option, out of it.

    ``strip_client_scanner_exclusions`` moves every list entry that has a path
    pattern and is not the operator's, and leaves the operator's where they are,
    so no client value is left in the option. An entry with no pattern stays,
    so a value holding one is not moved whole. A trivy ignore file that is set
    is replaced by the trusted one. ``entry`` says ``value`` is written as
    entries appended to the list (one, or a list of them, as an appending
    ``--config-overrides`` names them) rather than as the whole option.
    """
    if spec.kind == "trivy-ignore-file":
        return not entry and isinstance(value, str) and bool(value)
    if entry:
        entries = value if isinstance(value, list) else [value]
    elif isinstance(value, list):
        entries = value
    else:
        return False
    return all(_pattern_of(item)[0] is not None for item in entries)


def moved_exclusion_pointers(document: Any) -> List[str]:
    """The JSON pointers of the exclusion options in ``document`` that resolution moves whole.

    For the denied-fields check of a delivered file, which sees the sections as
    the move leaves them (``client_config_policy.apply_client_config_rules``):
    these hold nothing of the client's once the move has run, so the
    always-denied entries that cover a whole scanner section do not refuse them
    (``runtime_patch.SECTION_FLOOR_ENTRIES``). Every other ``denied_paths``
    entry and value pattern still applies, and so does the check of every other
    key of the section.
    """
    from automated_security_helper.config.config_sources import _resolve_dict_key

    scanners = document.get("scanners") if isinstance(document, dict) else None
    if not isinstance(scanners, dict):
        return []
    found: List[str] = []
    for key, section in scanners.items():
        if not isinstance(section, dict):
            continue
        options_key = _resolve_dict_key(section, "options")
        options = section.get(options_key)
        if not isinstance(options, dict):
            continue
        for name, value in options.items():
            segments = ["scanners", str(key), str(options_key), str(name)]
            located = exclusion_option_at(segments)
            if located is None or not moves_all_of(located[0], value, entry=False):
                continue
            found.append(
                "/"
                + "/".join(
                    segment.replace("~", "~0").replace("/", "~1")
                    for segment in segments
                )
            )
    return found


def strip_client_scanner_exclusions(
    config: Any,
    documents: Mapping[Path, Any],
    base: Any,
    *,
    source_dir: Path | str | None,
    scanned_root: Path | str | None,
    is_delivered: Optional[Any] = None,
) -> Any:
    """Move each exclusion a delivered config supplied from its scanner's options to the config.

    In place, on ``config`` (an ``AshConfig`` with a client-delivered file in its
    chain), which is returned. ``base`` is the trusted config.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.sandbox_grants import working_directory

    delivered = is_delivered or config_is_client_supplied
    operator_documents = [
        document for path, document in documents.items() if not delivered(path)
    ]
    # None with no root given and no working directory left: the one use of
    # the root, a delivered trivy ignore file, is then not read.
    named_root = scanned_root or source_dir
    root = Path(named_root) if named_root else working_directory()
    recorded: List[ClientScannerExclusion] = list(
        getattr(config, "_client_scanner_exclusions", None) or []
    )
    warnings: List[str] = list(getattr(config, "_resolution_warnings", None) or [])
    for spec in SCANNER_EXCLUSION_OPTIONS:
        operators = _operator_patterns(spec, operator_documents, base)
        for _, section in _scanner_sections(config, spec.scanner):
            options = _options_of(section)
            if options is None:
                continue
            value = _get(options, spec.option)
            if spec.kind == "trivy-ignore-file":
                if value and str(value) not in operators:
                    trusted = _trusted_ignore_file(base, spec)
                    _set(options, spec.option, trusted)
                    found, note = _trivy_ignore_exclusions(
                        str(value), spec, source_dir=source_dir, root=root
                    )
                    recorded.extend(found)
                    warnings.append(note)
                continue
            if not isinstance(value, list):
                continue
            kept: List[Any] = []
            moved: List[ClientScannerExclusion] = []
            for entry in value:
                pattern, reason = _pattern_of(entry)
                if pattern is None or pattern in operators:
                    kept.append(entry)
                    continue
                moved.append(
                    ClientScannerExclusion(
                        scanner=spec.scanner,
                        option=spec.option,
                        kind=spec.kind,
                        pattern=pattern,
                        reason=reason or "set by a config an MCP client delivered",
                    )
                )
            if not moved:
                continue
            _set(options, spec.option, kept)
            recorded.extend(moved)
            listed = ", ".join(repr(item.pattern) for item in moved)
            warnings.append(
                f"{spec.key}: {listed} came from a config an MCP client delivered and "
                f"{'is' if len(moved) == 1 else 'are'} not applied as an exclusion. "
                f"The files are scanned, and each {spec.scanner} finding "
                f"{'it' if len(moved) == 1 else 'they'} would have left out is "
                f"reported suppressed and marked client-supplied."
            )
    config._client_scanner_exclusions = _unique(recorded)
    config._resolution_warnings = warnings
    return config


def _unique(items: Iterable[ClientScannerExclusion]) -> List[ClientScannerExclusion]:
    seen: Set[ClientScannerExclusion] = set()
    out: List[ClientScannerExclusion] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _scanner_sections(config: Any, scanner: str) -> List[Tuple[str, Any]]:
    """Each section of ``config.scanners`` that ``get_plugin_config(scanner)`` could read."""
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )

    segment = config.scanners
    by_key = {
        (field.alias or name): name
        for name, field in type(segment).model_fields.items()
    }
    extra = segment.__pydantic_extra__ or {}
    wanted = reduced_plugin_name(scanner)
    found: List[Tuple[str, Any]] = []
    for key in list(by_key) + list(extra):
        if key != scanner and wanted not in plugin_key_lookup_names(key):
            continue
        section = getattr(segment, by_key[key]) if key in by_key else extra.get(key)
        if section is not None:
            found.append((key, section))
    return found


def _options_of(section: Any) -> Any:
    if isinstance(section, dict):
        from automated_security_helper.config.config_sources import _resolve_dict_key

        key = _resolve_dict_key(section, "options")
        options = section.get(key)
        return options if isinstance(options, (dict, BaseModel)) else None
    return getattr(section, "options", None)


def _get(options: Any, option: str) -> Any:
    if isinstance(options, dict):
        from automated_security_helper.config.config_sources import _resolve_dict_key

        return options.get(_resolve_dict_key(options, option))
    return getattr(options, option, None)


def _set(options: Any, option: str, value: Any) -> None:
    if isinstance(options, dict):
        from automated_security_helper.config.config_sources import _resolve_dict_key

        options[_resolve_dict_key(options, option)] = value
    else:
        setattr(options, option, value)


def _pattern_of(entry: Any) -> Tuple[Optional[str], Optional[str]]:
    """An option entry's pattern and reason: a string, or a path-with-reason entry."""
    if isinstance(entry, str):
        return entry, None
    if isinstance(entry, dict):
        path = entry.get("path")
        reason = entry.get("reason")
        return (path if isinstance(path, str) else None), (
            reason if isinstance(reason, str) else None
        )
    path = getattr(entry, "path", None)
    reason = getattr(entry, "reason", None)
    return (path if isinstance(path, str) else None), (
        reason if isinstance(reason, str) else None
    )


def _patterns_in(value: Any) -> Set[str]:
    if isinstance(value, str):
        return {value}
    if not isinstance(value, list):
        return set()
    found: Set[str] = set()
    for entry in value:
        pattern, _ = _pattern_of(entry)
        if pattern is not None:
            found.add(pattern)
    return found


def _operator_patterns(
    spec: ScannerExclusionOption, operator_documents: List[Any], base: Any
) -> Set[str]:
    """The entries the operator supplied for ``spec``: defaults, the trusted config, operator files."""
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )

    found = set(spec.default)
    read = base.get_plugin_config("scanner", spec.scanner) if base is not None else None
    if isinstance(read, dict):
        found |= _patterns_in(_get(read.get("options") or {}, spec.option))
    wanted = reduced_plugin_name(spec.scanner)
    for document in operator_documents:
        scanners = document.get("scanners") if isinstance(document, dict) else None
        if not isinstance(scanners, dict):
            continue
        for key, section in scanners.items():
            if key != spec.scanner and wanted not in plugin_key_lookup_names(str(key)):
                continue
            options = _options_of(section) if isinstance(section, dict) else None
            if isinstance(options, dict):
                found |= _patterns_in(_get(options, spec.option))
    return found


def _trusted_ignore_file(base: Any, spec: ScannerExclusionOption) -> Optional[str]:
    read = base.get_plugin_config("scanner", spec.scanner) if base is not None else None
    if isinstance(read, dict):
        value = _get(read.get("options") or {}, spec.option)
        if isinstance(value, str) and value:
            return value
    return None


def _trivy_ignore_exclusions(
    value: str,
    spec: ScannerExclusionOption,
    *,
    source_dir: Path | str | None,
    root: Optional[Path],
) -> Tuple[List[ClientScannerExclusion], str]:
    """The entries of the trivy ignore file a delivered config named, and a warning saying so.

    The file is read only as a regular file inside ``root``, the tree being
    scanned, through ``utils/scanned_tree.open_in_scanned_tree``: no ``..``, no
    symlink at any component, one hard link, and read from the descriptor that
    was checked. A wider test (any checkout above the tree, any session's
    delivered files) would let a delivered config pick a file elsewhere on the
    server and see parts of it in the results. Nothing read from a file is
    put in a warning. With no ``root`` (no scanned root, no source directory
    and no working directory) there is no tree to read it from, so it is not
    read and no entry is applied.
    """
    from automated_security_helper.utils.scanned_tree import (
        TreeInputRefused,
        open_in_scanned_tree,
    )

    lead = (
        f"{spec.key}: {value!r} came from a config an MCP client delivered and is not "
        f"passed to trivy."
    )
    if root is None:
        return [], (
            f"{lead} It was not read, and its entries are not applied: there is "
            f"no scanned tree to read it from (the working directory is gone), "
            f"and only a regular file inside the scanned tree is read."
        )
    path = Path(value)
    if not path.is_absolute():
        path = Path(source_dir or root) / path
    try:
        handle = open_in_scanned_tree(path, root)
    except TreeInputRefused as refused:
        return [], (
            f"{lead} It was not read, and its entries are not applied: "
            f"{refused.reason}, and only a regular file inside the scanned tree is "
            f"read."
        )
    except OSError:
        return [], f"{lead} It could not be read, so no entries are applied."
    with handle:
        data = handle.read(_MAX_IGNORE_FILE_BYTES + 1)
    if len(data) > _MAX_IGNORE_FILE_BYTES:
        return [], (
            f"{lead} It is larger than {_MAX_IGNORE_FILE_BYTES} bytes, so its "
            f"entries are not applied."
        )
    text = data.decode("utf-8", errors="replace")
    try:
        entries = parse_trivy_ignore_file(
            text, yaml_format=path.suffix in (".yaml", ".yml")
        )
    except ValueError:
        return [], f"{lead} It could not be parsed, so no entries are applied."
    reason = f"listed in the ignore file {value!r} a client-delivered config named"
    found = [
        ClientScannerExclusion(
            scanner=spec.scanner,
            option=spec.option,
            kind=spec.kind,
            pattern=entry_id,
            reason=reason,
            paths=paths,
        )
        for entry_id, paths in entries
    ]
    return found, (
        f"{lead} Its {len(found)} entr{'y is' if len(found) == 1 else 'ies are'} "
        f"applied after the scan: each trivy finding one names is reported suppressed "
        f"and marked client-supplied."
    )


def parse_trivy_ignore_file(
    text: str, *, yaml_format: bool, today: Optional[date] = None
) -> List[Tuple[str, Tuple[str, ...]]]:
    """(ID, paths) for each unexpired entry of a trivy ignore file.

    The plain format has one ID per line, ``#`` starts a comment, and an
    ``exp:YYYY-MM-DD`` field after the ID sets when the entry stops applying. The
    YAML format (``.trivyignore.yaml``) lists entries with ``id``, optional
    ``paths`` and optional ``expired_at`` under ``vulnerabilities``,
    ``misconfigurations``, ``secrets`` and ``licenses``.
    """
    today = today or date.today()
    found: List[Tuple[str, Tuple[str, ...]]] = []
    if yaml_format:
        import yaml

        from automated_security_helper.config.ash_config import load_config_yaml

        # ASH applies these entries itself, so the file is parsed as ASH parses
        # its own configuration: no aliases. An entry list of aliases to one
        # entry whose paths are aliases to one list is read as every entry
        # times every path.
        try:
            document = load_config_yaml(text) or {}
        except yaml.YAMLError as exc:
            raise ValueError(str(exc)) from exc
        if not isinstance(document, dict):
            raise ValueError("the document is not a mapping")
        for section in ("vulnerabilities", "misconfigurations", "secrets", "licenses"):
            for item in document.get(section) or []:
                if not isinstance(item, dict) or not item.get("id"):
                    continue
                if _expired(item.get("expired_at"), today):
                    continue
                paths = item.get("paths") or []
                found.append(
                    (
                        str(item["id"]),
                        tuple(str(path) for path in paths if isinstance(path, str)),
                    )
                )
        return found
    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        if not fields:
            continue
        expiry = next(
            (field[len("exp:") :] for field in fields[1:] if field.startswith("exp:")),
            None,
        )
        if _expired(expiry, today):
            continue
        found.append((fields[0], ()))
    return found


def _expired(value: Any, today: date) -> bool:
    if not value:
        return False
    try:
        return date.fromisoformat(str(value)[:10]) < today
    except ValueError:
        ASH_LOGGER.debug(
            f"Unreadable trivy ignore expiry {value!r}; treated as unexpired"
        )
        return False


def matching_exclusion(
    exclusions: Iterable[ClientScannerExclusion],
    *,
    scanner_name: Optional[str],
    relative: str,
    absolute: str,
    rule_id: Optional[str],
) -> Optional[ClientScannerExclusion]:
    """The first of ``exclusions`` that would have kept this finding from its scanner."""
    for exclusion in exclusions:
        if exclusion.applies_to(scanner_name) and exclusion.hides(
            relative=relative, absolute=absolute, rule_id=rule_id
        ):
            return exclusion
    return None


#: The CycloneDX property name a marked SBOM component carries.
SBOM_PROPERTY = "ash:clientSuppliedExclusion"


def mark_sbom_components(
    report: Any, exclusions: Iterable[ClientScannerExclusion]
) -> int:
    """Mark each SBOM component a delivered syft exclusion would have dropped.

    A component's files are its ``syft:location:<n>:path`` properties. Each match
    adds a ``SBOM_PROPERTY`` property naming the option and entry, once. Returns
    how many components were marked.
    """
    syft = [item for item in exclusions if item.applies_to("syft")]
    if not syft:
        return 0
    from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import Property

    marked = 0
    pending = list(getattr(report, "components", None) or [])
    while pending:
        component = pending.pop()
        pending.extend(getattr(component, "components", None) or [])
        properties = list(getattr(component, "properties", None) or [])
        locations = [
            str(prop.value).lstrip("/")
            for prop in properties
            if prop.name
            and prop.name.startswith("syft:location:")
            and prop.name.endswith(":path")
            and prop.value
        ]
        added = False
        for exclusion in syft:
            if not any(glob_excludes(exclusion.pattern, where) for where in locations):
                continue
            value = f"{exclusion.key}: {exclusion.pattern}"
            if any(p.name == SBOM_PROPERTY and p.value == value for p in properties):
                continue
            properties.append(Property(name=SBOM_PROPERTY, value=value))
            added = True
        if added:
            component.properties = properties
            marked += 1
    return marked
