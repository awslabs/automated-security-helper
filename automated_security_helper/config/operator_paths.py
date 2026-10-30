# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A relative path the operator sets is taken from where it was set, not the source directory.

Why this exists
---------------
Some options name a file or directory on the host: a scanner's own config file, a
baseline, a rules directory, a file detect-secrets loads a plugin or filter from,
a path the sandbox may read. The scanners joined a relative value to the source
directory, the tree being scanned. So an operator's config kept outside the tree
that named ``bandit.yaml``, meaning the file next to it, had bandit read a
``bandit.yaml`` the repository put at its root instead.

What happens now
----------------
``resolve_config`` reads every config file with ``the_operators_files`` as the
judge: each operator file's own relative values for the options below are made
absolute against that file's directory before the files are merged, so a value in
an ``extends`` base is taken from the base's directory, and one a ``patch``
operation sets from the directory of the file that holds the operation; a
``test`` operation's value compares equal to its path as written and as anchored
(``_test_value``), so a guard on a same-directory path holds. The file
``ASH_CONFIG`` names is read the same way. ``--config-overrides``, and the CLI
flags that become overrides, are taken from the working directory ASH runs in
(``anchor_override_paths``), and so are ``TRIVY_IGNOREFILE`` and
``TRIVY_SECRET_CONFIG``, which trivy and trivy-repo read in place of their
``ignore_file`` and ``secret_config_file`` (``_trivy_scanner_base``), and
``TRIVY_CONFIG``, the trivy config file trivy-repo passes with ``--config``. A
value that is already absolute, starts with ``~`` (the scanner expands it) or is
a URL is left as written, and so is a ``sandbox.extra_read_paths`` entry holding
``$`` (the sandbox expands it). No scanner expands a ``$`` in its path options,
so there it is a character of the file's name and the value is anchored like any
other. opengrep's and semgrep's ``config`` is anchored when a file or directory
is there, or when the value is spelled as a path (a rules-file suffix, or
``./``/``../``): left as written, a missing file would be read from the tool's
working directory, the scanned tree. The three
environment variables are anchored by ``anchored_environment_path``: nothing
expands them, so a relative value is joined as written, ``$`` and ``://``
included, and its ``..`` is left for the lookup, which goes up from where a
symbolic link before it points.

The options (``SCANNER_PATH_OPTIONS``, ``SCANNER_RULES_OPTIONS``):

* ``config_file`` of actionlint, bandit, cfn-lint, checkov, ferret-scan, gitleaks,
  grype, syft, trivy, trivy-repo and zizmor;
* gitleaks' ``baseline_path``;
* each entry of cfn-guard's ``rules_paths``, a list of rules files and
  directories, whether the list is set whole, appended to with ``key+=`` or a
  ``patch`` ``add`` at ``.../rules_paths/-``;
* detect-secrets' ``baseline_file``, and the ``file://`` entries of its
  ``scan_settings.plugins_used`` and ``filters_used``;
* trivy's and trivy-repo's ``ignore_file`` and ``secret_config_file``, and
  trivy-repo's ``module_dir``;
* opengrep's and semgrep's ``config``, only when a file or directory is there:
  otherwise it is a registry entry such as ``p/ci``, which the tool resolves;
* ``sandbox.extra_read_paths``.

actionlint's ``shellcheck`` and ``pyflakes`` are left out: each names a program,
and a bare name there (``shellcheck``) is looked up on PATH, so it is not a path
to anchor. A path the operator gives them is still taken from the source
directory, as the scanner's own check has it.

A file inside the scanned tree, or one an MCP client delivered, is left as
written. Such a file does not choose these options: most are replaced by the
operator's value (``tool_config_trust``, ``sandbox_grants``), and the scanners
of the rest (actionlint, cfn-guard, cfn-lint, gitleaks, trivy, trivy-repo's
``config_file`` and ``module_dir``, zizmor) use the value only when
``utils/config_trust.set_by_operator`` finds the operator's equal to it. Either
way the comparison is with the operator's anchored value, so a repository file
that names a same-named file of its own no longer matches the operator's.

Rejected: resolving against the source directory at the point of use, as before,
which is the tree; and keeping each value relative and recording which file set
it, which the merged document does not keep (``config_sources.deep_merge``).

Known limitations
-----------------
* An MCP client's ``config_overrides`` are not anchored: they are the client's,
  and under the MCP server none of these options is the client's to set.
* ``ash config update`` and the config wizard read a file without anchoring, so
  they write back what the file holds.
* ``anchored_path`` normalizes the joined path by name (``os.path.normpath``), so
  in a config file or ``--config-overrides`` a ``link/..`` names the directory
  holding the link, where the kernel would go up from the link's target. The
  values are compared with each other after anchoring (``tool_config_trust``,
  ``OperatorPaths``), so dropping the normalization means changing how those
  comparisons see a path. The environment variables are not normalized.
* Reporter options that name a report file (the Bedrock reporter's
  ``output_file`` and the others) are a file name in the reports directory, not
  a path, so they are not listed here. ``global_settings.ignore_paths`` and the
  scanners' exclusion lists name paths in the scanned tree on purpose.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

#: Scanner options whose value names a file or directory the scanner's tool
#: reads, or is a list of such paths (cfn-guard's ``rules_paths``), by scanner.
#: actionlint's ``shellcheck`` and ``pyflakes`` are not here: a bare name there
#: is a program looked up on PATH, not a path.
SCANNER_PATH_OPTIONS: Dict[str, Tuple[str, ...]] = {
    "actionlint": ("config_file",),
    "bandit": ("config_file",),
    "cfn-guard": ("rules_paths",),
    "cfn-lint": ("config_file",),
    "checkov": ("config_file",),
    "detect-secrets": ("baseline_file",),
    "ferret-scan": ("config_file",),
    "gitleaks": ("config_file", "baseline_path"),
    "grype": ("config_file",),
    "syft": ("config_file",),
    "trivy": ("config_file", "ignore_file", "secret_config_file"),
    "trivy-repo": ("config_file", "module_dir", "ignore_file", "secret_config_file"),
    "zizmor": ("config_file",),
}

#: Scanner options that are a path when a file or directory is there, and a
#: registry entry or a URL the tool resolves otherwise.
SCANNER_RULES_OPTIONS: Dict[str, Tuple[str, ...]] = {
    "opengrep": ("config",),
    "semgrep": ("config",),
}

#: detect-secrets ``scan_settings`` lists whose entries may name a file the worker
#: loads code from, as ``file://<path>`` or ``file://<path>::<function>``.
_DETECT_SECRETS_FILE_LISTS: Tuple[str, ...] = ("plugins_used", "filters_used")
_FILE_SCHEME = "file://"


def not_delivered_by_a_client(path: Path) -> bool:
    """Accepts a config file no MCP client delivered: the judge for ``ASH_CONFIG``."""
    from automated_security_helper.config.config_sources import (
        config_is_client_delivered,
    )

    return not config_is_client_delivered(path)


def the_operators_files(trees: Sequence[Path]) -> Callable[[Path], bool]:
    """Accepts a config file outside every scanned tree that no MCP client delivered.

    The judge ``resolve_config`` reads its files with. A file inside a tree, or
    reached through a link inside one, is the repository's; its values for these
    options are replaced by the operator's anyway, and ``client_scanner_exclusions``
    reads a delivered file's exclusion files from the source directory, as the
    client wrote them.
    """
    from automated_security_helper.config.sandbox_grants import files_inside

    known = list(trees)

    def judge(path: Path) -> bool:
        # named=[path]: the membership check also walks the path's own name
        # for a link whose location is inside a tree; the chain argument alone
        # does not walk link locations.
        return not files_inside(
            [path], known, named=[path]
        ) and not_delivered_by_a_client(path)

    return judge


def _spellings(container: Dict[str, Any], name: str) -> List[str]:
    """The keys ``container`` holds ``name`` under, spelled with ``-`` or ``_``."""
    wanted = name.replace("-", "_")
    return [
        key
        for key in container
        if isinstance(key, str) and key.replace("-", "_") == wanted
    ]


def anchored_environment_path(value: Any, base_dir: Path) -> Any:
    """A path the operator set in an environment variable, a relative one joined to ``base_dir``.

    ``base_dir`` is the working directory ASH runs in. Nothing expands such a
    variable's value, so a ``$`` or ``://`` in it is part of a file name, and the
    value is joined as written. ``..`` is left for the lookup to resolve, so it
    goes up from where a symbolic link before it points, as the kernel and the
    shell read the path. A value that is not a string, is empty, is absolute or
    starts with ``~`` (expanded by ``path_trust.resolved_path``) is returned as
    it is.
    """
    if not isinstance(value, str) or not value.strip():
        return value
    if value.startswith("~") or os.path.isabs(value):
        return value
    return os.path.join(os.fspath(base_dir), value)


def _names_a_root(value: str) -> bool:
    """True for an absolute path, and on Windows for one rooted without a drive.

    Python 3.13 stopped counting ``/opt/ca`` or ``\\opt\\ca`` as absolute on
    Windows, because the drive it is on is the current one. Anchoring such a
    value would put the config file's drive in front of the root the operator
    wrote, so it is left as written, as it was on 3.12 and before.
    """
    if os.path.isabs(value):
        return True
    return os.name == "nt" and value[:1] in ("/", "\\")


#: A URL: a scheme (RFC 3986) at the start of the value, then ``://``. A value
#: that holds ``://`` after a path separator or another character a scheme cannot
#: hold, such as ``rules/a://b.yaml``, is a relative path.
_URL_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")

#: Suffixes a rules file opengrep or semgrep reads carries; a registry entry
#: (``p/ci``, ``r/python.lang.security``, ``auto``) carries none.
_RULES_FILE_SUFFIXES: Tuple[str, ...] = (".yaml", ".yml", ".json")


def _names_a_rules_file(value: str) -> bool:
    """Whether a relative ``config`` value is spelled as a path, not a registry entry.

    A value with a rules-file suffix, or one written from the current or parent
    directory (``./rules``, ``../rules``), names a file or directory wherever it
    is read from, so it is anchored even when nothing is there yet: left as
    written, the tool would read it from its working directory, the scanned
    tree, and run a same-named rules file the repository put there.
    """
    if value.lower().endswith(_RULES_FILE_SUFFIXES):
        return True
    return value.startswith(("./", ".\\", "../", "..\\"))


def anchored_path(
    value: Any,
    base_dir: Path,
    *,
    only_if_there: bool = False,
    expands_variables: bool = True,
) -> Any:
    """``value`` made absolute against ``base_dir``, when it is a relative path.

    Anything else (not a string, empty, absolute, starting with ``~``, or a URL:
    starting with a scheme and ``://``) is returned as it is. A ``://`` further
    into the value is part of a relative name and is anchored. A value holding
    ``$`` is returned as it is too when ``expands_variables`` is true, the
    default: its reader expands the variable after this (the sandbox does for
    ``extra_read_paths``), and anchoring the text first would put ``base_dir`` in
    front of the expansion. A scanner's
    tool reads its path options as written, so those are anchored with
    ``expands_variables`` false and a ``$`` is a character of the file's name.
    With ``only_if_there``, a relative value that names nothing under
    ``base_dir`` is returned as it is too, unless it is spelled as a path
    (``_names_a_rules_file``).
    """
    if not isinstance(value, str) or not value.strip():
        return value
    if value.startswith("~") or _URL_SCHEME.match(value) or "\x00" in value:
        return value
    if expands_variables and "$" in value:
        return value
    if _names_a_root(value):
        return value
    candidate = os.path.normpath(os.path.join(os.fspath(base_dir), value))
    if (
        only_if_there
        and not os.path.exists(candidate)
        and not _names_a_rules_file(value)
    ):
        return value
    return candidate


def _anchored_path_option(value: Any, base_dir: Path) -> Any:
    """A ``SCANNER_PATH_OPTIONS`` value anchored: one path, or each path of a list.

    No scanner expands a variable in these options, so a ``$`` is part of the
    name and the value is anchored like any other relative path.
    """
    if isinstance(value, list):
        return [
            anchored_path(entry, base_dir, expands_variables=False) for entry in value
        ]
    return anchored_path(value, base_dir, expands_variables=False)


def _anchored_file_entry(value: Any, base_dir: Path) -> Any:
    """A ``file://<path>[::<function>]`` entry with a relative path made absolute.

    detect-secrets reads the path as written, so a ``$`` in it is a character
    of the file's name and the path is anchored like a scanner's path option;
    left as written, a relative path would be read from the tool's working
    directory, the scanned tree.
    """
    if not isinstance(value, str) or not value.startswith(_FILE_SCHEME):
        return value
    file_part, separator, function = value[len(_FILE_SCHEME) :].partition("::")
    anchored = anchored_path(file_part, base_dir, expands_variables=False)
    if anchored == file_part:
        return value
    return f"{_FILE_SCHEME}{anchored}{separator}{function}"


def _scanner_matches(key: str, scanner: str) -> bool:
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )

    return key == scanner or reduced_plugin_name(scanner) in plugin_key_lookup_names(
        key
    )


def _anchor_options(key: str, options: Dict[str, Any], base_dir: Path) -> None:
    for scanner, names in SCANNER_PATH_OPTIONS.items():
        if _scanner_matches(key, scanner):
            for name in names:
                for spelling in _spellings(options, name):
                    options[spelling] = _anchored_path_option(
                        options[spelling], base_dir
                    )
    for scanner, names in SCANNER_RULES_OPTIONS.items():
        if _scanner_matches(key, scanner):
            for name in names:
                for spelling in _spellings(options, name):
                    options[spelling] = anchored_path(
                        options[spelling],
                        base_dir,
                        only_if_there=True,
                        expands_variables=False,
                    )
    if not _scanner_matches(key, "detect-secrets"):
        return
    for settings_key in _spellings(options, "scan_settings"):
        settings = options[settings_key]
        if not isinstance(settings, dict):
            continue
        for list_name in _DETECT_SECRETS_FILE_LISTS:
            for list_key in _spellings(settings, list_name):
                entries = settings[list_key]
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if isinstance(entry, dict) and "path" in entry:
                        entry["path"] = _anchored_file_entry(entry["path"], base_dir)


def anchor_relative_paths(document: Any, base_dir: Union[str, Path]) -> Any:
    """A copy of one config file's document with its relative operator paths anchored.

    Args:
        document: The file's parsed document, before its ``extends`` and
            ``patch`` are applied. Anything but a mapping is returned as it is.
        base_dir: The directory the file is in.
    """
    if not isinstance(document, dict):
        return document
    import copy

    base = Path(base_dir)
    anchored = copy.deepcopy(document)
    for scanners_key in _spellings(anchored, "scanners"):
        scanners = anchored[scanners_key]
        if not isinstance(scanners, dict):
            continue
        for key, section in scanners.items():
            if not isinstance(key, str) or not isinstance(section, dict):
                continue
            for options_key in _spellings(section, "options"):
                if isinstance(section[options_key], dict):
                    _anchor_options(key, section[options_key], base)
    for sandbox_key in _spellings(anchored, "sandbox"):
        sandbox = anchored[sandbox_key]
        if not isinstance(sandbox, dict):
            continue
        for paths_key in _spellings(sandbox, "extra_read_paths"):
            paths = sandbox[paths_key]
            if isinstance(paths, list):
                sandbox[paths_key] = [anchored_path(path, base) for path in paths]
    return anchored


def _is_index(segment: str) -> bool:
    return segment == "-" or (segment.isascii() and segment.isdigit())


def _anchored_at(segments: Sequence[str], value: Any, base_dir: Path) -> Any:
    """``value``, set at the config path ``segments``, with its operator paths anchored.

    The value is placed in a document of its own at that path, anchored there by
    ``anchor_relative_paths``, and read back, so an override or a patch operation
    is anchored by exactly the rule a file is. A segment that is a list index
    (``0``, or ``-`` for an append) stands for an entry of a list.
    """
    document: Any = value
    for segment in reversed(segments):
        document = [document] if _is_index(segment) else {segment: document}
    anchored = anchor_relative_paths(document, base_dir)
    for segment in segments:
        anchored = anchored[0] if _is_index(segment) else anchored[segment]
    return anchored


def anchor_patch_operations(ops: Any, base_dir: Union[str, Path]) -> Any:
    """``patch`` operations of one file with the values they set anchored like its own.

    Only the ``value`` of an operation is changed; an operation that is not a
    mapping with a JSON pointer ``path`` is returned as it is, for
    ``config_sources._apply_patch`` to refuse.
    """
    if not isinstance(ops, list):
        return ops
    from automated_security_helper.config.config_sources import _unescape

    base = Path(base_dir)
    anchored_ops = []
    for op in ops:
        pointer = op.get("path") if isinstance(op, dict) else None
        if (
            not isinstance(pointer, str)
            # The root pointer is the empty string: an operation there replaces
            # the whole document, and the loader accepts it, so its value is
            # anchored as a whole document is.
            or (pointer and not pointer.startswith("/"))
            or "value" not in op
        ):
            anchored_ops.append(op)
            continue
        segments = (
            []
            if not pointer
            else [_unescape(segment) for segment in pointer[1:].split("/")]
        )
        value = _anchored_at(segments, op["value"], base)
        if op.get("op") == "test":
            value = _test_value(op["value"], value)
        anchored_ops.append(dict(op, value=value))
    return anchored_ops


class _EitherSpelling(str):  # noqa: SLOT000 -- a str subtype takes no non-empty __slots__; ``written`` is per instance
    """A ``test`` operation's value: the path as anchored, which also compares
    equal to the path as written (``_test_value``).

    ``jsonpatch`` compares the document's value against the operation's with
    ``!=``; a comparison against a subclass of ``str`` is the subclass's, so the
    test holds for either spelling. Printed, dumped or hashed it is the anchored
    path. Rebuilt with both spellings by ``copy.deepcopy``, which the loader's
    shadow apply makes of the operations.

    Made by ``_either_spelling``, which sets ``written`` on a new one after
    ``str`` has built it from the anchored path: the class takes no constructor
    of its own, since the package admits no ``__new__`` outside the text
    escapers' (``tests/unit/utils/test_shown_text_is_shown_once.py`` reads every
    module for one).
    """

    written: str

    def __eq__(self, other: object) -> bool:
        return (
            str.__eq__(self, other) is True or str.__eq__(self.written, other) is True
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    __hash__ = str.__hash__

    def __reduce__(self) -> Tuple[Any, Tuple[str, str]]:
        return (_either_spelling, (str(self), self.written))


def _either_spelling(anchored: str, written: str) -> _EitherSpelling:
    """An ``_EitherSpelling`` of the anchored path that also equals ``written``."""
    value = _EitherSpelling(anchored)
    value.written = written
    return value


def _test_value(written: Any, anchored: Any) -> Any:
    """A ``test`` operation's value, equal to its path as written and as anchored.

    A test compares its value with what the document holds and sets nothing.
    Every operator file and base is anchored before the merge, so a test of a
    same-directory relative path (``test: bandit.yaml`` in a file whose base set
    it) holds only against the anchored spelling; left as written, the test never
    matched and the operator's chain failed to load. A base the load left as
    written (a file inside the scanned tree) still holds the path as written. The
    value compares equal to either spelling, so the test passes against whichever
    one the document holds. A value that is not text is compared as written.
    """
    if (
        not isinstance(written, str)
        or not isinstance(anchored, str)
        or written == anchored
    ):
        return written
    return _either_spelling(anchored, written)


def anchor_override_paths(
    overrides: Optional[Sequence[str]], base_dir: Union[str, Path]
) -> List[str]:
    """``--config-overrides`` with each relative operator path anchored at ``base_dir``.

    ``base_dir`` is the working directory the operator ran ASH from. An override
    whose value holds no such path is returned exactly as given; one that does is
    rewritten with the anchored value, a list or mapping as JSON, which
    ``resolve_config.apply_config_overrides`` reads back as the same value.
    """
    from automated_security_helper.config.resolve_config import _parse_config_value

    base = Path(base_dir)
    rewritten: List[str] = []
    for override in overrides or []:
        key_path, separator, raw = str(override).partition("=")
        if not separator or not key_path.strip():
            rewritten.append(override)
            continue
        append = key_path.endswith("+")
        segments = key_path.removesuffix("+").strip().split(".")
        value = _parse_config_value(raw)
        if append and not isinstance(value, list):
            anchored = _anchored_at([*segments, "-"], value, base)
        else:
            anchored = _anchored_at(segments, value, base)
        if anchored == value:
            rewritten.append(override)
        elif isinstance(anchored, (list, dict)):
            rewritten.append(f"{key_path}={json.dumps(anchored)}")
        else:
            rewritten.append(f"{key_path}={anchored}")
    return rewritten
