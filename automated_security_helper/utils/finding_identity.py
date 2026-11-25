# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What makes a finding the same finding from one scan to the next.

One definition of a finding's identity key, shared by the ``id`` of every
flattened finding (flat-json, CSV, the MCP tools) and the Security Hub reporter's
finding ``Id``, so that the two cannot disagree about whether two results are one
finding. The key is a JSON-serializable mapping; :func:`canonical` serializes it
with sorted keys. Each consumer hashes it its own way: :func:`finding_id` gives the
flattened ``<scanner>-<rule>-<12 hex digits>``, and the Security Hub reporter
``"ash/" + sha256(json.dumps([target, key], sort_keys=True))``.

The key of a result is:

* the scanner and the rule;
* the file, relative to the scan root (:func:`relative_path`), so checkouts on
  different machines agree. A file a converter wrote (a notebook converted to
  Python, a member extracted from an archive) is keyed by its path relative to
  the converted root, with ``"tree": "converted"``, so the key does not depend on
  where the output directory is;
* the package name and path, for a dependency finding (grype and npm-audit put
  every package of a lockfile at its line 1);
* the workspace project;
* the result's SARIF ``fingerprints``, or failing those its ``partialFingerprints``,
  as sorted ``[key, value]`` pairs under the kind's name, so that an edit above the
  finding does not re-key it. A value counts as absent when it is the placeholder
  ``"requires login"``, in any case (semgrep writes ``"matchBasedId/v1": "requires
  login"`` on every result), when it is empty, or when results of the run with the
  same scanner, rule, file, package, project and tree carry it at more than one location, a
  location being the lines and the start column, since then it does not tell
  those findings apart. The same value in another file or from another scanner
  does not count: the rest of the key tells those findings apart, and fixing one
  of them would otherwise re-key the other;
* without fingerprints, its start and end line.

Results of the run that share all of the above, fingerprinted or not (two secrets
on one line; two results of one scanner and rule carrying one fingerprint value at
one place), each get an ``occurrence``: the first 8 hex digits of
``sha256(json.dumps([start column or -1, message]))``, with ``json``'s default
separators, where the message is the masked one (with a converted file's path
replaced by the key's file). Taken from the finding's own content, so a newcomer
never takes an existing finding's id and removing one never hands its id to
another. Exact duplicates, with the same column and message, also get an
``ordinal`` in the order the scanner listed them: none for the first, then 1, 2.
A finding alone with its key carries no occurrence, so rewording its message does
not re-key it.

The project is the result's workspace project, or failing that the one the run's
results were written for.

Left out on purpose: the severity, which a newer scanner may re-rate without the
finding being a different one; and the package version, since upgrading to a
release that is still vulnerable is the same finding.

Known limitations: a finding identified by its location gets a new identity when
an edit above it moves it; only fingerprints avoid that, and few scanners emit
them. A finding that shares its key gets a new identity when its column changes or
its scanner rewords its message, and a finding alone with its key gets one when a
second finding with the same key appears. A fingerprinted finding is keyed by its
lines instead once a second result of its scanner and rule in its file carries the
same value at another location.

The Security Hub reporter takes its keys from :func:`identity_keys`, over each
``FlatVulnerability.identity`` with its file made relative to the reporter's
source directory first (:func:`relative_to_scan_root`). A flattened finding's
id is computed without a source directory, so the two differ only for a result
that names a file inside the scan root by an absolute path, and for a result of
the same scanner and rule that names that file by its relative path and carries
one of its fingerprint values: the reporter counts that value as shared between
the two, and the flattened findings do not.

The same secret from more than one scanner
------------------------------------------

The identity key starts with the scanner and the rule, so two scanners that find
one secret give two findings with two identities, and nothing in either says they
are about the same thing. ASH keeps both: it does not deduplicate. What it adds is
a second key that leaves the scanner and the rule out
(:func:`secret_location_key`): the file, the start line, the workspace project and,
for a converted file, the tree. Findings that share it are still separate findings,
each with its own identity; the key only lets a consumer put them side by side.

Only a secret detection has one, because only there does the place say what the
problem is: a credential at a line is that credential, whichever scanner read it.
A SAST or IaC check does not get one (two rules that fire on one line are two
problems), and neither does a dependency finding (every package of a lockfile sits
at its line 1). A secret detection with no file or no start line has none either.

Known limitations: two secrets on one line share the key, since the column is not
in it (few scanners report one, and those that do disagree on where a secret
starts); and scanners that place one secret on different lines do not share it.

The frame boundary
------------------

A run's keys are derived on a polars frame (:func:`identity_keys`): which
fingerprint values are shared is a group-by over every result's values, which
kind of fingerprint a result is keyed by is a min over what is left, and the
occurrence and ordinal are a count over the key and a cumulative count within the
key and the occurrence. The per-result parts stay on the host: the result's
:class:`FindingIdentity` is built one result at a time by the extractors, its
occurrence digest is a SHA-256 of that result's own column and message, and the
key is a mapping with arbitrary nesting. A run of one result takes no frame
(:func:`identity_key`): nothing it holds can be shared or collide.

:func:`_identity_frame` is the run as a frame, for the consumers that group,
join or count findings by identity. It has one row per identity, in the order
given, with these columns:

========================  =========  =============================================
``i``                     Int64      the identity's position in the run
``scanner``               String     the key's scanner
``rule``                  String     the key's rule (``"unknown"`` for none)
``file``                  String     the key's file; null for none
``key``                   String     :func:`canonical` of the whole key, with its
                                     ``occurrence`` and ``ordinal``
``fingerprinted``         Boolean    whether the key is keyed by a fingerprint
                                     (:func:`key_is_fingerprinted`)
``occurrence``            String     the key's occurrence; null when the identity
                                     is alone with its key
``ordinal``               Int64      the key's ordinal; null for the first of its
                                     exact duplicates
``id``                    String     :func:`finding_id` of the key; present only
                                     for ``ids=True``
========================  =========  =============================================

Every String column holds text through :func:`~automated_security_helper.utils.
frame_text.wire`, because a path can hold a lone surrogate (an ``os.fsdecode`` of
undecodable bytes) and polars strings are UTF-8: ``wire`` is one-to-one, so two
columns are equal exactly when the texts are, and ``unwire`` gives the text back.
A mapping key's line numbers and columns, which are unbounded Python ints, appear
only inside ``key``. The frame is built from the same keys :func:`identity_keys`
returns, so a consumer never recomputes an identity: ``key`` joins with the
``key`` of another run's frame as the old ``canonical(key)`` compared.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence, Tuple

from automated_security_helper.utils.frame_ops import ordinal_over
from automated_security_helper.utils.frame_text import wire, wire_cell
from automated_security_helper.utils.uri_separators import (
    root_text,
    sanitized_uri_text,
)

if TYPE_CHECKING:
    import polars as pl

#: Hex digits of the digest in a flattened finding's id. 48 bits: two findings of
#: one scanner and rule collide with odds near n**2 / 2**49, about 1 in 5 million
#: at 10,000 findings of a single rule.
FINDING_ID_DIGEST_LENGTH = 12

#: Hex digits of a location-keyed finding's occurrence. Only findings with the same
#: scanner, rule, file and lines are told apart by it, so 32 bits is ample.
OCCURRENCE_DIGEST_LENGTH = 8

#: Fingerprint values that do not identify anything, compared stripped and in
#: lower case. An empty value is one too (:func:`result_fingerprints`): a lone
#: result whose only fingerprint is "" was keyed by scanner, rule and file alone,
#: and a later, different finding of that rule in that file took its id.
PLACEHOLDER_FINGERPRINT_VALUES = frozenset({"requires login", ""})

#: The fingerprint kinds, in the order they are preferred.
FINGERPRINT_KINDS = ("fingerprints", "partialFingerprints")

#: The ``tree`` of a file a converter wrote.
CONVERTED_TREE = "converted"

#: The SARIF result property the scanner executor records a converted file's path
#: relative to the converted root in (``utils/scan_output_dirs``).
CONVERTED_PATH_PROPERTY = "converted_path"

_DRIVE = re.compile(r"^[A-Za-z]:/")

Fingerprints = Tuple[Tuple[str, Tuple[Tuple[str, str], ...]], ...]


@dataclass(frozen=True)
class FindingIdentity:
    """One result's identity, before the run it belongs to is considered.

    Attributes:
        base: The key's fields every result has: scanner, rule, file, package,
            project, and ``tree`` for a converted file.
        lines: The start and end line.
        column: The start column, or None.
        fingerprints: Each fingerprint kind the result carries, in preference
            order, as sorted ``(key, value)`` pairs, placeholders removed.
        occurrence: The occurrence digest of the column and message.
    """

    base: Mapping[str, Any]
    lines: Tuple[Optional[int], Optional[int]]
    column: Optional[int] = None
    fingerprints: Fingerprints = ()
    occurrence: str = ""

    @property
    def location(self) -> Tuple[Any, ...]:
        """Where the result is, for telling a shared fingerprint value."""
        return (self.base.get("tree"), self.base.get("file"), *self.lines, self.column)


def _is_absolute(text: str) -> bool:
    return text.startswith("/") or bool(_DRIVE.match(text))


def relative_path(
    file_path: Optional[str],
    source_dir: Optional[str | Path] = None,
    *,
    resolve_root: bool = True,
) -> Optional[str]:
    """*file_path* as an identity key writes it.

    The backslashes of a drive-letter or UNC path become ``/``. Any other
    backslash is part of a POSIX file name and is kept, so ``a\\b.py`` and
    ``a/b.py`` are two findings' files: sanitizing already wrote ``/`` for the
    separators of a path made on Windows (``utils/uri_separators.py``). Decided
    from the path alone, not from *source_dir*, because the flattened findings
    have no scan root and their ``id`` and the Security Hub ``Id`` must come from
    the same key. ``.`` segments are dropped and ``..`` segments are collapsed.
    An absolute path inside *source_dir* is made relative to it; any other
    absolute path stays absolute. A relative path is taken as relative to the
    scan root already.

    *resolve_root* also tries ``Path(source_dir).resolve()`` as the root, after
    *source_dir* as spelled. The resolved arm exists for paths a scan recorded
    under a symbolic-link-resolved root, which a caller on the scanning host
    still holds as the unresolved spelling. Passing False compares only the
    spelling given, as the offline export does (it must not resolve paths on a
    host that is not the scanning one), and changes the identity of a path that
    only the resolved arm matched: it stays absolute, and so does its Id.
    """
    if not file_path:
        return None
    text = posixpath.normpath(sanitized_uri_text(str(file_path)))
    if not _is_absolute(text) or source_dir is None:
        return text
    for root in (
        (source_dir, Path(source_dir).resolve()) if resolve_root else (source_dir,)
    ):
        spelled = posixpath.normpath(root_text(root))
        if text == spelled:
            return "."
        prefix = spelled.rstrip("/") + "/"
        if text.startswith(prefix):
            return text[len(prefix) :]
    return text


def result_fingerprints(result: Any) -> Fingerprints:
    """The result's SARIF fingerprints of each kind, sorted, placeholders removed.

    A value that is empty, or only whitespace, identifies nothing and is left
    out like the ``"requires login"`` placeholder; a kind whose every value is
    one is absent, so the result is keyed by its lines instead.
    """
    found = []
    for kind in FINGERPRINT_KINDS:
        values = getattr(result, kind, None)
        if not isinstance(values, dict):
            continue
        pairs = tuple(
            sorted(
                (str(k), str(v))
                for k, v in values.items()
                if v is not None
                and str(v).strip().lower() not in PLACEHOLDER_FINGERPRINT_VALUES
            )
        )
        if pairs:
            found.append((kind, pairs))
    return tuple(found)


def result_start_column(result: Any) -> Optional[int]:
    """``region.startColumn`` of the result's first location, or None."""
    try:
        location = result.locations[0].physicalLocation
        region = getattr(location, "root", location).region
    except (AttributeError, IndexError, TypeError):
        return None
    column = getattr(region, "startColumn", None)
    return column if isinstance(column, int) else None


def occurrence_digest(column: Optional[int], message: Optional[str]) -> str:
    """The first 8 hex digits of ``sha256(json.dumps([column or -1, message]))``.

    ``json.dumps`` with its defaults, ``", "`` between items and non-ASCII
    escaped, as the Security Hub reporter computes it. A column of 0 stays 0.
    """
    text = json.dumps([-1 if column is None else column, message or ""])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:OCCURRENCE_DIGEST_LENGTH]


def finding_identity(
    *,
    scanner: str,
    rule_id: Optional[str],
    file_path: Optional[str],
    line_start: Optional[int],
    line_end: Optional[int],
    package_name: Optional[str] = None,
    package_path: Optional[str] = None,
    workspace_project: Optional[str] = None,
    fingerprints: Fingerprints = (),
    column: Optional[int] = None,
    message: Optional[str] = None,
    converted: bool = False,
) -> FindingIdentity:
    """One result's identity; see the module docstring for what is in it.

    *file_path* is used as given: pass it through :func:`relative_path` first, or,
    with *converted*, pass the path relative to the converted root. *fingerprints*
    is what :func:`result_fingerprints` returns. *message* is the masked message
    with the finding's own path replaced by *file_path*.
    """
    base: Dict[str, Any] = {
        "scanner": scanner,
        "rule": rule_id or "unknown",
        "file": file_path,
        "package": [package_name, package_path],
        "project": workspace_project,
    }
    if converted:
        base["tree"] = CONVERTED_TREE
    return FindingIdentity(
        base=base,
        lines=(line_start, line_end),
        column=column,
        fingerprints=fingerprints,
        occurrence=occurrence_digest(column, message),
    )


def relative_to_scan_root(
    identity: FindingIdentity,
    source_dir: Optional[str | Path],
    *,
    resolve_root: bool = True,
) -> FindingIdentity:
    """*identity* with its file made relative to *source_dir* by :func:`relative_path`.

    For a consumer that knows the scan root: the Security Hub reporter has its
    context's source directory, while ``FlatVulnerability.from_sarif_result`` sees
    one result and keys its path as the result wrote it. Only an absolute path
    changes, so a converted file's key, which is relative to the converted root,
    is left as it is.

    *resolve_root* is passed to :func:`relative_path`: True also matches a path
    recorded under the symbolic-link-resolved form of *source_dir*, False only
    the spelling given, which changes the identity (the file in its key) of a
    path that only the resolved form matched.
    """
    if source_dir is None:
        return identity
    file = relative_path(
        identity.base.get("file"), source_dir, resolve_root=resolve_root
    )
    if file == identity.base.get("file"):
        return identity
    return replace(identity, base={**identity.base, "file": file})


def _run_bases(
    identities: Sequence[FindingIdentity], default_project: Optional[str]
) -> List[Dict[str, Any]]:
    """Each identity's base with the run's default project folded in."""
    bases: List[Dict[str, Any]] = []
    for identity in identities:
        base = dict(identity.base)
        if base.get("project") is None and default_project:
            base["project"] = default_project
        bases.append(base)
    return bases


def _fingerprint_choices(
    identities: Sequence[FindingIdentity], canonical_bases: Sequence[str]
) -> Dict[int, Tuple[int, List[int]]]:
    """Which fingerprints key each result of the run: ``index -> (rank, positions)``.

    ``rank`` is the place of the chosen kind in the identity's own order of kinds
    and ``positions`` the places, in the kind's sorted pairs, of the pairs that
    are not shared. A result with no entry is keyed by its lines.

    A value is shared when results with the same base, kind and name carry it at
    more than one location: a group-by over every result's pairs. The kind a
    result is keyed by is the first one with a pair left, a minimum over the
    pairs that are not shared.
    """
    import polars as pl

    columns: Dict[str, List[Any]] = {
        name: []
        for name in ("i", "rank", "pos", "kind", "name", "value", "base", "loc")
    }
    for index, identity in enumerate(identities):
        if not identity.fingerprints:
            continue
        base = wire(canonical_bases[index])
        # The location as one text: a tuple of a path, lines that can be larger
        # than 64 bits and a column cannot be a column of its own, and the text
        # is equal exactly when the tuple is.
        location = wire(json.dumps(list(identity.location), ensure_ascii=False))
        for rank, (kind, pairs) in enumerate(identity.fingerprints):
            for pos, (name, value) in enumerate(pairs):
                columns["i"].append(index)
                columns["rank"].append(rank)
                columns["pos"].append(pos)
                columns["kind"].append(wire(kind))
                columns["name"].append(wire(name))
                columns["value"].append(wire(value))
                columns["base"].append(base)
                columns["loc"].append(location)
    if not columns["i"]:
        return {}
    schema = {
        "i": pl.Int64,
        "rank": pl.Int64,
        "pos": pl.Int64,
        "kind": pl.String,
        "name": pl.String,
        "value": pl.String,
        "base": pl.String,
        "loc": pl.String,
    }
    values = pl.DataFrame(columns, schema=schema)
    counted = ["base", "kind", "name", "value"]
    shared = (
        values.group_by(counted)
        .agg(pl.col("loc").n_unique().alias("places"))
        .filter(pl.col("places") > 1)
        .select(counted)
    )
    usable = values.join(shared, on=counted, how="anti")
    chosen = (
        usable.join(usable.group_by("i").agg(pl.col("rank").min()), on=["i", "rank"])
        .sort(["i", "pos"])
        .group_by("i", maintain_order=True)
        .agg(pl.col("rank").first(), pl.col("pos"))
    )
    return {index: (rank, positions) for index, rank, positions in chosen.iter_rows()}


def _located_keys(
    identities: Sequence[FindingIdentity], keys: List[Dict[str, Any]]
) -> None:
    """Give *keys*, which are one run's keys before any occurrence, their
    ``occurrence`` and ``ordinal``, in place.

    Keys that are equal (:func:`canonical`) are a group; a group of more than
    one gives each member its identity's occurrence, and a member that repeats an
    earlier member's occurrence the count of members before it with that
    occurrence. Every key, fingerprinted or not: two results of one scanner and
    rule that carry the same fingerprint value at the same lines and column are
    not told apart by the value (it is shared only across locations), so without
    this they got one key, one finding id and one Security Hub Id.
    """
    import polars as pl

    placed = pl.DataFrame(
        {
            "i": list(range(len(keys))),
            "key": [wire(canonical(key)) for key in keys],
            "occurrence": [wire(identity.occurrence) for identity in identities],
        },
        schema={"i": pl.Int64, "key": pl.String, "occurrence": pl.String},
    )
    shared = placed.with_columns(
        pl.len().over("key").alias("members"),
        ordinal_over("key", "occurrence").alias("ordinal"),
    ).filter(pl.col("members") > 1)
    for index, ordinal in shared.select("i", "ordinal").iter_rows():
        keys[index]["occurrence"] = identities[index].occurrence
        if ordinal:
            keys[index]["ordinal"] = ordinal


def identity_keys(
    identities: Sequence[FindingIdentity], default_project: Optional[str] = None
) -> List[Dict[str, Any]]:
    """The identity key of each of *identities*, which are one run's results.

    Returned in the order given. The run matters three times: a fingerprint value
    that results with the same scanner, rule, file, package, project and tree
    carry at more than one location counts as absent, results that share a key,
    fingerprinted or keyed by their lines, get an ``occurrence``, and exact
    duplicates among those an ``ordinal``. *default_project* is the workspace
    project the run's results were written for, used for a result that names
    none, before the fingerprint values are counted.

    Derived on a frame (see the module docstring); the keys are the mappings
    this function has always returned, with their fields in the same order.
    """
    if not identities:
        return []
    bases = _run_bases(identities, default_project)
    choices = _fingerprint_choices(identities, [canonical(base) for base in bases])
    keys: List[Dict[str, Any]] = []
    for index, identity in enumerate(identities):
        key = dict(bases[index])
        if index in choices:
            rank, positions = choices[index]
            kind, pairs = identity.fingerprints[rank]
            key[kind] = [[pairs[pos][0], pairs[pos][1]] for pos in positions]
        else:
            key["startLine"], key["endLine"] = identity.lines
        keys.append(key)
    _located_keys(identities, keys)
    return keys


def _identity_frame(
    identities: Sequence[FindingIdentity],
    default_project: Optional[str] = None,
    *,
    ids: bool = False,
) -> "pl.DataFrame":
    """The run of *identities* as a frame; the columns are in the module docstring.

    *ids* adds the ``id`` column, :func:`finding_id` of each key, which
    raises for a key holding a lone surrogate as :func:`finding_id` does.
    """
    import polars as pl

    keys = identity_keys(identities, default_project)

    columns: Dict[str, List[Any]] = {
        "i": list(range(len(keys))),
        "scanner": [wire_cell(key.get("scanner")) for key in keys],
        "rule": [wire_cell(key.get("rule")) for key in keys],
        "file": [wire_cell(key.get("file")) for key in keys],
        "key": [wire(canonical(key)) for key in keys],
        "fingerprinted": [key_is_fingerprinted(key) for key in keys],
        "occurrence": [wire_cell(key.get("occurrence")) for key in keys],
        "ordinal": [key.get("ordinal") for key in keys],
    }
    schema: Dict[str, Any] = {
        "i": pl.Int64,
        "scanner": pl.String,
        "rule": pl.String,
        "file": pl.String,
        "key": pl.String,
        "fingerprinted": pl.Boolean,
        "occurrence": pl.String,
        "ordinal": pl.Int64,
    }
    if ids:
        columns["id"] = [wire(finding_id(key)) for key in keys]
        schema["id"] = pl.String
    return pl.DataFrame(columns, schema=schema)


def identity_key(
    identity: FindingIdentity, default_project: Optional[str] = None
) -> Dict[str, Any]:
    """*identity*'s key as if its result were the only one in its run.

    Nothing a lone result holds can be shared with another or collide with one,
    so its key is the first of its fingerprint kinds that has a pair, else its
    lines, with no frame: this runs for every result the extractors flatten.
    ``identity_keys([identity], default_project)[0]`` is the same mapping.
    """
    key = _run_bases([identity], default_project)[0]
    for kind, pairs in identity.fingerprints:
        usable = [[name, value] for name, value in pairs]
        if usable:
            key[kind] = usable
            break
    else:
        key["startLine"], key["endLine"] = identity.lines
    return key


def canonical(key: Mapping[str, Any]) -> str:
    """The key as one string: JSON with sorted keys and no whitespace."""
    return json.dumps(
        key, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


#: Key fields that say where a result is or which of several it is, not what it is.
_LOCATION_KEY_FIELDS = frozenset(
    {"startLine", "endLine", "occurrence", "ordinal", *FINGERPRINT_KINDS}
)


def key_is_fingerprinted(key: Optional[Mapping[str, Any]]) -> bool:
    """Whether the assigned identity *key* is keyed by a fingerprint, not by lines."""
    return any(kind in (key or {}) for kind in FINGERPRINT_KINDS)


def key_base(key: Mapping[str, Any]) -> Dict[str, Any]:
    """*key* without its location fields: scanner, rule, file, package, project, tree.

    The project is the one :func:`identity_keys` folded in, so a caller does not
    re-apply the run's default project.
    """
    return {
        name: value for name, value in key.items() if name not in _LOCATION_KEY_FIELDS
    }


def secret_location_key(
    identity: FindingIdentity, default_project: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Where a secret detection is, without the scanner or the rule that found it.

    The file, the start line and the workspace project, plus ``tree`` for a
    converted file, as the identity key spells them, so that two scanners
    reporting one secret get equal keys. *default_project* is the project the
    run's results were written for, folded in as :func:`identity_keys` does.
    None when the identity names no file or no start line: there is then no
    place to compare.

    The caller decides that the result is a secret detection; see the module
    docstring for why no other kind of finding has such a key.
    """
    file_path = identity.base.get("file")
    line = identity.lines[0]
    if not file_path or not isinstance(line, int) or isinstance(line, bool):
        return None
    key: Dict[str, Any] = {
        "file": file_path,
        "startLine": line,
        "project": identity.base.get("project") or default_project or None,
    }
    if identity.base.get("tree") is not None:
        key["tree"] = identity.base["tree"]
    return key


def finding_id(key: Mapping[str, Any]) -> str:
    """``<scanner>-<rule>-<12 hex digits>``, the id of a flattened finding."""
    digest = hashlib.sha256(canonical(key).encode("utf-8")).hexdigest()
    return (
        f"{key.get('scanner')}-{key.get('rule') or 'unknown'}-"
        f"{digest[:FINDING_ID_DIGEST_LENGTH]}"
    )
