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
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from automated_security_helper.utils.uri_separators import (
    root_text,
    sanitized_uri_text,
)

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
    file_path: Optional[str], source_dir: Optional[str | Path] = None
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
    """
    if not file_path:
        return None
    text = posixpath.normpath(sanitized_uri_text(str(file_path)))
    if not _is_absolute(text) or source_dir is None:
        return text
    for root in (source_dir, Path(source_dir).resolve()):
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
    identity: FindingIdentity, source_dir: Optional[str | Path]
) -> FindingIdentity:
    """*identity* with its file made relative to *source_dir* by :func:`relative_path`.

    For a consumer that knows the scan root: the Security Hub reporter has its
    context's source directory, while ``FlatVulnerability.from_sarif_result`` sees
    one result and keys its path as the result wrote it. Only an absolute path
    changes, so a converted file's key, which is relative to the converted root,
    is left as it is.
    """
    if source_dir is None:
        return identity
    file = relative_path(identity.base.get("file"), source_dir)
    if file == identity.base.get("file"):
        return identity
    return replace(identity, base={**identity.base, "file": file})


def _shared_fingerprint_values(
    identities: Sequence[FindingIdentity], bases: Sequence[str]
) -> Set[Tuple[str, str, str, str]]:
    """``(base, kind, key, value)`` that results with that base carry at more
    than one location; *bases* is the canonical base of each of *identities*."""
    locations: Dict[Tuple[str, str, str, str], Set[Tuple[Any, ...]]] = defaultdict(set)
    for identity, base in zip(identities, bases):
        for kind, pairs in identity.fingerprints:
            for name, value in pairs:
                locations[(base, kind, name, value)].add(identity.location)
    return {entry for entry, where in locations.items() if len(where) > 1}


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
    """
    bases: List[Dict[str, Any]] = []
    for identity in identities:
        base = dict(identity.base)
        if base.get("project") is None and default_project:
            base["project"] = default_project
        bases.append(base)
    canonical_bases = [canonical(base) for base in bases]
    shared = _shared_fingerprint_values(identities, canonical_bases)
    keys: List[Dict[str, Any]] = []
    by_location: Dict[str, List[int]] = defaultdict(list)
    for index, identity in enumerate(identities):
        key = dict(bases[index])
        for kind, pairs in identity.fingerprints:
            usable = [
                [name, value]
                for name, value in pairs
                if (canonical_bases[index], kind, name, value) not in shared
            ]
            if usable:
                key[kind] = usable
                break
        else:
            key["startLine"], key["endLine"] = identity.lines
        # Every key, fingerprinted or not: two results of one scanner and rule
        # that carry the same fingerprint value at the same lines and column are
        # not told apart by the value (it is shared only across locations), so
        # without this they got one key, one finding id and one Security Hub Id.
        by_location[canonical(key)].append(index)
        keys.append(key)
    for members in by_location.values():
        if len(members) < 2:
            continue
        seen: Dict[str, int] = defaultdict(int)
        for index in members:
            occurrence = identities[index].occurrence
            keys[index]["occurrence"] = occurrence
            if seen[occurrence]:
                keys[index]["ordinal"] = seen[occurrence]
            seen[occurrence] += 1
    return keys


def identity_key(
    identity: FindingIdentity, default_project: Optional[str] = None
) -> Dict[str, Any]:
    """*identity*'s key as if its result were the only one in its run."""
    return identity_keys([identity], default_project)[0]


def canonical(key: Mapping[str, Any]) -> str:
    """The key as one string: JSON with sorted keys and no whitespace."""
    return json.dumps(
        key, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def finding_id(key: Mapping[str, Any]) -> str:
    """``<scanner>-<rule>-<12 hex digits>``, the id of a flattened finding."""
    digest = hashlib.sha256(canonical(key).encode("utf-8")).hexdigest()
    return (
        f"{key.get('scanner')}-{key.get('rule') or 'unknown'}-"
        f"{digest[:FINDING_ID_DIGEST_LENGTH]}"
    )
