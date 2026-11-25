# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Per-result layer digests for an image scan, from trivy's JSON report.

trivy's SARIF writer carries no layer data: a result says what was found and
where in the image's filesystem, never which layer put it there. trivy's JSON
report does (``Layer.Digest`` and ``Layer.DiffID`` on each vulnerability,
secret and misconfiguration). So an image scan with trivy runs one more
``--format json`` pass of the same invocation and joins the two reports on
what both name, and the ``layerDigest`` result property
(``utils/finding_identity.IMAGE_LAYER_DIGEST_PROPERTY``) is written where the
join is unambiguous. The flat extractor reads it into the ``layer_digest``
column; it is attribution only and is not part of a finding's id.

The join keys, per finding kind:

- vulnerability: rule id (the CVE) and package name;
- secret: rule id, in-image path and start line;
- misconfiguration: rule id and in-image path.

A key that more than one layer carries with different digests (the same CVE in
the same package at two layers) matches no result: the column stays empty
rather than naming a layer that may be the wrong one.

The digest is ``Layer.Digest`` (the layer's compressed blob digest, what a
registry names) when trivy knows it, else ``Layer.DiffID`` (the digest of the
uncompressed layer, which is all some saved archives carry).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from automated_security_helper.utils.finding_identity import (
    IMAGE_LAYER_DIGEST_PROPERTY,
)

#: A join key, and the layer digest it resolves to (None when ambiguous).
LayerIndex = Dict[Tuple[Any, ...], Optional[str]]


def json_argv(final_args: List[str], json_path: Path) -> Optional[List[str]]:
    """The invocation *final_args* ran, asking for a JSON report at *json_path*.

    The format and output options are replaced in whichever spelling the
    argv carries (two tokens, or ``--format=sarif``); every other token is the
    run's own, so the JSON pass reads the same image the same way. None when
    the argv names no ``--format`` and ``--output``, which this module cannot
    translate without guessing.
    """
    argv = list(final_args)
    saw_format = saw_output = False
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in ("--format", "-f") and index + 1 < len(argv):
            argv[index + 1] = "json"
            saw_format = True
            index += 2
            continue
        if token.startswith("--format="):
            argv[index] = "--format=json"
            saw_format = True
        elif token in ("--output", "-o") and index + 1 < len(argv):
            argv[index + 1] = json_path.as_posix()
            saw_output = True
            index += 2
            continue
        elif token.startswith("--output="):
            argv[index] = f"--output={json_path.as_posix()}"
            saw_output = True
        index += 1
    if not (saw_format and saw_output):
        return None
    return argv


def _layer_digest(entry: Any) -> Optional[str]:
    layer = entry.get("Layer") if isinstance(entry, dict) else None
    if not isinstance(layer, dict):
        return None
    for name in ("Digest", "DiffID"):
        value = layer.get(name)
        if isinstance(value, str) and value:
            return value
    return None


def _remember(index: LayerIndex, key: Tuple[Any, ...], digest: Optional[str]) -> None:
    if digest is None:
        return
    if key in index and index[key] != digest:
        index[key] = None
    else:
        index[key] = digest


def layer_index(report: Any) -> LayerIndex:
    """The join index of a trivy JSON report (the parsed document)."""
    index: LayerIndex = {}
    results = report.get("Results") if isinstance(report, dict) else None
    for block in results or []:
        if not isinstance(block, dict):
            continue
        target = block.get("Target")
        for entry in block.get("Vulnerabilities") or []:
            if isinstance(entry, dict):
                _remember(
                    index,
                    ("vuln", entry.get("VulnerabilityID"), entry.get("PkgName")),
                    _layer_digest(entry),
                )
        for entry in block.get("Secrets") or []:
            if isinstance(entry, dict):
                _remember(
                    index,
                    ("secret", entry.get("RuleID"), target, entry.get("StartLine")),
                    _layer_digest(entry),
                )
        for entry in block.get("Misconfigurations") or []:
            if isinstance(entry, dict):
                _remember(
                    index,
                    ("misconfig", entry.get("ID"), target),
                    _layer_digest(entry),
                )
    return index


def read_layer_index(json_path: Path) -> LayerIndex:
    """:func:`layer_index` of the report at *json_path*; empty when unreadable."""
    try:
        document = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return layer_index(document)


def _result_keys(result: Any, package: Optional[str]) -> List[Tuple[Any, ...]]:
    """The index keys a SARIF result could match, most specific first."""
    rule = getattr(result, "ruleId", None)
    uri = line = None
    for location in getattr(result, "locations", None) or []:
        physical = getattr(location, "physicalLocation", None)
        root = getattr(physical, "root", None)
        artifact = getattr(root, "artifactLocation", None)
        region = getattr(root, "region", None)
        uri = getattr(artifact, "uri", None)
        line = getattr(region, "startLine", None)
        break
    if package is not None:
        return [("vuln", rule, package)]
    return [("secret", rule, uri, line), ("misconfig", rule, uri)]


def attach_layer_digests(sarif_report: Any, index: LayerIndex, package_of: Any) -> int:
    """Write ``layerDigest`` on each result *index* resolves; the count written.

    *package_of* maps a result's message text to the package name it is about
    (None for a result that is not a package vulnerability); the scanner passes
    its own message reader so the one reading of trivy's message template is
    not copied here.
    """
    from automated_security_helper.schemas.sarif_schema_model import PropertyBag

    if not index:
        return 0
    written = 0
    for run in getattr(sarif_report, "runs", None) or []:
        for result in getattr(run, "results", None) or []:
            message = getattr(getattr(result, "message", None), "root", None)
            package = package_of(getattr(message, "text", None))
            digest = None
            for key in _result_keys(result, package):
                if index.get(key):
                    digest = index[key]
                    break
            if digest is None:
                continue
            if result.properties is None:
                result.properties = PropertyBag()
            setattr(result.properties, IMAGE_LAYER_DIGEST_PROPERTY, digest)
            written += 1
    return written
