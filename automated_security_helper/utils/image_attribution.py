# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Attribution the scanner executor records on every image-scan result.

The mechanism is ``mark_converted_results``' (``utils/scan_output_dirs``): the
executor stamps result properties after a scan, and the flat extractor reads
them back by the names ``utils/finding_identity`` exports. For an image scan the
properties are the subject itself:

- ``imageRef``: the locator as submitted (``ImageLocator.shown()``), always;
- ``imageDigest``: the image's sha256 digest: the tool's own run output when it
  names one, else the locator's ``resolved_digest``, else the digest a pinned
  reference (``repo@sha256:...``) states. The executor never asks an engine
  itself;
- ``layerDigest``: written by the scanner, not here. trivy's SARIF carries no
  layer, so its image scan joins its JSON report (``utils/image_layer_digests``)
  onto the results; grype and syft name none, so their results have none. The
  property name is the contract: any tool or plugin post-process that writes it
  flows through to the flat columns.

The identity keys on the digest when there is one, else the submitted ref
(``finding_identity``'s ``image`` argument), so two scans of one pinned image
agree across machines while a bare tag rescan after a push is a new subject.
"""

import re
from typing import Any, Optional

from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.utils.finding_identity import (
    IMAGE_DIGEST_PROPERTY,
    IMAGE_REF_PROPERTY,
)

#: A resolved image digest as tools write it: ``sha256:`` then 64 hex digits.
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}$")


def _digest_text(value: Any) -> Optional[str]:
    """*value* as a digest, or None: the ``sha256:...`` tail of a string.

    Accepts the bare form (``sha256:<hex>``, trivy's run-level ``imageID``) and
    the repo-digest form (``alpine@sha256:<hex>``, entries of ``repoDigests``).
    """
    if not isinstance(value, str):
        return None
    tail = value.rsplit("@", 1)[-1]
    return tail if _DIGEST.fullmatch(tail) else None


def image_scan_source(image: ImageLocator) -> str:
    """The ``scan_source`` an image scan records: ``image:<digest>`` or ``image:<ref>``.

    The scope a reporter that archives resolved findings compares (aws-security-hub
    reads "not reported" as "fixed" within one scope only). It names the image by
    its digest when the scan knows one (the locator's ``resolved_digest``, or the
    digest a pinned reference states), so two tags of one image are one scope and
    a tag that moves to another image is a new one: the findings of the image it
    left are not archived as fixed by a scan of the image it now names. With no
    digest it names the submitted reference or payload path, as before. The
    ``image:`` prefix keeps it from reading as a directory of the same name, and
    no repository scope (a directory or ``.``) can equal it.
    """
    digest = _digest_text(image.resolved_digest) or _digest_text(image.ref)
    return f"image:{digest}" if digest is not None else f"image:{image.shown()}"


def image_digest_of_run(run: Any) -> Optional[str]:
    """The subject image's digest, where *run*'s own properties name one.

    trivy's SARIF writer records ``imageID`` and ``repoDigests`` at the run
    level for an image scan; ``imageID`` is preferred because it names the
    image's own manifest where a repo digest names the registry's. A run whose
    properties carry neither (grype's, syft has no SARIF) resolves nothing, and
    the identity then keys on the submitted ref.
    """
    properties = getattr(run, "properties", None)
    if properties is None:
        return None
    for name in ("imageID", "repoDigests"):
        value = getattr(properties, name, None)
        if isinstance(value, (list, tuple)):
            for entry in value:
                digest = _digest_text(entry)
                if digest is not None:
                    return digest
        else:
            digest = _digest_text(value)
            if digest is not None:
                return digest
    return None


def mark_image_results(sarif_report: Any, image: Optional[ImageLocator]) -> int:
    """Record, on each result of an image scan, which image it is about.

    ``imageRef`` on every result, and ``imageDigest`` where the result's run
    resolved one (:func:`image_digest_of_run`). Runs before suppressions are
    applied, so an ``image:``-scoped suppression can match, and before the flat
    extractor keys the result, so the identity carries the image component.

    Returns:
        The number of results marked.
    """
    from automated_security_helper.schemas.sarif_schema_model import PropertyBag

    if image is None:
        return 0
    shown = image.shown()
    marked = 0
    # The tool's own run output names the image it read. Failing that, the
    # locator's: an engine's resolved digest, else the digest a pinned reference
    # (``repo@sha256:...``) states itself.
    fallback = _digest_text(image.resolved_digest) or _digest_text(image.ref)
    for run in getattr(sarif_report, "runs", None) or []:
        digest = image_digest_of_run(run) or fallback
        for result in getattr(run, "results", None) or []:
            if result.properties is None:
                result.properties = PropertyBag()
            # Extra properties: PropertyBag allows them, as converted_path and
            # the workspace aggregator's workspace_project already are.
            setattr(result.properties, IMAGE_REF_PROPERTY, shown)
            if digest is not None:
                setattr(result.properties, IMAGE_DIGEST_PROPERTY, digest)
            marked += 1
    return marked
