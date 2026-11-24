"""Taxonomy identifiers (CVE, CWE) read off the standard SARIF fields.

One reading of "what CVE does a rule id name" and "what CWE does a tag name",
shared by the flat finding model and the OCSF reporter so the two views of a
finding cannot drift apart. The readings are generic: they look at SARIF
standard values (``result.ruleId``, ``properties.tags``) and know no scanner.

A scanner whose rule ids or tags use an encoding these patterns do not reach
should normalize its own SARIF to the tags convention in its adapter before
the SARIF leaves it. Widening the patterns here per scanner would be the wrong
place for that knowledge.

This module imports nothing from the package, so any module may import it.
"""

import re
from typing import Any, Iterable, List, Optional

#: A CVE identifier at the head of a rule id. Trivy names a rule by the CVE
#: (``CVE-2019-20477``) and grype by the CVE and the package
#: (``CVE-2022-40897-setuptools``), so the identifier is read off the front and
#: the package suffix is left behind. A scanner's own rule id (``B602``), an
#: advisory id (``GHSA-...``), or an id that only contains a CVE id further in
#: names no CVE.
CVE_RULE_ID = re.compile(r"^(CVE-\d{4}-\d{4,})(?:-|$)", re.IGNORECASE)

#: A CWE in a tag, in the two spellings in common use: the code scanning
#: convention ``external/cwe/cwe-78`` and ``CWE-798: Use of Hard-coded
#: Credentials``. A tag that only mentions a CWE further in is not one.
CWE_TAG = re.compile(r"^(?:external/cwe/)?cwe-(\d+)(?::|$)", re.IGNORECASE)


def cve_of_rule_id(rule_id: Any) -> Optional[str]:
    """The CVE the rule id names, in upper case, or None."""
    if not isinstance(rule_id, str):
        return None
    match = CVE_RULE_ID.match(rule_id.strip())
    return match.group(1).upper() if match else None


def cwes_of_tags(tags: Iterable[Any]) -> List[str]:
    """The CWEs the tags name, as ``CWE-<n>``: each once, in the order written."""
    found: List[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        match = CWE_TAG.match(tag.strip())
        if match is None:
            continue
        cwe = f"CWE-{match.group(1)}"
        if cwe not in found:
            found.append(cwe)
    return found
