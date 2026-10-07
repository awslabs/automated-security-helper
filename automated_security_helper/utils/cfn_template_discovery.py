# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which files in a scan are CloudFormation templates, decided the way cfn-nag decides.

Why this module exists
----------------------
cfn-lint and cfn-guard need the same answer cfn-nag already gives: a template is a
``.json``/``.yaml``/``.yml`` file in the scan set that ``cfn_template_model`` models as
CloudFormation. Two scanners that disagree about which files are templates would report
coverage nobody could reconcile -- a file linted by one and silently skipped by the
other. So the selection is written once here, as a copy of the loop in
``CfnNagScanner.scan``, and the two new scanners call it.

cfn-nag does not call this. Its loop is left exactly as it is; changing cfn-nag was out
of scope for adding the new scanners. ``tests/unit/utils/test_cfn_template_discovery.py``
holds the two to the same answer on a fixture tree instead, so a change to either side
fails a test.

The three outcomes per file
---------------------------
* a template: returned in ``templates``;
* not CloudFormation (unparseable as YAML/JSON, or no ``Resources`` mapping): skipped,
  as cfn-nag skips it;
* CloudFormation the model rejects (``CloudFormationTemplateModelError``): returned in
  ``unmodelable`` with the reason, so the caller counts a failed target rather than
  letting the file vanish. That is the distinction ``cfn_template_model`` documents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, List, Literal, Tuple

from automated_security_helper.utils.cfn_template_model import (
    CloudFormationTemplateModelError,
    get_model_from_template,
)
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.base.plugin_context import PluginContext

_TEMPLATE_SUFFIXES = (".json", ".yaml", ".yml")


@dataclass
class TemplateDiscovery:
    """The templates in one target, and the CloudFormation files that could not be modeled."""

    templates: List[Path] = field(default_factory=list)
    unmodelable: List[Tuple[Path, str]] = field(default_factory=list)


def candidate_files(
    context: "PluginContext", target_type: Literal["source", "converted"]
) -> List[Path]:
    """The JSON/YAML files cfn-nag would consider for ``target_type``, sorted.

    The same two sources ``CfnNagScanner.scan`` reads: the converted work directory's
    files for a converted target, and the scan set otherwise. Sorted so runs are
    reproducible regardless of filesystem enumeration order.
    """
    if target_type == "converted":
        found = [str(p) for p in Path(context.work_dir).glob("**/*.*")]
    else:
        found = scan_set(source=str(context.source_dir), output=str(context.output_dir))
    selected = {
        Path(f) for f in found if any(str(f).endswith(s) for s in _TEMPLATE_SUFFIXES)
    }
    return sorted(selected, key=lambda p: p.as_posix())


def discover_templates(
    context: "PluginContext", target_type: Literal["source", "converted"]
) -> TemplateDiscovery:
    """Classify every candidate file as a template, not-a-template, or unmodelable."""
    result = TemplateDiscovery()
    for path in candidate_files(context, target_type):
        if not path.is_file():
            continue
        try:
            model = get_model_from_template(template_path=path)
        except CloudFormationTemplateModelError as exc:
            result.unmodelable.append(
                (
                    path,
                    (
                        "the template carries a Resources mapping but could not be "
                        f"modeled as CloudFormation: {type(exc.error).__name__}"
                    ),
                )
            )
            continue
        except Exception as exc:  # nosec B112 - not YAML/JSON, so not a template
            ASH_LOGGER.trace(f"Not a CloudFormation file: {path}. Exception: {exc}")
            continue
        if model is None:
            continue
        result.templates.append(path)
    return result


def display_path(path: Path, source_dir: Path) -> str:
    """``path`` relative to ``source_dir`` in POSIX form when it is inside it.

    Both sides made absolute without resolving symlinks, for the reason
    ``ScannerPluginBase._output_dir_inside`` gives: the tool sees the path as given.
    A path outside the source directory (a converted file under an external output
    directory) is returned absolute.
    """
    absolute = Path(path).absolute()
    source = Path(source_dir).absolute()
    try:
        return absolute.relative_to(source).as_posix()
    except ValueError:
        return absolute.as_posix()
