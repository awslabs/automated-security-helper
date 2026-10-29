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
``CfnNagScanner.scan``, and the two new scanners call it. Their
``nothing_to_scan_reason`` answers from it too
(:func:`cloudformation_templates_nothing_to_scan_reason`), so whether there is
anything to scan is decided by the selection the scan makes.

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

A file is read under the scanned-tree rule (``utils/scanned_tree.py``), against the
tree cfn-nag reads it against: a symlink, a file under a symlinked directory, one
outside the tree or with more than one hard link is not read, and is returned in
``refused`` so the caller can name it, as cfn-nag skips and names it. cfn-lint and
cfn-guard then open the templates themselves, by path; under ``--sandbox`` they can
read nothing outside the tree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, List, Literal, Optional, Tuple

from automated_security_helper.utils.cfn_template_model import (
    CloudFormationTemplateModelError,
    get_model_from_template,
    unevaluable_template_reason,
)
from automated_security_helper.utils.get_scan_set import honors_ignore_files, scan_set
from automated_security_helper.utils.link_exclusions import drop_ignored
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scan_targets import scan_targets
from automated_security_helper.utils.scanned_tree import TreeInputRefused

if TYPE_CHECKING:
    from automated_security_helper.base.plugin_context import PluginContext

_TEMPLATE_SUFFIXES = (".json", ".yaml", ".yml")

#: The reason cfn-lint and cfn-guard give when no tree holds a template; see
#: :func:`cloudformation_templates_nothing_to_scan_reason`.
NO_CLOUDFORMATION_TEMPLATE = "no CloudFormation template in the scanned files"


@dataclass
class TemplateDiscovery:
    """The templates in one target, and the CloudFormation files that could not be modeled."""

    templates: List[Path] = field(default_factory=list)
    unmodelable: List[Tuple[Path, str]] = field(default_factory=list)
    refused: List[Tuple[str, str]] = field(default_factory=list)
    #: Candidates ASH could not open or decode (an OSError, bytes that are not
    #: UTF-8), with the reason. Not known to be CloudFormation, so not a target;
    #: named by the callers, and counted as something to scan by
    #: :func:`cloudformation_templates_nothing_to_scan_reason`, since only MISSING
    #: cannot hide a template.
    unreadable: List[Tuple[str, str]] = field(default_factory=list)


def candidate_files(
    context: "PluginContext",
    target_type: Literal["source", "converted"],
    global_ignore_paths: Optional[Iterable[object]] = None,
) -> List[Path]:
    """The JSON/YAML files cfn-nag would consider for ``target_type``, sorted.

    The same two sources ``CfnNagScanner.scan`` reads: the converted work directory's
    files for a converted target, and otherwise the scan set without the files
    ``global_ignore_paths`` ignores (``link_exclusions.drop_ignored``), as cfn-nag
    is given them. Sorted so runs are reproducible regardless of filesystem
    enumeration order.
    """
    if target_type == "converted":
        found = [str(p) for p in Path(context.work_dir).glob("**/*.*")]
    else:
        if global_ignore_paths is None:
            # The caller did not say (nothing_to_scan_reason has no scan() call
            # to take them from): the config's own global ignore paths, as
            # cfn-nag's cloudformation_candidate_files reads them, so a tree
            # whose only templates are ignored is SKIPPED, not MISSING.
            from automated_security_helper.utils.suppression_matcher import (
                active_ignore_paths,
            )

            global_settings = getattr(
                getattr(context, "config", None), "global_settings", None
            )
            global_ignore_paths = active_ignore_paths(
                getattr(global_settings, "ignore_paths", None) or []
            )
        found = drop_ignored(
            scan_set(
                source=str(context.source_dir),
                output=str(context.output_dir),
                honor_ignore_files=honors_ignore_files(context.config),
                run_id=getattr(context, "run_id", None),
            ),
            context.source_dir,
            global_ignore_paths,
        )
    selected = {
        Path(f) for f in found if any(str(f).endswith(s) for s in _TEMPLATE_SUFFIXES)
    }
    return sorted(selected, key=lambda p: p.as_posix())


def discover_templates(
    context: "PluginContext",
    target_type: Literal["source", "converted"],
    global_ignore_paths: Optional[Iterable[object]] = None,
) -> TemplateDiscovery:
    """Classify every candidate file as a template, not-a-template, unmodelable, or refused.

    ``global_ignore_paths`` is what the scanner's ``scan()`` was given; see
    ``candidate_files``.
    """
    result = TemplateDiscovery()
    # The tree CfnNagScanner.scan reads each candidate against.
    scan_root = context.work_dir if target_type == "converted" else context.source_dir
    for path in candidate_files(context, target_type, global_ignore_paths):
        if not path.is_file():
            continue
        try:
            model = get_model_from_template(template_path=path, scan_root=scan_root)
        except TreeInputRefused as refused:
            result.refused.append((refused.path, refused.reason))
            continue
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
        except (OSError, UnicodeDecodeError) as exc:
            # Not read, so not known to be CloudFormation. Named rather than
            # dropped at TRACE: a template ASH cannot open or decode would
            # otherwise vanish from cfn-lint's and cfn-guard's coverage silently.
            result.unreadable.append(
                (
                    display_path(path, context.source_dir),
                    f"the file could not be read: {type(exc).__name__}",
                )
            )
            continue
        except Exception as exc:  # nosec B112 - not YAML/JSON, so not a template
            # A file whose structure is a template but whose values the parser
            # could not build, or that is nested deeper than ASH reads, is a
            # failed target, as cfn-nag counts the same file; a file that is not
            # YAML or JSON at all is not a template.
            reason = unevaluable_template_reason(path, scan_root)
            if reason is not None:
                result.unmodelable.append((path, reason))
                continue
            ASH_LOGGER.trace(f"Not a CloudFormation file: {path}. Exception: {exc}")
            continue
        if model is None:
            continue
        result.templates.append(path)
    return result


def cloudformation_templates_nothing_to_scan_reason(
    context: "PluginContext",
) -> Optional[str]:
    """``nothing_to_scan_reason`` for cfn-lint and cfn-guard, or None.

    From :func:`discover_templates`, the selection both scanners' ``scan()`` makes,
    over every tree a scan hands them (``utils/scan_targets.py``). A template is
    something to scan, and so is a CloudFormation file the model rejects, which
    both scanners count as a target that failed, and so is a candidate ASH could
    not read, since only MISSING cannot hide a template. A file that is not
    CloudFormation and one the scanned-tree rule refuses are not: ``scan()`` skips
    both, with its tool or without it. The selection drops the files the config's
    global ignore paths ignore, as ``scan()`` is given them, so a tree whose only
    templates are ignored reads SKIPPED, not MISSING.
    """
    for target_type, _ in scan_targets(context):
        found = discover_templates(context, target_type)
        if found.templates or found.unmodelable or found.unreadable:
            return None
    return NO_CLOUDFORMATION_TEMPLATE


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
