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

The outcomes per file
---------------------
* a template: returned in ``templates``;
* not CloudFormation (unparseable as YAML/JSON, or no ``Resources`` mapping): skipped,
  as cfn-nag skips it;
* CloudFormation the model rejects (``CloudFormationTemplateModelError``), or a file
  whose structure is a template but whose values could not be built or that is
  nested deeper than ASH reads: returned in ``unmodelable`` with the reason, so the
  caller counts a failed target rather than letting the file vanish. That is the
  distinction ``cfn_template_model`` documents;
* a candidate ASH could not open (``OSError``): returned in ``unreadable`` with the
  reason. Not known to be CloudFormation and not known not to be, so the callers
  count it as a target that was not evaluated, the same answer the tool-absent check
  gives (only MISSING cannot hide a template);
* a candidate that is not UTF-8 (``UnicodeDecodeError``): decoded as well as it can
  be and judged from its text (``cfn_template_model.judge_undecodable_candidate``),
  with the three answers the UTF-8 route gives a file the parser rejects, so the
  encoding does not change a file's answer. A reading whose STRUCTURE is a template
  (a ``Resources`` mapping, read by shape without building a value, as the UTF-8
  route reads it) is a template ASH could not decode, returned in ``unreadable``,
  even when a value in it cannot be built; one that carries
  only a CloudFormation marker is a damaged template, returned in ``unparseable``
  (a Jinja-templated stack saved as cp1252 reads as its UTF-8 twin does, where the
  first cut made it a failed target from the marker alone); a file that is not
  CloudFormation (a UTF-16 ``appsettings.json``, a Latin-1 locale file) is returned
  in ``skipped`` with the reason, so the callers name it at WARNING and count
  nothing, as cfn-nag skips it. Before this split one such file failed all three
  CloudFormation scanners with no structure read at all;
* a UTF-16 or UTF-32 template written without a byte-order mark: it decodes as
  UTF-8 without an error (NUL is valid UTF-8) and reaches the parsers
  NUL-interleaved, so it is found by ``cfn_template_model.unmarked_wide_template_reason``
  and returned in ``unreadable`` with the reason, a template ASH could not decode,
  the same answer its marked twin gets;
* a candidate neither parser reads that could still be a damaged template (a lenient
  read finds a Resources mapping, or the text carries a CloudFormation marker):
  returned in ``unparseable`` with the parse error, so the callers name it and count
  it as something to scan, as cfn-nag's tool-absent check counts the same file;
* a file the scanned-tree rule refuses: returned in ``refused`` (below).

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
    UNDECODABLE_DAMAGED,
    UNDECODABLE_TEMPLATE,
    CloudFormationTemplateModelError,
    active_global_ignore_paths,
    describe_parse_error,
    get_model_from_template_text,
    holds_cloudformation_template,
    is_template_candidate,
    judge_undecodable_candidate,
    read_template_text,
    unevaluable_template_reason,
    unmarked_wide_template_reason,
)
from automated_security_helper.utils.get_scan_set import honors_ignore_files, scan_set
from automated_security_helper.utils.link_exclusions import drop_ignored
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scan_targets import scan_targets
from automated_security_helper.utils.scanned_tree import TreeInputRefused

if TYPE_CHECKING:
    from automated_security_helper.base.plugin_context import PluginContext

#: The reason cfn-lint and cfn-guard give when no tree holds a template; see
#: :func:`cloudformation_templates_nothing_to_scan_reason`.
NO_CLOUDFORMATION_TEMPLATE = "no CloudFormation template in the scanned files"


@dataclass
class TemplateDiscovery:
    """The templates in one target, and the CloudFormation files that could not be modeled."""

    templates: List[Path] = field(default_factory=list)
    unmodelable: List[Tuple[Path, str]] = field(default_factory=list)
    refused: List[Tuple[str, str]] = field(default_factory=list)
    #: Candidates ASH could not open (an OSError), candidates that are not UTF-8
    #: whose text reads as a template, and UTF-16 or UTF-32 templates written
    #: without a byte-order mark, with the reason. Not known not to be
    #: CloudFormation, so a target that was not evaluated; named by the callers,
    #: and counted as something to scan by
    #: :func:`cloudformation_templates_nothing_to_scan_reason`, since only MISSING
    #: cannot hide a template.
    unreadable: List[Tuple[str, str]] = field(default_factory=list)
    #: Candidates that are not UTF-8 and whose text, decoded as well as it can be,
    #: is not CloudFormation, with the reason: skipped and named at WARNING by the
    #: callers, counted as nothing.
    skipped: List[Tuple[str, str]] = field(default_factory=list)
    #: Candidates neither parser could read that could be a damaged template
    #: (``cfn_template_model.holds_cloudformation_template``: a lenient read
    #: finds a Resources mapping, or the text carries a CloudFormation marker),
    #: and candidates that are not UTF-8 whose text carries only the marker
    #: (``judge_undecodable_candidate``), with the reason. Not a target, since the
    #: tool could not read them either,
    #: so not counted as failed; named by the callers, where they vanished at
    #: TRACE before, and counted as something to scan, as cfn-nag counts them.
    unparseable: List[Tuple[str, str]] = field(default_factory=list)


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
            # to take them from): the list scan() is given, read from the
            # context as cfn-nag's cloudformation_candidate_files reads it
            # (the config's unexpired ignore paths, none under
            # --ignore-suppressions), so a tree whose only templates are
            # ignored is SKIPPED, not MISSING, and the two selections agree.
            global_ignore_paths = active_global_ignore_paths(context)
        found = drop_ignored(
            scan_set(
                source=str(context.source_dir),
                output=str(context.output_dir),
                honor_ignore_files=honors_ignore_files(context.config),
                run_id=getattr(context, "run_id", None),
                # In a workspace scan the run's recorded scan set is keyed on
                # this too; without it the tree was walked again.
                workspace_output_dir=getattr(context, "workspace_output_dir", None),
            ),
            context.source_dir,
            global_ignore_paths,
        )
    # cfn-nag's suffix test (cfn_template_model.is_template_candidate), so the
    # two selections cannot drift: case-insensitive, and .template included.
    selected = {Path(f) for f in found if is_template_candidate(f)}
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
        # Read once, under the scanned-tree rule, and parsed from that text, so a
        # file the parser rejects is classified from the text already read instead
        # of being read and parsed again (unevaluable_template_reason takes it).
        text: Optional[str] = None
        try:
            text = read_template_text(path, scan_root)
            model = get_model_from_template_text(text, path)
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
        except UnicodeDecodeError as exc:
            # Not UTF-8. Judged from its text, decoded as well as it can be: a
            # template ASH cannot decode is a target that was not evaluated (named
            # rather than dropped at TRACE, or it would vanish from cfn-lint's and
            # cfn-guard's coverage silently); a file that is not CloudFormation is
            # skipped and named, as cfn-nag skips it, not failed with no structure
            # read at all.
            #
            # Three answers, the ones the UTF-8 route gives a file the parser
            # rejects, so a file's encoding does not change them: its STRUCTURE
            # makes it a failed target; a marker alone makes it a damaged template,
            # unparseable; neither makes it a skip. The judgment answers a failed
            # second read as a template itself, so no except arm is needed here.
            shown = display_path(path, context.source_dir)
            judged = judge_undecodable_candidate(path, scan_root)
            if judged == UNDECODABLE_TEMPLATE:
                result.unreadable.append(
                    (shown, f"the file could not be read: {type(exc).__name__}")
                )
            elif judged == UNDECODABLE_DAMAGED:
                result.unparseable.append(
                    (
                        shown,
                        (
                            "it could be a CloudFormation template but could not be "
                            "parsed: not UTF-8, and its text carries a CloudFormation "
                            "marker with no Resources mapping: "
                            f"{type(exc).__name__}"
                        ),
                    )
                )
            else:
                reason = (
                    "not UTF-8, and its text is not a CloudFormation template: "
                    f"{type(exc).__name__}"
                )
                result.skipped.append((shown, reason))
            continue
        except OSError as exc:
            # Not read, so not known to be CloudFormation. Named rather than
            # dropped at TRACE: a template ASH cannot open would otherwise vanish
            # from cfn-lint's and cfn-guard's coverage silently.
            result.unreadable.append(
                (
                    display_path(path, context.source_dir),
                    f"the file could not be read: {type(exc).__name__}",
                )
            )
            continue
        except Exception as exc:  # nosec B112 - not YAML/JSON, so not a template
            # A UTF-16 or UTF-32 template written without a byte-order mark
            # decodes as UTF-8 without an error and reaches the parsers
            # NUL-interleaved: a template ASH could not decode, so a failed
            # target, as its marked twin is through the UnicodeDecodeError arm.
            # Named as a template that could not be parsed, it was counted as
            # nothing; dropped at TRACE before that, it vanished.
            unmarked_reason = (
                unmarked_wide_template_reason(text) if text is not None else None
            )
            if unmarked_reason is not None:
                result.unreadable.append(
                    (display_path(path, context.source_dir), unmarked_reason)
                )
                continue
            # A file whose structure is a template but whose values the parser
            # could not build, or that is nested deeper than ASH reads, is a
            # failed target, as cfn-nag counts the same file; a file that is not
            # YAML or JSON at all is not a template.
            unmodelable_reason = unevaluable_template_reason(
                path, scan_root, text=text
            )
            if unmodelable_reason is not None:
                result.unmodelable.append((path, unmodelable_reason))
                continue
            # A file neither parser reads but that could be a damaged template
            # is named, as cfn-nag names it: left at TRACE, a template with a
            # syntax error vanished from cfn-lint's and cfn-guard's coverage and
            # the target read SKIPPED with "no template" where cfn-nag's
            # tool-absent check counts the same file as one. Not a failed target:
            # the tool could not have read it either.
            if holds_cloudformation_template([path], scan_root):
                result.unparseable.append(
                    (
                        display_path(path, context.source_dir),
                        (
                            "it could be a CloudFormation template but could not be "
                            f"parsed: {describe_parse_error(exc)}"
                        ),
                    )
                )
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
    not read, since only MISSING cannot hide a template, and so is a damaged
    template neither parser reads, as cfn-nag's tool-absent check counts it. A
    file that is not CloudFormation and one the scanned-tree rule refuses are
    not: ``scan()`` skips both, with its tool or without it. The selection drops
    the files the config's global ignore paths ignore, as ``scan()`` is given them,
    so a tree whose only templates are ignored reads SKIPPED, not MISSING.
    """
    for target_type, _ in scan_targets(context):
        found = discover_templates(context, target_type)
        if (
            found.templates
            or found.unmodelable
            or found.unreadable
            or found.unparseable
        ):
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
