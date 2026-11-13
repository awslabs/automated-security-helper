"""A scanner with nothing to scan is SKIPPED whether or not its tool is installed.

cdk-nag and cfn-nag read CloudFormation templates and npm-audit reads npm, yarn and
pnpm lockfiles, and each picks those files out of the scan set itself. With nothing
to read, such a scanner is SKIPPED with its tool absent too, so on a machine without
Node.js a Python project's scan does not exit 1 for two scanners that have nothing to
do there.

The decision is made from the same file selection the scanner uses when it runs, and
only that: a project that HAS a template or a lockfile and no tool is MISSING and
fails the completeness gate. A scanner that cannot tell (every other scanner, a
third-party one, a test double) is MISSING without its tool.
"""

from __future__ import annotations

import io
import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.interactions.run_ash_scan import incomplete_scanners
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
)
from automated_security_helper.utils.console import ash_console
from automated_security_helper.utils.log import ASH_LOGGER, ConsoleHandler

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}},
}


@pytest.fixture
def context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n", encoding="utf-8")
    # A JSON file that is not CloudFormation: what a Python or JS project has.
    (source / "settings.json").write_text('{"debug": false}\n', encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )


def _without_its_tool(scanner_class):
    """The real scanner class with its dependency check answering False."""

    class _NoTool(scanner_class):
        def validate_plugin_dependencies(self) -> bool:
            return False

    _NoTool.__name__ = scanner_class.__name__
    _NoTool.__module__ = scanner_class.__module__
    return _NoTool


def _scan(context, plugins) -> AshAggregatedResults:
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=plugins,
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(aggregated_results=aggregated, parallel=False)
    return populate_metrics_from_unified_source(aggregated_results=results)


SCANNERS = [
    pytest.param(CdkNagScanner, "cdk-nag", "CloudFormation", id="cdk-nag"),
    pytest.param(CfnNagScanner, "cfn-nag", "CloudFormation", id="cfn-nag"),
    pytest.param(NpmAuditScanner, "npm-audit", "lockfile", id="npm-audit"),
]


def _give_it_something_to_scan(name: str, root: Path) -> None:
    if name == "npm-audit":
        (root / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
        (root / "package-lock.json").write_text(
            json.dumps({"name": "app", "lockfileVersion": 3}), encoding="utf-8"
        )
    else:
        (root / "template.json").write_text(json.dumps(TEMPLATE), encoding="utf-8")


@pytest.mark.parametrize("scanner_class,name,what", SCANNERS)
def test_without_its_tool_and_nothing_to_scan_it_is_skipped(
    context, scanner_class, name, what
):
    results = _scan(context, [_without_its_tool(scanner_class)])

    row = results.scanner_results[name]
    assert row.status == ScannerStatus.SKIPPED, (
        f"{name} has nothing to scan here; its absent tool must not make it "
        f"MISSING: {row!r}"
    )
    assert row.excluded is False, "nothing deselected it"
    assert row.dependencies_satisfied is True, row
    assert what in (row.skipped_reason or ""), row.skipped_reason
    assert incomplete_scanners(results) == []
    # The container says it looked and attempted no target (0, not None), so the
    # flat row reports a scanner that tracked its input and had none.
    from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
        ReportContentEmitter,
    )

    (flat,) = [
        entry
        for entry in ReportContentEmitter(results).get_scanner_results()
        if entry["scanner_name"] == name
    ]
    assert flat["targets_attempted"] == 0, flat


@pytest.mark.parametrize("scanner_class,name,what", SCANNERS)
def test_without_its_tool_and_something_to_scan_it_is_missing(
    context, scanner_class, name, what
):
    """The gate holds for a scanner that had something to scan."""
    _give_it_something_to_scan(name, context.source_dir)

    results = _scan(context, [_without_its_tool(scanner_class)])

    row = results.scanner_results[name]
    assert row.status == ScannerStatus.MISSING, row
    assert (name, "MISSING") in incomplete_scanners(results)


@pytest.mark.parametrize("scanner_class,name,what", SCANNERS)
def test_input_in_the_converted_tree_counts(context, scanner_class, name, what):
    """The scanners read the converted tree too (an archive's contents)."""
    _give_it_something_to_scan(name, context.work_dir)

    results = _scan(context, [_without_its_tool(scanner_class)])

    assert results.scanner_results[name].status == ScannerStatus.MISSING


@pytest.mark.parametrize("scanner_class,name,what", SCANNERS)
def test_the_hook_says_why_when_there_is_nothing(context, scanner_class, name, what):
    scanner = scanner_class(context=context)

    assert what in (scanner.nothing_to_scan_reason() or "")


@pytest.mark.parametrize("scanner_class,name,what", SCANNERS)
def test_the_hook_has_no_reason_when_there_is_input(context, scanner_class, name, what):
    # Before the scan set is first read: a scan computes it once, at its start,
    # and every scanner reads that list from the output directory.
    _give_it_something_to_scan(name, context.source_dir)
    scanner = scanner_class(context=context)

    assert scanner.nothing_to_scan_reason() is None


def test_a_package_json_without_a_lockfile_is_nothing_npm_audit_can_audit(context):
    (context.source_dir / "package.json").write_text('{"name": "app"}\n')

    scanner = NpmAuditScanner(context=context)

    assert "lockfile" in (scanner.nothing_to_scan_reason() or "")


def test_npm_audit_with_its_tool_and_no_lockfile_is_skipped_with_the_same_reason(
    context,
):
    """The other half of 'whether or not its tool is installed'."""

    class _WithTool(NpmAuditScanner):
        def validate_plugin_dependencies(self) -> bool:
            return True

    _WithTool.__name__ = NpmAuditScanner.__name__
    _WithTool.__module__ = NpmAuditScanner.__module__

    with patch.object(_WithTool, "_run_subprocess") as spawn:
        results = _scan(context, [_WithTool])

    spawn.assert_not_called()
    row = results.scanner_results["npm-audit"]
    assert row.status == ScannerStatus.SKIPPED, row
    assert "lockfile" in (row.skipped_reason or ""), row.skipped_reason


def test_a_scanner_that_declares_nothing_is_missing(context):
    """The base class cannot tell, so the default leaves MISSING alone."""

    class _Plain(ScannerPluginBase):
        def model_post_init(self, context):
            from automated_security_helper.base.scanner_plugin import (
                ScannerPluginConfigBase,
            )

            if self.config is None:
                self.config = ScannerPluginConfigBase(name="plain-tool")
            self.command = "plain-tool"
            super().model_post_init(context)

        def validate_plugin_dependencies(self) -> bool:
            return False

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

    assert ScannerPluginBase.nothing_to_scan_reason(object()) is None
    results = _scan(context, [_Plain])
    assert results.scanner_results["plain-tool"].status == ScannerStatus.MISSING


def test_a_hook_that_raises_does_not_turn_missing_into_skipped(context):
    class _Raises(_without_its_tool(NpmAuditScanner)):
        def nothing_to_scan_reason(self):
            raise RuntimeError("could not read the scan set")

    _Raises.__name__ = NpmAuditScanner.__name__
    results = _scan(context, [_Raises])

    assert results.scanner_results["npm-audit"].status == ScannerStatus.MISSING


class _Rendered(ConsoleHandler):
    """ASH's console handler, keeping what it printed for each record."""

    def __init__(self, markup: bool) -> None:
        self.buffer = io.StringIO()
        super().__init__(
            console=ash_console(file=self.buffer, width=400, color_system=None),
            markup=markup,
            show_time=False,
            show_path=False,
        )
        self.setFormatter(logging.Formatter("%(message)s"))
        self.rendered: list = []

    def emit(self, record: logging.LogRecord) -> None:
        start = len(self.buffer.getvalue())
        super().emit(record)
        self.rendered.append((record, self.buffer.getvalue()[start:]))


def test_the_nothing_to_scan_line_shows_its_reason_as_given(context):
    """The reason is the plugin's text, built from what it found in the scan
    set, so the INFO line logs it with markup off, as its MISSING twin does.

    It is read through two console handlers, one built with markup on and the
    default one with markup off. Under markup a "[/x]" in the reason raises
    MarkupError and a "[bold]" is obeyed; with markup off at the call both
    show as written.
    """
    reason = "no lockfile under pkgs/[/x]/ or [bold]B[/bold]"

    class _Says(_without_its_tool(NpmAuditScanner)):
        def nothing_to_scan_reason(self):
            return reason

    _Says.__name__ = NpmAuditScanner.__name__
    handlers = [_Rendered(markup=True), _Rendered(markup=False)]
    saved_handlers, saved_level = list(ASH_LOGGER.handlers), ASH_LOGGER.level
    ASH_LOGGER.handlers = list(handlers)
    ASH_LOGGER.setLevel(logging.INFO)
    try:
        results = _scan(context, [_Says])
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.setLevel(saved_level)

    assert results.scanner_results["npm-audit"].status == ScannerStatus.SKIPPED
    for handler in handlers:
        lines = [
            out
            for record, out in handler.rendered
            if "has nothing to scan" in record.getMessage()
        ]
        assert lines, f"no nothing-to-scan line reached markup={handler.markup}"
        assert reason in " ".join(lines[0].split()), (handler.markup, lines[0])


def test_a_mock_answer_is_not_a_reason(tmp_path):
    """A test double answers every method with a Mock; that must not skip it."""
    from automated_security_helper.core.phases.scan_phase import (
        _nothing_to_scan_reason,
    )

    double = MagicMock()
    assert _nothing_to_scan_reason(double) is None


# ---------------------------------------------------------------------------
# The hook is conservative: only a certain "nothing here" makes a scanner SKIPPED
# ---------------------------------------------------------------------------
#
# A wrong "nothing to scan" turns MISSING (the scan exits 1) into SKIPPED (exit 0), so
# every case the hook cannot read with certainty has to answer "something to scan".

CFN_SCANNERS = [
    pytest.param(CdkNagScanner, id="cdk-nag"),
    pytest.param(CfnNagScanner, id="cfn-nag"),
]


def _hook(context, scanner_class):
    return scanner_class(context=context).nothing_to_scan_reason()


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_a_tab_indented_json_template_is_a_template(context, scanner_class):
    """Valid JSON and a valid template; YAML forbids the tabs, so load_yaml raises."""
    (context.source_dir / "stack.json").write_text(
        json.dumps(TEMPLATE, indent="\t"), encoding="utf-8"
    )

    assert _hook(context, scanner_class) is None


def test_a_tab_indented_json_template_is_modeled_by_the_scanners_parser():
    """The scanners read templates through get_model_from_template_text too."""
    from automated_security_helper.utils.cfn_template_model import (
        get_model_from_template_text,
    )

    model = get_model_from_template_text(
        json.dumps(TEMPLATE, indent="\t"), "stack.json"
    )

    assert model is not None and list(model.Resources) == ["Bucket"]


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_a_document_with_resources_the_model_rejects_counts(context, scanner_class):
    """The scanners count it as a failed target, so it is something to scan."""
    (context.source_dir / "odd.json").write_text(
        json.dumps({"Resources": {"Thing": {"Type": "not a valid type!"}}}),
        encoding="utf-8",
    )

    assert _hook(context, scanner_class) is None


#: Files a JavaScript or Python project holds that neither parser reads, none of them
#: CloudFormation. With their tools installed cdk-nag and cfn-nag pass over each (see
#: test_cdk_nag_unevaluated_is_not_skipped.py), so without the tool the scanner has
#: nothing to scan. Read as "might be a damaged template" they made both scanners
#: MISSING and the scan exit 1.
NOT_CLOUDFORMATION = [
    pytest.param(
        "mkdocs.yml",
        "site_name: docs\n"
        "markdown_extensions:\n"
        "  - pymdownx.emoji:\n"
        "      emoji_index: !!python/name:material.extensions.emoji.twemoji\n"
        "      emoji_generator: !!python/name:material.extensions.emoji.to_svg\n",
        id="mkdocs-python-tags",
    ),
    pytest.param(
        "chart/templates/service.yaml",
        "apiVersion: v1\n"
        "kind: Service\n"
        "metadata:\n"
        '  name: {{ include "app.fullname" . }}\n'
        "  labels:\n"
        '    {{- include "app.labels" . | nindent 4 }}\n'
        "spec:\n"
        "  type: {{ .Values.service.type }}\n",
        id="helm-template",
    ),
    pytest.param(
        # No "{{-": the template parser's loader reads "{{ ... }}" as a mapping
        # used as a key and raises TypeError ("unhashable type"), not a YAML error.
        "chart/templates/deployment.yaml",
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        '  name: {{ include "app.fullname" . }}\n'
        "spec:\n"
        "  replicas: {{ .Values.replicaCount }}\n",
        id="helm-template-unhashable-key",
    ),
    pytest.param(
        # Nested past the YAML loaders' recursion limit, and not JSON (a bare key):
        # both YAML reads raise RecursionError, and JSON rejects it. Under the
        # structural read's bound (EVENT_DEPTH_BOUND), past which a mapping root
        # counts whatever it holds.
        "deep.yaml",
        "nested: " + "[" * 600 + "]" * 600 + "\n",
        id="deep-yaml",
    ),
    pytest.param(
        "tsconfig.json",
        "{\n"
        "  // source, `npm run build` leaves lib/*.js\n"
        '  "compilerOptions": { "strict": true, /* and */ "outDir": "lib" }\n'
        "}\n",
        id="jsonc-tsconfig",
    ),
]


def _does_not_parse(name: str, body: str) -> bool:
    from automated_security_helper.utils.cfn_template_model import (
        get_model_from_template_text,
    )

    try:
        get_model_from_template_text(body, name)
    except Exception:
        return True
    return False


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
@pytest.mark.parametrize("name,body", NOT_CLOUDFORMATION)
def test_a_file_that_is_not_cloudformation_is_nothing_to_scan(
    context, scanner_class, name, body
):
    assert _does_not_parse(name, body), "the case must reach the fallback"
    path = context.source_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")

    assert "CloudFormation" in (_hook(context, scanner_class) or "")


@pytest.mark.parametrize(
    "scanner_class,scanner_name",
    [
        pytest.param(CdkNagScanner, "cdk-nag", id="cdk-nag"),
        pytest.param(CfnNagScanner, "cfn-nag", id="cfn-nag"),
    ],
)
def test_without_its_tool_those_files_leave_it_skipped(
    context, scanner_class, scanner_name
):
    """End to end: SKIPPED, not MISSING, so the scan does not exit 1 on them."""
    for param in NOT_CLOUDFORMATION:
        name, body = param.values
        path = context.source_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")

    results = _scan(context, [_without_its_tool(scanner_class)])

    row = results.scanner_results[scanner_name]
    assert row.status == ScannerStatus.SKIPPED, row
    assert incomplete_scanners(results) == []


#: Templates no parser can read, as a truncated or mis-indented template would be.
DAMAGED_TEMPLATES = [
    pytest.param(
        "stack.yaml",
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "   Properties: [\n",
        id="yaml-format-version",
    ),
    pytest.param(
        "stack.yaml",
        "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n  Properties: {\n",
        id="yaml-resource-type-only",
    ),
    pytest.param(
        "stack.json",
        json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}, indent=2)[
            :-4
        ],
        id="json-truncated",
    ),
    pytest.param(
        # A non-printable character (DEL): PyYAML's reader refuses the whole file
        # before it reads a line, and the text is not JSON.
        "stack.yaml",
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: a\x7fb\n",
        id="yaml-control-character",
    ),
]


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
@pytest.mark.parametrize("name,body", DAMAGED_TEMPLATES)
def test_a_damaged_template_is_still_something_to_scan(
    context, scanner_class, name, body
):
    """MISSING is the answer that cannot hide a template the tool would have read."""
    assert _does_not_parse(name, body), "the case must reach the fallback"
    (context.source_dir / name).write_text(body, encoding="utf-8")

    assert _hook(context, scanner_class) is None


#: Damaged so that no reader parses it, with a CloudFormation marker in its text, and
#: a sequence for its root, which no template has.
DAMAGED_SEQUENCE_ROOT = (
    "- AWSTemplateFormatVersion: '2010-09-09'\n"
    "  Resources: {\n"
    "    Bucket: {Type: AWS::S3::Bucket\n"
)


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_a_damaged_sequence_root_is_nothing_to_scan(context, scanner_class):
    """SKIPPED without the tool: the marker made it a possibly damaged template,
    and the scanner MISSING, though its root says it cannot be one."""
    (context.source_dir / "stack.yaml").write_text(
        DAMAGED_SEQUENCE_ROOT, encoding="utf-8"
    )

    assert "CloudFormation" in (_hook(context, scanner_class) or "")


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_with_its_tool_a_damaged_sequence_root_says_no_template(
    context, cdk_nag_parses_for_real, scanner_class
):
    """With the tool, the reason the same tree reads without it: no template."""
    from automated_security_helper.core.phases.scanner_executor import (
        _skipped_reason_after_scan,
    )
    from automated_security_helper.utils.cfn_template_model import (
        NO_CLOUDFORMATION_TEMPLATE,
    )

    (context.source_dir / "stack.yaml").write_text(
        DAMAGED_SEQUENCE_ROOT, encoding="utf-8"
    )
    scanner = _with_its_tool(scanner_class)(context=context)

    _scan_one_tree(scanner, context.source_dir)

    assert (scanner.targets_attempted, scanner.targets_failed) == (0, 0)
    assert _skipped_reason_after_scan(scanner, "scanner", "source") == (
        NO_CLOUDFORMATION_TEMPLATE
    )


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_a_template_with_jsonc_comments_is_something_to_scan(context, scanner_class):
    """Read once the comments are gone, and it carries Resources."""
    body = "// generated\n" + json.dumps(TEMPLATE, indent=2)
    assert _does_not_parse("stack.json", body)
    (context.source_dir / "stack.json").write_text(body, encoding="utf-8")

    assert _hook(context, scanner_class) is None


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_a_file_the_second_read_parses_is_judged_by_its_document(
    context, scanner_class
):
    """Not by its text: this mkdocs.yml quotes a resource type and has no Resources."""
    body = (
        "site_name: docs\n"
        "extra:\n"
        '  example: "Type: AWS::S3::Bucket"\n'
        "markdown_extensions:\n"
        "  - pymdownx.emoji:\n"
        "      emoji_index: !!python/name:material.extensions.emoji.twemoji\n"
    )
    assert _does_not_parse("mkdocs.yml", body)
    (context.source_dir / "mkdocs.yml").write_text(body, encoding="utf-8")

    assert "CloudFormation" in (_hook(context, scanner_class) or "")


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_a_commented_template_without_a_marker_is_something_to_scan(
    context, scanner_class
):
    """No format version and no AWS:: type, so only the second read finds it."""
    body = '// generated\n{"Resources": {"Thing": {"Type": "Custom::Thing"}}}\n'
    assert _does_not_parse("stack.json", body)
    (context.source_dir / "stack.json").write_text(body, encoding="utf-8")

    assert _hook(context, scanner_class) is None


def test_a_damaged_template_without_its_tool_is_missing(context):
    (context.source_dir / "stack.yaml").write_text(
        DAMAGED_TEMPLATES[0].values[1], encoding="utf-8"
    )

    results = _scan(context, [_without_its_tool(CfnNagScanner)])

    assert results.scanner_results["cfn-nag"].status == ScannerStatus.MISSING


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_an_unreadable_candidate_counts(context, scanner_class, monkeypatch):
    (context.source_dir / "locked.yaml").write_text("Resources: {}\n", encoding="utf-8")

    from automated_security_helper.utils import cfn_template_model

    def unreadable(path, scan_root):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(cfn_template_model, "read_template_text", unreadable)

    assert _hook(context, scanner_class) is None


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_a_document_without_resources_is_certainly_not_a_template(
    context, scanner_class
):
    """Control: the one case that is certain. The fixture's settings.json is it."""
    assert "CloudFormation" in (_hook(context, scanner_class) or "")


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_the_hook_reads_the_scan_set_the_scanners_read(
    context, scanner_class, monkeypatch
):
    """Whatever the scan set holds -- a template under a gitignored directory a later
    change keeps -- the hook sees, because it asks the same function the scanners'
    scan() asks. ``build/`` and not ``cdk.out/``: the scan set keeps the templates
    of an ignored CDK cloud assembly."""
    hidden = context.source_dir / "build" / "Stack.template.json"
    hidden.parent.mkdir()
    hidden.write_text(json.dumps(TEMPLATE), encoding="utf-8")
    (context.source_dir / ".gitignore").write_text("build\n", encoding="utf-8")

    from automated_security_helper.utils import get_scan_set

    assert _hook(context, scanner_class) is not None, (
        "control: with build gitignored the scan set drops the template"
    )
    monkeypatch.setattr(get_scan_set, "scan_set", lambda **kwargs: [hidden.as_posix()])

    assert _hook(context, scanner_class) is None


def test_npm_shrinkwrap_is_a_lockfile_npm_audits(context):
    """The lockfile lookup is read on an instance: it skips the lockfiles the
    scan's ignore list dropped, a set each scanner holds, so there is no
    class-level answer to ask for."""
    (context.source_dir / "package.json").write_text('{"name": "app"}\n')
    (context.source_dir / "npm-shrinkwrap.json").write_text(
        json.dumps({"name": "app", "lockfileVersion": 3})
    )

    scanner = NpmAuditScanner(context=context)
    assert scanner.nothing_to_scan_reason() is None
    assert scanner._lockfile_beside(context.source_dir / "package.json") == (
        context.source_dir / "npm-shrinkwrap.json"
    )


def _with_its_tool(scanner_class):
    """The real scanner class with its dependency check answering True."""

    class _WithTool(scanner_class):
        def validate_plugin_dependencies(self) -> bool:
            return True

    _WithTool.__name__ = scanner_class.__name__
    _WithTool.__module__ = scanner_class.__module__
    return _WithTool


@pytest.mark.parametrize(
    "scanner_class,name",
    [
        pytest.param(CfnNagScanner, "cfn-nag", id="cfn-nag"),
        pytest.param(NpmAuditScanner, "npm-audit", id="npm-audit"),
    ],
)
def test_with_its_tool_and_nothing_to_scan_no_exit_code_is_recorded(
    context, scanner_class, name
):
    """Its tool never started, so it has no exit code; 0 would read as a clean exit."""
    scanner = _with_its_tool(scanner_class)

    with patch.object(scanner, "_run_subprocess") as spawn:
        results = _scan(context, [scanner])

    spawn.assert_not_called()
    reloaded = populate_metrics_from_unified_source(
        aggregated_results=AshAggregatedResults.model_validate_json(
            results.model_dump_json()
        )
    )
    for when, model in [("as written", results), ("reloaded", reloaded)]:
        row = model.scanner_results[name]
        assert row.status == ScannerStatus.SKIPPED, f"{when}: {row!r}"
        assert row.exit_code is None, f"{when}: the tool never started: {row!r}"
        for target, report in model.additional_reports[name].items():
            assert report.get("exit_code") is None, f"{when}, {target}: {report!r}"


def test_cfn_nag_with_only_a_template_the_model_rejects_has_no_exit_code(context):
    """It attempted the template and failed it without starting cfn_nag."""
    (context.source_dir / "odd.json").write_text(
        json.dumps({"Resources": {"Thing": {"Type": "not a valid type!"}}}),
        encoding="utf-8",
    )
    scanner = _with_its_tool(CfnNagScanner)

    with patch.object(scanner, "_run_subprocess") as spawn:
        results = _scan(context, [scanner])

    spawn.assert_not_called()
    row = results.scanner_results["cfn-nag"]
    assert row.status == ScannerStatus.ERROR, row
    assert row.exit_code is None, f"cfn_nag never started: {row!r}"
    for target, report in results.additional_reports["cfn-nag"].items():
        assert report.get("exit_code") is None, (target, report)


@pytest.fixture
def template_checks(monkeypatch):
    """Each call to holds_cloudformation_template, which parses every candidate."""
    from automated_security_helper.utils import cfn_template_model

    calls = []
    real = cfn_template_model.holds_cloudformation_template

    def counting(files, scan_root):
        calls.append(scan_root)
        return real(files, scan_root)

    monkeypatch.setattr(cfn_template_model, "holds_cloudformation_template", counting)
    return calls


def test_a_damaged_template_is_not_reported_as_no_template(context):
    """With its tool, cfn-nag passes over a template it cannot parse and is SKIPPED.

    Its reason must still hold: the tree has a template, which the tool-absent
    check counts (that tree without the tool is MISSING), so "no CloudFormation
    template in the scanned files" is false; the template could not be parsed.
    """
    from automated_security_helper.utils.cfn_template_model import (
        NO_CLOUDFORMATION_TEMPLATE,
    )

    (context.source_dir / "stack.yaml").write_text(
        DAMAGED_TEMPLATES[0].values[1], encoding="utf-8"
    )
    scanner = _with_its_tool(CfnNagScanner)

    with patch.object(scanner, "_run_subprocess") as spawn:
        results = _scan(context, [scanner])

    spawn.assert_not_called()
    row = results.scanner_results["cfn-nag"]
    assert row.status == ScannerStatus.SKIPPED, row
    assert row.skipped_reason != NO_CLOUDFORMATION_TEMPLATE, row.skipped_reason
    assert "could parse" in (row.skipped_reason or ""), row.skipped_reason


def test_a_skipped_target_is_not_parsed_again_for_its_reason(context, template_checks):
    """scan() just looked at every candidate; asking the hook re-parses both trees.

    Measured: one parse of a 6.1 MB package-lock.json took 7.5 s,
    and the hook ran once per SKIPPED target, so about four extra full parses per
    scanner on the default path. cfn-nag end to end, with its tool installed and
    nothing to scan.
    """
    scanner = _with_its_tool(CfnNagScanner)

    with patch.object(scanner, "_run_subprocess") as spawn:
        results = _scan(context, [scanner])

    spawn.assert_not_called()
    row = results.scanner_results["cfn-nag"]
    assert row.status == ScannerStatus.SKIPPED, row
    assert "CloudFormation" in (row.skipped_reason or ""), row.skipped_reason
    assert template_checks == [], (
        f"the trees were parsed again for the reason: {template_checks}"
    )


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_the_reason_after_a_scan_parses_nothing(
    context, template_checks, scanner_class
):
    """The executor's reason for a target the scanner attempted none of.

    cdk-nag cannot be run end to end without the cdk extra, so both scanners are
    asked through the executor's helper directly.
    """
    from automated_security_helper.core.phases.scanner_executor import (
        _skipped_reason_after_scan,
    )

    from automated_security_helper.utils.cfn_template_model import (
        NO_CLOUDFORMATION_TEMPLATE,
    )

    reason = _skipped_reason_after_scan(
        scanner_class(context=context), "scanner", "source"
    )

    assert reason == NO_CLOUDFORMATION_TEMPLATE, reason
    assert template_checks == [], template_checks


def test_cfn_nag_says_no_template_unless_one_failed_to_parse(context):
    """Per target: the damaged-template wording only when scan() passed over one.

    The default SKIPPED row, on every tree with no CloudFormation and cfn_nag
    installed, must read as it does without the tool. The damaged tree is scanned
    first and the clean tree second with the same scanner, so the value is reset
    for each target rather than carried over.
    """
    from automated_security_helper.core.phases.scanner_executor import (
        _skipped_reason_after_scan,
    )
    from automated_security_helper.utils.cfn_template_model import (
        NO_CLOUDFORMATION_TEMPLATE,
        NO_PARSEABLE_CLOUDFORMATION_TEMPLATE,
    )

    damaged = context.source_dir / "damaged"
    damaged.mkdir()
    (damaged / "stack.yaml").write_text(DAMAGED_TEMPLATES[0].values[1], "utf-8")
    clean = context.source_dir / "clean"
    clean.mkdir()
    (clean / "settings.json").write_text('{"debug": false}\n', encoding="utf-8")
    scanner = _with_its_tool(CfnNagScanner)(context=context)

    reasons = []
    for tree in (damaged, clean):
        with (
            patch.object(scanner, "_run_subprocess") as spawn,
            patch(
                "automated_security_helper.plugin_modules.ash_builtin.scanners."
                "cfn_nag_scanner.cloudformation_candidate_files",
                return_value=sorted(p.as_posix() for p in tree.iterdir()),
            ),
        ):
            scanner.scan(target=tree, target_type="source")
        spawn.assert_not_called()
        assert scanner.targets_attempted == 0
        reasons.append(_skipped_reason_after_scan(scanner, "cfn-nag", "source"))

    assert reasons == [NO_PARSEABLE_CLOUDFORMATION_TEMPLATE, NO_CLOUDFORMATION_TEMPLATE]


@pytest.fixture
def cdk_nag_parses_for_real(monkeypatch):
    """cdk-nag with its tool present; its wrapper parses as the real one and stops there.

    See tests/utils/cdk_nag_parse_double.py: the real wrapper imports cdk-nag, and
    so starts node, before it parses.
    """
    from tests.utils.cdk_nag_parse_double import use_the_parse_double

    use_the_parse_double(monkeypatch)


def _scan_one_tree(scanner, tree: Path, target_type: str = "source", spawn_answer=None):
    with patch.object(scanner, "_run_subprocess", return_value=spawn_answer) as spawn:
        report = scanner.scan(target=tree, target_type=target_type)
    if spawn_answer is None:
        spawn.assert_not_called()
    return report


#: Nested past the YAML loader's recursion limit, which raises RecursionError; how
#: deep json.loads can go depends on the Python version and platform, so after that
#: error the template parser does not try JSON. Its top level is a sequence.
DEEP_JSON = "[" * 3000 + "]" * 3000

#: Nested past the recursion limit too, not JSON: every reading of it fails. Its root
#: is a mapping, under the structural read's bound (EVENT_DEPTH_BOUND), past which it
#: would count as a template whatever it holds.
DEEP_YAML = "nested: " + "[" * 600 + "]" * 600 + "\n"

#: What cfn_nag_scan writes for a template it evaluated and found nothing in.
CFN_NAG_CLEAN_RUN = {
    "stdout": json.dumps(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "cfn_nag"}}, "results": []}],
        }
    ),
    "returncode": 0,
}


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
@pytest.mark.parametrize("name,body", NOT_CLOUDFORMATION)
def test_with_its_tool_a_file_that_is_not_cloudformation_says_no_template(
    context, cdk_nag_parses_for_real, scanner_class, name, body
):
    """The reason the same tree reads without the tool: no CloudFormation template.

    These files fail the template parser, and the scanners pass over each. The
    could-not-parse reason is for a file that could be a damaged template, which
    is what the tool-absent check counts (holds_cloudformation_template); these it
    does not count, so with the tool the reason said a template failed to parse
    where the same tree without it said there was none. ASH's own repository has
    two of them, mkdocs.yml and deploy/cdk/tsconfig.json.
    """
    from automated_security_helper.core.phases.scanner_executor import (
        _skipped_reason_after_scan,
    )
    from automated_security_helper.utils.cfn_template_model import (
        NO_CLOUDFORMATION_TEMPLATE,
    )

    path = context.source_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    scanner = _with_its_tool(scanner_class)(context=context)

    _scan_one_tree(scanner, context.source_dir)

    assert (scanner.targets_attempted, scanner.targets_failed) == (0, 0), (
        f"{name} is not a template the scanner failed on: "
        f"attempted={scanner.targets_attempted} failed={scanner.targets_failed}"
    )
    assert _skipped_reason_after_scan(scanner, "scanner", "source") == (
        NO_CLOUDFORMATION_TEMPLATE
    )


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
@pytest.mark.parametrize("name,body", DAMAGED_TEMPLATES)
def test_with_its_tool_a_damaged_template_says_it_could_not_parse(
    context, cdk_nag_parses_for_real, scanner_class, name, body
):
    """Control for the test above: a file that could be a template keeps the wording."""
    from automated_security_helper.core.phases.scanner_executor import (
        _skipped_reason_after_scan,
    )
    from automated_security_helper.utils.cfn_template_model import (
        NO_PARSEABLE_CLOUDFORMATION_TEMPLATE,
    )

    (context.source_dir / name).write_text(body, encoding="utf-8")
    scanner = _with_its_tool(scanner_class)(context=context)

    _scan_one_tree(scanner, context.source_dir)

    assert (scanner.targets_attempted, scanner.targets_failed) == (0, 0)
    assert _skipped_reason_after_scan(scanner, "scanner", "source") == (
        NO_PARSEABLE_CLOUDFORMATION_TEMPLATE
    )


def test_cdk_nag_with_its_tool_passes_over_a_helm_template(
    context, cdk_nag_parses_for_real
):
    """Not a failed target, so not ERROR: the template parser cannot read it at all.

    cfn_tools' loader reads ``{{ include ... }}`` as a mapping used as a key and
    raises TypeError ("unhashable type: 'ODict'"), not a YAML error. cdk-nag
    counts that TypeError as a file that does not parse, as cfn-nag does, so a Helm
    chart is not a CloudFormation template it failed on and the scan does not
    report ERROR: the parse failure is recorded in the scanner's error stream like
    every other.
    """
    from automated_security_helper.core.phases.scanner_executor import (
        _non_negative_int_attr,
        _target_count_attr,
    )
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )

    name, body = next(
        p.values for p in NOT_CLOUDFORMATION if p.id == "helm-template-unhashable-key"
    )
    from automated_security_helper.utils.cfn_template_model import (
        get_model_from_template_text,
    )

    with pytest.raises(Exception) as raised:
        get_model_from_template_text(body, name)
    assert raised.type.__name__ != "ParserError", (
        "control: the case is a loader error other than the YAML parser's"
    )
    path = context.source_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    scanner = _with_its_tool(CdkNagScanner)(context=context)

    report = _scan_one_tree(scanner, context.source_dir)

    container = ScanResultsContainer(scanner_name="cdk-nag")
    container.targets_attempted = _target_count_attr(scanner, "targets_attempted")
    container.targets_failed = _non_negative_int_attr(scanner, "targets_failed")
    assert container.determine_status("MEDIUM") == ScannerStatus.SKIPPED
    description = report.runs[0].invocations[0].exitCodeDescription or ""
    assert "deployment.yaml is not parseable as YAML or JSON" in description, (
        description
    )


@pytest.mark.parametrize(
    "scanner_class,scanner_name",
    [
        pytest.param(CdkNagScanner, "cdk-nag", id="cdk-nag"),
        pytest.param(CfnNagScanner, "cfn-nag", id="cfn-nag"),
    ],
)
def test_a_damaged_template_in_the_converted_tree_is_the_rows_reason(
    context, cdk_nag_parses_for_real, scanner_class, scanner_name
):
    """Two targets: a source tree with no template, a converted tree with a damaged one.

    The row took the source target's reason first, so it said "no CloudFormation
    template" while the converted target's report said one could not be parsed. A
    template that could not be parsed in either tree is the row's reason.
    """
    from automated_security_helper.utils.cfn_template_model import (
        NO_CLOUDFORMATION_TEMPLATE,
        NO_PARSEABLE_CLOUDFORMATION_TEMPLATE,
    )

    (context.work_dir / "stack.yaml").write_text(
        DAMAGED_TEMPLATES[0].values[1], encoding="utf-8"
    )
    scanner = _with_its_tool(scanner_class)

    with patch.object(scanner, "_run_subprocess") as spawn:
        results = _scan(context, [scanner])

    spawn.assert_not_called()
    reports = results.additional_reports[scanner_name]
    assert reports["source"]["skipped_reason"] == NO_CLOUDFORMATION_TEMPLATE, reports
    assert reports["converted"]["skipped_reason"] == (
        NO_PARSEABLE_CLOUDFORMATION_TEMPLATE
    ), reports
    row = results.scanner_results[scanner_name]
    assert row.status == ScannerStatus.SKIPPED, row
    assert row.skipped_reason == NO_PARSEABLE_CLOUDFORMATION_TEMPLATE, row
    reloaded = populate_metrics_from_unified_source(
        aggregated_results=AshAggregatedResults.model_validate_json(
            results.model_dump_json()
        )
    )
    assert reloaded.scanner_results[scanner_name].skipped_reason == (
        NO_PARSEABLE_CLOUDFORMATION_TEMPLATE
    )


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_with_its_tool_a_template_beside_a_deep_file_is_scanned(
    context, cdk_nag_parses_for_real, scanner_class
):
    """A deep file with no top-level Resources is passed over; it does not end the scan.

    cfn-nag asks whether the file could be a template. Were its lenient re-read
    to let RecursionError out of the except arm, scan() would raise and the
    whole target would be ERROR, the good template's results with it, and
    cdk-nag would treat the RecursionError as a template it failed on. Neither
    file has a top-level Resources mapping, so neither is a template ASH failed
    on.
    """
    (context.source_dir / "deep.json").write_text(DEEP_JSON, encoding="utf-8")
    (context.source_dir / "deep.yaml").write_text(DEEP_YAML, encoding="utf-8")
    (context.source_dir / "stack.json").write_text(
        json.dumps(TEMPLATE), encoding="utf-8"
    )
    scanner = _with_its_tool(scanner_class)(context=context)

    _scan_one_tree(scanner, context.source_dir, spawn_answer=CFN_NAG_CLEAN_RUN)

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 0), (
        f"attempted={scanner.targets_attempted} failed={scanner.targets_failed} "
        f"errors={scanner.errors}"
    )


def _template_tagged(value: str) -> str:
    """A template whose one tag value is *value*, written unquoted."""
    return (
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      Tags:\n"
        "        - Key: created\n"
        f"          Value: {value}\n"
    )


#: Date-like values no calendar holds. YAML's timestamp resolver made each one a
#: date to construct, which raised ValueError, so a real template carrying one was
#: passed over as one that could not be parsed: beside a good template it was never
#: counted, and the gate passed. CloudFormation reads them as strings, and cfn_nag
#: scans them.
DATE_LIKE_VALUES = ["2024-13-01", "2024-02-30"]


def _cfn_nag_answers_with_a_finding_for(marker: str):
    """cfn_nag_scan's answer: one finding, located on the staged copy it was given,
    for a template whose results directory's name holds *marker*.

    The copy has a fixed name (``template`` plus the template's extension) and sits
    in a directory named after the template, so the marker is read off that
    directory's name. The finding's URI is the copy's path, as cfn_nag writes it;
    the scanner points it back at the template, which is what the tests read.
    """

    def answer(command=None, **_kwargs):
        command = [str(a) for a in command or []]
        staged = command[command.index("--input-path") + 1]
        results = []
        if marker in Path(staged).parent.parent.name:
            results = [
                {
                    "ruleId": "W51",
                    "level": "warning",
                    "message": {"text": "finding"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": staged},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            ]
        return {
            "stdout": json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {"tool": {"driver": {"name": "cfn_nag"}}, "results": results}
                    ],
                }
            ),
            "returncode": 0,
        }

    return answer


def test_cfn_nag_with_its_tool_scans_a_template_holding_date_like_values(context):
    """Each dated template is modeled, given to cfn_nag_scan, and its findings kept."""
    (context.source_dir / "stack.json").write_text(json.dumps(TEMPLATE), "utf-8")
    for index, value in enumerate(DATE_LIKE_VALUES):
        (context.source_dir / f"dated-{index}.yaml").write_text(
            _template_tagged(value), encoding="utf-8"
        )
    scanner = _with_its_tool(CfnNagScanner)(context=context)

    with patch.object(
        scanner,
        "_run_subprocess",
        side_effect=_cfn_nag_answers_with_a_finding_for("dated"),
    ) as spawn:
        report = scanner.scan(target=context.source_dir, target_type="source")

    assert (scanner.targets_attempted, scanner.targets_failed) == (3, 0), scanner.errors
    assert spawn.call_count == 3
    found = sorted(
        location.physicalLocation.root.artifactLocation.uri
        for run in report.runs
        for result in run.results or []
        for location in result.locations or []
    )
    assert found == [f"dated-{i}.yaml" for i in range(2)], found


def test_cdk_nag_with_its_tool_evaluates_a_template_holding_date_like_values(
    context, cdk_nag_parses_for_real, monkeypatch
):
    """cdk-nag evaluates each of them, and none fails or is passed over as unparseable."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cdk_nag_scanner,
    )
    from tests.utils.cdk_nag_parse_double import parse_like_the_cdk_nag_wrapper

    evaluated = []

    def recording(template_path, **kwargs):
        response = parse_like_the_cdk_nag_wrapper(template_path, **kwargs)
        if response is not None and response.failure is None:
            evaluated.append(Path(template_path).name)
        return response

    monkeypatch.setattr(cdk_nag_scanner, "run_cdk_nag_against_cfn_template", recording)
    (context.source_dir / "stack.json").write_text(json.dumps(TEMPLATE), "utf-8")
    for index, value in enumerate(DATE_LIKE_VALUES):
        (context.source_dir / f"dated-{index}.yaml").write_text(
            _template_tagged(value), encoding="utf-8"
        )
    scanner = _with_its_tool(CdkNagScanner)(context=context)

    _scan_one_tree(scanner, context.source_dir)

    assert (scanner.targets_attempted, scanner.targets_failed) == (3, 0), scanner.errors
    assert sorted(evaluated) == ["dated-0.yaml", "dated-1.yaml", "stack.json"]


def test_an_unquoted_format_version_stays_the_string_cloudformation_reads():
    """``AWSTemplateFormatVersion: 2010-09-09`` was a date; CloudFormation reads text."""
    from automated_security_helper.utils.cfn_template_model import (
        _TagTolerantLoader,
        get_model_from_template_text,
    )

    text = (
        "AWSTemplateFormatVersion: 2010-09-09\n"
        + _template_tagged("x").split("\n", 1)[1]
    )

    model = get_model_from_template_text(text, "stack.yaml")
    loader = _TagTolerantLoader(text)
    try:
        lenient = loader.get_single_data()
    finally:
        loader.dispose()

    assert model is not None
    assert model.model_extra["AWSTemplateFormatVersion"] == "2010-09-09"
    assert lenient["AWSTemplateFormatVersion"] == "2010-09-09"


def _template_with_properties(*lines: str) -> str:
    """A template whose one resource's Properties block is *lines*, each indented."""
    return (
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n" + "".join(f"      {line}\n" for line in lines)
    )


#: Templates whose syntax parses and one value the loader cannot build, each
#: raising a different error class: a ValueError, which carries no position, and two
#: ConstructorErrors, which carry the line of the value: undecodable binary data
#: (line 8) and a merge of a scalar (line 6).
UNBUILDABLE_TEMPLATES = [
    pytest.param(_template_tagged("!!int forty-two"), None, id="int"),
    pytest.param(_template_tagged("!!binary abcde"), "at line 8", id="binary"),
    pytest.param(
        _template_with_properties("<<: 5"), "at line 6", id="merge-of-a-scalar"
    ),
]


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
@pytest.mark.parametrize("body,line", UNBUILDABLE_TEMPLATES)
def test_with_its_tool_a_template_with_a_value_it_cannot_build_is_a_failed_target(
    context, cdk_nag_parses_for_real, scanner_class, body, line
):
    """A value the loader cannot build, in a file whose structure is a template
    (a top-level Resources mapping), is a template ASH failed on: counted, so the
    gate sees it, never passed over. Beside a good template, one of two failed, and
    the one error names the file and, where the loader knew it, the line: cdk-nag's
    worker does not carry the line back, so cdk-nag words it from its own re-read.
    """
    (context.source_dir / "stack.json").write_text(json.dumps(TEMPLATE), "utf-8")
    (context.source_dir / "broken.yaml").write_text(body, encoding="utf-8")
    scanner = _with_its_tool(scanner_class)(context=context)

    _scan_one_tree(scanner, context.source_dir, spawn_answer=CFN_NAG_CLEAN_RUN)

    assert (scanner.targets_attempted, scanner.targets_failed) == (2, 1), scanner.errors
    (error,) = [e for e in scanner.errors if "broken.yaml" in e]
    assert "could not be built" in error, error
    if line is not None:
        assert line in error, error


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_with_its_tool_a_template_the_model_rejects_is_one_error(
    context, cdk_nag_parses_for_real, scanner_class
):
    """A template with a Resources mapping the model cannot represent is a failed
    target named once. cfn-nag logged it at ERROR, which already records it in the
    scanner's errors, and appended it again."""
    (context.source_dir / "stack.json").write_text(json.dumps(TEMPLATE), "utf-8")
    (context.source_dir / "unmodelable.yaml").write_text(
        "Resources:\n  Bad:\n    Type: 'invalid type with spaces'\n", encoding="utf-8"
    )
    scanner = _with_its_tool(scanner_class)(context=context)

    _scan_one_tree(scanner, context.source_dir, spawn_answer=CFN_NAG_CLEAN_RUN)

    assert (scanner.targets_attempted, scanner.targets_failed) == (2, 1), scanner.errors
    named = [e for e in scanner.errors if "unmodelable.yaml" in e]
    assert len(named) == 1, named
    assert "ValidationError" in named[0], named


def test_cfn_nag_reads_a_template_it_cannot_evaluate_once(context, monkeypatch):
    """The text cfn-nag read is the one its failed-target check judges.

    The file is read once, so the check sees the same text the parser rejected,
    and the scanned tree is not read a second time.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cfn_nag_scanner,
    )
    from automated_security_helper.utils import cfn_template_model

    reads: list[str] = []
    real = cfn_template_model.read_template_text

    def counting(template_path, scan_root):
        reads.append(Path(template_path).name)
        return real(template_path, scan_root)

    monkeypatch.setattr(cfn_nag_scanner, "read_template_text", counting)
    monkeypatch.setattr(cfn_template_model, "read_template_text", counting)
    (context.source_dir / "broken.yaml").write_text(
        _template_tagged("!!binary abcde"), encoding="utf-8"
    )
    scanner = _with_its_tool(CfnNagScanner)(context=context)

    _scan_one_tree(scanner, context.source_dir)

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1), scanner.errors
    assert reads.count("broken.yaml") == 1, reads


def test_a_value_that_cannot_be_built_is_named_with_its_line():
    """TemplateConstructorError carries the loader's mark, so the reason has a line."""
    from automated_security_helper.utils.cfn_template_model import (
        TemplateConstructorError,
        describe_parse_error,
        get_model_from_template_text,
    )

    with pytest.raises(TemplateConstructorError) as raised:
        get_model_from_template_text(_template_tagged("!!binary abcde"), "s.yaml")

    assert describe_parse_error(raised.value) == "TemplateConstructorError at line 8"


#: Kubernetes and Helm files that carry a template as text: a ConfigMap and a
#: CloudFormation-controller Stack, each with a ``{{ .Values.x }}`` the loader reads
#: as a mapping used as a key. Neither has a top-level Resources mapping, so neither
#: is a template ASH failed on, though the template text inside is one.
EMBEDDED_TEMPLATES = [
    pytest.param(
        "chart/templates/configmap.yaml",
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: {{ .Values.name }}\n"
        "data:\n"
        "  template.yaml: |\n"
        "    AWSTemplateFormatVersion: '2010-09-09'\n"
        "    Resources:\n"
        "      Bucket:\n"
        "        Type: AWS::S3::Bucket\n",
        id="configmap",
    ),
    pytest.param(
        "chart/templates/stack.yaml",
        "apiVersion: cloudformation.linki.space/v1alpha1\n"
        "kind: Stack\n"
        "metadata:\n"
        "  name: {{ .Values.stackName }}\n"
        "spec:\n"
        "  template: |\n"
        "    AWSTemplateFormatVersion: '2010-09-09'\n"
        "    Resources:\n"
        "      Bucket:\n"
        "        Type: AWS::S3::Bucket\n",
        id="controller-stack",
    ),
    pytest.param(
        # A template whose structure cannot be read either: a sequence used as a
        # key is a key no reading of the document can build.
        "complex-key.yaml",
        _template_with_properties("? [a, b]", ": value"),
        id="sequence-as-key",
    ),
    # A Helm-templated template: its "{{ .Values.name }}:" resource key is a mapping
    # used as a key, so its structure cannot be read either. With a tab anywhere in
    # it, the structure read took any YAML error for a tab-indented JSON template's
    # and read it again with spaces, so it became a failed target.
    *(
        pytest.param(
            "chart/templates/stack.yaml",
            "AWSTemplateFormatVersion: '2010-09-09'\n"
            f"# {comment}\n"
            f'Description: "{description}"\n'
            "Resources:\n"
            "  {{ .Values.name }}:\n"
            "    Type: AWS::S3::Bucket\n",
            id=case,
        )
        for case, comment, description in (
            ("helm-key", "a comment", "a bucket"),
            ("helm-key-tab-in-a-comment", "a\tcomment", "a bucket"),
            ("helm-key-tab-in-a-value", "a comment", "a\tbucket"),
        )
    ),
]


#: Each case alone in the tree, and beside a good template. Two parameters rather
#: than two scans in one test: the context lists the scanned tree's files once.
BESIDE_A_TEMPLATE = [
    pytest.param(False, id="alone"),
    pytest.param(True, id="beside-a-template"),
]


@pytest.mark.parametrize("beside_a_template", BESIDE_A_TEMPLATE)
@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
@pytest.mark.parametrize("name,body", EMBEDDED_TEMPLATES)
def test_with_its_tool_a_file_whose_structure_is_not_a_template_is_not_counted(
    context, cdk_nag_parses_for_real, scanner_class, name, body, beside_a_template
):
    """Passed over as a file that could not be parsed, alone and beside a template.

    These failed the gate when a CloudFormation marker in the text decided whether
    the file was a template; the template text inside them carries one.
    """
    from automated_security_helper.core.phases.scanner_executor import (
        _skipped_reason_after_scan,
    )
    from automated_security_helper.utils.cfn_template_model import (
        NO_PARSEABLE_CLOUDFORMATION_TEMPLATE,
    )

    path = context.source_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    if beside_a_template:
        (context.source_dir / "stack.json").write_text(json.dumps(TEMPLATE), "utf-8")
    scanner = _with_its_tool(scanner_class)(context=context)

    if beside_a_template:
        _scan_one_tree(scanner, context.source_dir, spawn_answer=CFN_NAG_CLEAN_RUN)
        assert (scanner.targets_attempted, scanner.targets_failed) == (1, 0), (
            scanner.errors
        )
        return
    _scan_one_tree(scanner, context.source_dir)

    assert (scanner.targets_attempted, scanner.targets_failed) == (0, 0), scanner.errors
    assert _skipped_reason_after_scan(scanner, "scanner", "source") == (
        NO_PARSEABLE_CLOUDFORMATION_TEMPLATE
    )


#: Valid templates nested past the YAML loader's recursion limit (about 490 levels of
#: sequences). Each has a top-level Resources mapping, which a read of the YAML event
#: stream finds at any depth.
DEEP_TEMPLATES = [
    pytest.param(
        "deep-stack.yaml",
        _template_with_properties("Deep: " + "[" * 600 + "]" * 600),
        id="yaml-600",
    ),
    pytest.param(
        "deep-stack.json",
        '{"Resources": {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": '
        '{"Deep": ' + "[" * 3000 + "]" * 3000 + "}}}}",
        id="json-3000",
    ),
    pytest.param(
        # Its only tab comes after the depth, so the loader never reached it, and
        # the event read of the text as written stopped at it: a quiet skip.
        "deep-stack.json",
        '{"Resources": {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": '
        '{"Deep": ' + "[" * 600 + "]" * 600 + '}}},\t"Outputs": {}}',
        id="json-600-tab-after-the-depth",
    ),
]


@pytest.mark.parametrize("beside_a_template", BESIDE_A_TEMPLATE)
@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
@pytest.mark.parametrize("name,body", DEEP_TEMPLATES)
def test_with_its_tool_a_template_too_deep_to_evaluate_is_a_failed_target(
    context, cdk_nag_parses_for_real, scanner_class, name, body, beside_a_template
):
    """Alone it is a failed target; beside a good template, one of two failed.

    It counts as a failed target, so the gate sees a real template that was not
    evaluated.
    """
    (context.source_dir / name).write_text(body, encoding="utf-8")
    if beside_a_template:
        (context.source_dir / "stack.json").write_text(json.dumps(TEMPLATE), "utf-8")
    scanner = _with_its_tool(scanner_class)(context=context)

    _scan_one_tree(scanner, context.source_dir, spawn_answer=CFN_NAG_CLEAN_RUN)

    expected = (2, 1) if beside_a_template else (1, 1)
    assert (scanner.targets_attempted, scanner.targets_failed) == expected, (
        scanner.errors
    )
    (error,) = [e for e in scanner.errors if name in e]
    assert "nested" in error, error


def test_cdk_nag_never_synthesizes_a_template_too_deep_to_evaluate(
    context, cdk_nag_parses_for_real, monkeypatch
):
    """The deep JSON template is decided in seconds, and nothing reaches synthesis.

    The parser does not try JSON after YAML's RecursionError, so the template
    never reaches the cdk-nag worker's synthesis, and the outcome is the same on
    every Python version.
    """
    import time

    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cdk_nag_scanner,
    )
    from tests.utils.cdk_nag_parse_double import parse_like_the_cdk_nag_wrapper

    synthesized = []

    def recording(template_path, **kwargs):
        response = parse_like_the_cdk_nag_wrapper(template_path, **kwargs)
        if response is not None and response.failure is None:
            synthesized.append(Path(template_path).name)
        return response

    monkeypatch.setattr(cdk_nag_scanner, "run_cdk_nag_against_cfn_template", recording)
    name, body = next(p.values for p in DEEP_TEMPLATES if p.id == "json-3000")
    (context.source_dir / name).write_text(body, encoding="utf-8")
    scanner = _with_its_tool(CdkNagScanner)(context=context)

    started = time.monotonic()
    _scan_one_tree(scanner, context.source_dir)
    elapsed = time.monotonic() - started

    assert synthesized == []
    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1), scanner.errors
    assert elapsed < 60, f"{elapsed:.1f}s"


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_with_its_tool_a_deep_sequence_is_passed_over_quickly(
    context, cdk_nag_parses_for_real, scanner_class, monkeypatch
):
    """100,000 opening brackets, the shape of a JSON test-suite file, is no template.

    The structural read looks at the root before the rest of the event stream, since
    parsing all of it takes minutes for this file (the YAML scanner's work grows
    with the depth at every token). No reader a decision makes runs its composer to
    the recursion limit, which costs about 1.5 s apiece on Python 3.10 (8 s of CPU
    for one decision's four or five readers, past a 10 s bound under load): a root
    that is a sequence is decided at its first node, and no reader composes the
    file. The time bound is only a guard against a hang.
    """
    import time

    import yaml.composer

    composed = []
    compose = yaml.composer.Composer.get_single_node

    def counting(self):
        composed.append(type(self).__name__)
        return compose(self)

    monkeypatch.setattr(yaml.composer.Composer, "get_single_node", counting)
    # The only candidate, so every composer parse counted is one of this file.
    (context.source_dir / "settings.json").unlink()
    (context.source_dir / "n_structure_100000_opening_arrays.json").write_text(
        "[" * 100000, encoding="utf-8"
    )
    scanner = _with_its_tool(scanner_class)(context=context)

    started = time.monotonic()
    _scan_one_tree(scanner, context.source_dir)
    elapsed = time.monotonic() - started

    assert (scanner.targets_attempted, scanner.targets_failed) == (0, 0), scanner.errors
    assert composed == []
    assert elapsed < 60, f"{elapsed:.1f}s"


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_with_its_tool_a_mapping_root_nested_past_the_bound_is_a_failed_target(
    context, cdk_nag_parses_for_real, scanner_class
):
    """Past 1,000 levels under a mapping root, the read stops and the file counts.

    The read is bounded so a deep mapping root cannot hold a scan for minutes. The
    cost, accepted: such a file is a template ASH could not evaluate ("nested")
    without its Resources being seen, here one that has none.
    """
    import time

    (context.source_dir / "deep-mapping.json").write_text(
        '{"Deep": ' + "[" * 6000 + "]" * 6000 + "}", encoding="utf-8"
    )
    scanner = _with_its_tool(scanner_class)(context=context)

    started = time.monotonic()
    _scan_one_tree(scanner, context.source_dir)
    elapsed = time.monotonic() - started

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1), scanner.errors
    (error,) = [e for e in scanner.errors if "deep-mapping.json" in e]
    assert "nested" in error, error
    assert elapsed < 60, f"{elapsed:.1f}s"


#: A JSON template indented with tabs, nested 3,000 levels. YAML refuses the tab
#: before it reaches the depth, so the text is read as JSON, which reads 3,000 levels
#: on Python 3.12 and later and raises RecursionError on 3.10 and 3.11.
TAB_INDENTED_DEEP_JSON = (
    "{\n"
    '\t"Resources": {\n'
    '\t\t"Bucket": {\n'
    '\t\t\t"Type": "AWS::S3::Bucket",\n'
    '\t\t\t"Properties": {"Deep": ' + "[" * 3000 + "]" * 3000 + "}\n"
    "\t\t}\n"
    "\t}\n"
    "}\n"
)


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_with_its_tool_a_tab_indented_deep_json_template_is_a_failed_target(
    context, cdk_nag_parses_for_real, scanner_class
):
    """The same "nested" failed target as without the tabs, on every Python version.

    Every Python version counts it as the same "nested" failed target, and none
    reaches cdk-nag synthesis.
    """
    (context.source_dir / "tabbed-deep.json").write_text(
        TAB_INDENTED_DEEP_JSON, encoding="utf-8"
    )
    scanner = _with_its_tool(scanner_class)(context=context)

    _scan_one_tree(scanner, context.source_dir, spawn_answer=CFN_NAG_CLEAN_RUN)

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1), scanner.errors
    (error,) = [e for e in scanner.errors if "tabbed-deep.json" in e]
    assert "nested" in error, error


def test_cdk_nag_never_synthesizes_a_tab_indented_deep_json_template(
    context, cdk_nag_parses_for_real, monkeypatch
):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cdk_nag_scanner,
    )
    from tests.utils.cdk_nag_parse_double import parse_like_the_cdk_nag_wrapper

    synthesized = []

    def recording(template_path, **kwargs):
        response = parse_like_the_cdk_nag_wrapper(template_path, **kwargs)
        if response is not None and response.failure is None:
            synthesized.append(Path(template_path).name)
        return response

    monkeypatch.setattr(cdk_nag_scanner, "run_cdk_nag_against_cfn_template", recording)
    (context.source_dir / "tabbed-deep.json").write_text(
        TAB_INDENTED_DEEP_JSON, encoding="utf-8"
    )
    scanner = _with_its_tool(CdkNagScanner)(context=context)

    _scan_one_tree(scanner, context.source_dir)

    assert synthesized == []
    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1), scanner.errors


#: A template with a YAML merge key. CloudFormation itself does not accept hash
#: merges, so such a template is one a preprocessor flattens before it deploys;
#: ASH scans what the merged document says.
MERGED_TEMPLATE = (
    "AWSTemplateFormatVersion: '2010-09-09'\n"
    "Resources:\n"
    "  Bucket:\n"
    "    <<: &bucket\n"
    "      Type: AWS::S3::Bucket\n"
    "    Properties:\n"
    "      BucketName: merged\n"
)


def test_a_merge_key_is_merged_into_its_mapping():
    from automated_security_helper.utils.cfn_template_model import (
        get_model_from_template_text,
    )

    model = get_model_from_template_text(MERGED_TEMPLATE, "merged.yaml")

    assert model is not None
    assert model.Resources["Bucket"].Type == "AWS::S3::Bucket"


def test_cfn_nag_with_its_tool_scans_a_template_with_a_merge_key(context):
    (context.source_dir / "stack.json").write_text(json.dumps(TEMPLATE), "utf-8")
    (context.source_dir / "merged.yaml").write_text(MERGED_TEMPLATE, "utf-8")
    scanner = _with_its_tool(CfnNagScanner)(context=context)

    with patch.object(
        scanner,
        "_run_subprocess",
        side_effect=_cfn_nag_answers_with_a_finding_for("merged"),
    ):
        report = scanner.scan(target=context.source_dir, target_type="source")

    assert (scanner.targets_attempted, scanner.targets_failed) == (2, 0), scanner.errors
    found = [
        location.physicalLocation.root.artifactLocation.uri
        for run in report.runs
        for result in run.results or []
        for location in result.locations or []
    ]
    assert found == ["merged.yaml"], found


def test_cdk_nag_with_its_tool_evaluates_a_template_with_a_merge_key(
    context, cdk_nag_parses_for_real
):
    (context.source_dir / "merged.yaml").write_text(MERGED_TEMPLATE, "utf-8")
    scanner = _with_its_tool(CdkNagScanner)(context=context)

    _scan_one_tree(scanner, context.source_dir)

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 0), scanner.errors


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_with_its_tool_a_control_character_leaves_the_good_template_scanned(
    context, cdk_nag_parses_for_real, scanner_class
):
    """The lenient re-read built its loader outside its try, and the reader raises
    on a non-printable character as it is built: the whole target was ERROR and the
    good template beside the file lost its results."""
    name, body = next(
        p.values for p in DAMAGED_TEMPLATES if p.id == "yaml-control-character"
    )
    (context.source_dir / name).write_text(body, encoding="utf-8")
    (context.source_dir / "stack.json").write_text(json.dumps(TEMPLATE), "utf-8")
    scanner = _with_its_tool(scanner_class)(context=context)

    _scan_one_tree(scanner, context.source_dir, spawn_answer=CFN_NAG_CLEAN_RUN)

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 0), scanner.errors
