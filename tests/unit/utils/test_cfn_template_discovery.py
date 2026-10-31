# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-lint and cfn-guard read exactly the files cfn-nag reads.

``utils/cfn_template_discovery.py`` restates cfn-nag's template selection rather than
sharing it, because cfn-nag was not to be changed. This holds the two to one answer:
the same fixture tree goes through ``discover_templates`` and through
``CfnNagScanner.scan`` with only its subprocess faked, and the files cfn-nag hands
to ``cfn_nag_scan`` must be exactly the discovered templates.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cfn_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
)
from automated_security_helper.utils.cfn_template_discovery import (
    candidate_files,
    discover_templates,
    display_path,
)

TREE = {
    "stack.yaml": "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n",
    "nested/stack.json": '{"Resources": {"T": {"Type": "AWS::SNS::Topic"}}}',
    "short.yml": "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n",
    "intrinsics.yaml": (
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n"
        "    Properties:\n      BucketName: !Sub '${AWS::StackName}-b'\n"
    ),
    "config.yaml": "service:\n  name: x\n",
    "broken.json": '{"Resources": ',
    "custom.yaml": "Resources:\n  X:\n    Type: 'Not A Valid Type!'\n",
    "notes.txt": "Resources: {}\n",
}


@pytest.fixture
def context(ash_temp_path) -> PluginContext:
    source = ash_temp_path / "src"
    for name, text in TREE.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return PluginContext(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        work_dir=source / ".ash" / "ash_output" / "converted",
        config=get_default_config(),
    )


@pytest.mark.unit
def test_discovery_classifies_the_tree(context):
    found = discover_templates(context, "source")
    source = Path(context.source_dir)
    assert [display_path(p, source) for p in found.templates] == [
        "intrinsics.yaml",
        "nested/stack.json",
        "short.yml",
        "stack.yaml",
    ]
    assert [display_path(p, source) for p, _ in found.unmodelable] == ["custom.yaml"]


@pytest.mark.unit
def test_a_candidate_that_is_not_utf8_is_judged_from_its_text(context):
    """At the previous tip every candidate whose UTF-8 read failed was returned in
    ``unreadable`` and counted as a failed target by cfn-lint and cfn-guard, so one
    UTF-16 appsettings.json or Latin-1 locale file in a repository failed every
    CloudFormation scanner with no structure read at all. Now the text, decoded as
    well as it can be, decides: a template ASH could not decode stays a failed
    target, a file that is not CloudFormation is skipped and named."""
    source = Path(context.source_dir)
    (source / "latin-notes.yaml").write_bytes(b"greeting: caf\xe9\n")
    (source / "latin-stack.yaml").write_bytes(b"Resources:\n  caf\xe9: {}\n")
    (source / "utf16.json").write_bytes(
        '{"Resources": {"T": {"Type": "AWS::SNS::Topic"}}}'.encode("utf-16")
    )
    # No byte-order mark: the bytes decode as UTF-8 without an error (NUL is valid
    # UTF-8), so the text reaches the parsers NUL-interleaved and both reject it;
    # the reading as UTF-16 (or UTF-32) is what finds the template, and it is a
    # template ASH could not decode, a failed target with the encoding in its
    # reason, as its marked twin is. Named as a template that could not be parsed,
    # it was counted as nothing; dropped at TRACE before that, it vanished.
    (source / "utf16-nomark.json").write_bytes(
        '{"Resources": {"T": {"Type": "AWS::SNS::Topic"}}}'.encode("utf-16-le")
    )
    (source / "utf32-nomark.json").write_bytes(
        '{"Resources": {"T": {"Type": "AWS::SNS::Topic"}}}'.encode("utf-32-be")
    )
    # No byte-order mark and a character outside ASCII: its UTF-16 bytes are not
    # UTF-8, so this one takes the UnicodeDecodeError arm, where the lenient
    # decode reads it as UTF-16 and finds the template.
    (source / "utf16-nomark-accent.json").write_bytes(
        '{"Resources": {"Café": {"Type": "AWS::SNS::Topic"}}}'.encode("utf-16-le")
    )

    found = discover_templates(context, "source")

    assert [shown for shown, _ in found.skipped] == ["latin-notes.yaml"]
    assert "not UTF-8" in found.skipped[0][1], found.skipped
    unreadable = dict(found.unreadable)
    assert sorted(unreadable) == [
        "latin-stack.yaml",
        "utf16-nomark-accent.json",
        "utf16-nomark.json",
        "utf16.json",
        "utf32-nomark.json",
    ]
    assert found.unparseable == []
    for shown in ("latin-stack.yaml", "utf16-nomark-accent.json", "utf16.json"):
        assert "UnicodeDecodeError" in unreadable[shown], unreadable
    assert "UTF-16 text without a byte-order mark" in unreadable["utf16-nomark.json"]
    assert "UTF-32 text without a byte-order mark" in unreadable["utf32-nomark.json"]
    assert [display_path(p, source) for p in found.templates] == [
        "intrinsics.yaml",
        "nested/stack.json",
        "short.yml",
        "stack.yaml",
    ]


# A Jinja-templated stack: a CloudFormation marker in text neither parser reads,
# and no Resources mapping any reading can build. The comment's "ü" makes the
# cp1252 copy invalid UTF-8, so that copy takes the UnicodeDecodeError arm.
JINJA_STACK = (
    "# Warteschlange für {{ env }}\n"
    "{% for q in queues %}\n"
    "Resources:\n"
    "  {{ q }}:\n"
    "    Type: AWS::SQS::Queue\n"
    "{% endfor %}\n"
)


@pytest.mark.unit
def test_the_encoding_of_a_damaged_template_does_not_change_its_answer(context):
    """One Jinja-templated stack, saved as UTF-8 and as cp1252. The UTF-8 copy is
    named as a template that could not be parsed, counted as nothing: neither
    parser reads it and no reading of it has a Resources mapping, only the
    marker. At the previous tip the cp1252 copy was a FAILED target, because the
    undecodable route answered from the marker alone where the UTF-8 route takes
    a structure read; so saving the same file in another encoding turned a
    WARNING into an ERROR in three scanners. Both copies now read the same."""
    source = Path(context.source_dir)
    (source / "jinja-utf8.yaml").write_bytes(JINJA_STACK.encode("utf-8"))
    (source / "jinja-cp1252.yaml").write_bytes(JINJA_STACK.encode("cp1252"))
    with pytest.raises(UnicodeDecodeError):
        JINJA_STACK.encode("cp1252").decode("utf-8")

    found = discover_templates(context, "source")

    assert [shown for shown, _ in found.unparseable] == [
        "jinja-cp1252.yaml",
        "jinja-utf8.yaml",
    ]
    assert found.unreadable == []
    assert found.skipped == []
    for _, reason in found.unparseable:
        assert reason.startswith("it could be a CloudFormation template"), reason
    assert "UnicodeDecodeError" in found.unparseable[0][1]
    assert len(found.templates) == 4


# The same Jinja-templated stack with an ASCII comment, so that its UTF-16 and
# UTF-32 bytes, written without a byte-order mark, are valid UTF-8 (NUL is valid
# UTF-8) and take the route of text that reaches the parsers NUL-interleaved.
JINJA_STACK_ASCII = (
    "# Queue for {{ env }}\n"
    "{% for q in queues %}\n"
    "Resources:\n"
    "  {{ q }}:\n"
    "    Type: AWS::SQS::Queue\n"
    "{% endfor %}\n"
)


@pytest.mark.unit
def test_a_marker_only_template_without_a_byte_order_mark_reads_unparseable(context):
    """A UTF-16 or UTF-32 file written without a byte-order mark reaches the
    parsers NUL-interleaved, and is read again in those encodings. When the reading
    carries a CloudFormation marker but no reading of it has a Resources mapping, it
    is a damaged template, not a failed target: a marker alone never makes one, on
    any route. At the previous tip this route decided from the marker, so the two
    wide copies were unreadable while the UTF-8 copy of the same text was
    unparseable. All three now read alike."""
    source = Path(context.source_dir)
    (source / "jinja-utf8.yaml").write_bytes(JINJA_STACK_ASCII.encode("utf-8"))
    (source / "jinja-utf16-nomark.yaml").write_bytes(
        JINJA_STACK_ASCII.encode("utf-16-le")
    )
    (source / "jinja-utf32-nomark.yaml").write_bytes(
        JINJA_STACK_ASCII.encode("utf-32-be")
    )
    # What makes the wide copies reach the NUL-interleaved route and not the
    # UnicodeDecodeError arm: their bytes decode as UTF-8.
    for name in ("jinja-utf16-nomark.yaml", "jinja-utf32-nomark.yaml"):
        assert b"\x00" in (source / name).read_bytes()
        (source / name).read_bytes().decode("utf-8")

    found = discover_templates(context, "source")

    assert [shown for shown, _ in found.unparseable] == [
        "jinja-utf16-nomark.yaml",
        "jinja-utf32-nomark.yaml",
        "jinja-utf8.yaml",
    ]
    assert found.unreadable == []
    assert found.skipped == []
    for _, reason in found.unparseable:
        assert reason.startswith("it could be a CloudFormation template"), reason
    assert len(found.templates) == 4


# A real Resources mapping with one value no YAML constructor can build: the int tag
# on a word. The shape is a template; the value is why ASH cannot evaluate it. The
# accented comment makes the cp1252 copy invalid UTF-8, so that copy takes the
# UnicodeDecodeError arm; the ASCII copy's UTF-16 and UTF-32 bytes, written without a
# byte-order mark, are valid UTF-8 and take the NUL-interleaved route.
UNBUILDABLE_STACK = (
    "# Queue settings\n"
    "Resources:\n"
    "  Q:\n"
    "    Type: AWS::SQS::Queue\n"
    "    Properties:\n"
    "      DelaySeconds: !!int forty-two\n"
)
UNBUILDABLE_STACK_ACCENT = UNBUILDABLE_STACK.replace(
    "# Queue settings", "# Warteschlange für die Queue"
)


@pytest.mark.unit
def test_a_value_that_cannot_be_built_does_not_hide_a_template_in_any_encoding(
    context,
):
    """One template with a Resources mapping and a value no constructor can build,
    saved as UTF-8, as cp1252 and as UTF-16 and UTF-32 without a byte-order mark. The
    UTF-8 copy is a failed target: the structure is read without building a value.
    At the previous tip the other three were decided by a read that builds values,
    which raised on the int tag and found no document, so each read as a file that
    could not be parsed where its UTF-8 twin was a failed target, and saving a
    template in another encoding refused it less. All four now read alike."""
    source = Path(context.source_dir)
    (source / "unbuildable-utf8.yaml").write_bytes(UNBUILDABLE_STACK.encode("utf-8"))
    (source / "unbuildable-cp1252.yaml").write_bytes(
        UNBUILDABLE_STACK_ACCENT.encode("cp1252")
    )
    (source / "unbuildable-utf16-nomark.yaml").write_bytes(
        UNBUILDABLE_STACK.encode("utf-16-le")
    )
    (source / "unbuildable-utf32-nomark.yaml").write_bytes(
        UNBUILDABLE_STACK.encode("utf-32-be")
    )
    # What routes each copy: the accented cp1252 bytes are not UTF-8; the wide
    # copies' bytes are, since NUL is valid UTF-8.
    with pytest.raises(UnicodeDecodeError):
        UNBUILDABLE_STACK_ACCENT.encode("cp1252").decode("utf-8")
    for name in ("unbuildable-utf16-nomark.yaml", "unbuildable-utf32-nomark.yaml"):
        assert b"\x00" in (source / name).read_bytes()
        (source / name).read_bytes().decode("utf-8")

    found = discover_templates(context, "source")

    assert sorted(display_path(p, source) for p, _ in found.unmodelable) == [
        "custom.yaml",
        "unbuildable-utf8.yaml",
    ]
    unreadable = dict(found.unreadable)
    assert sorted(unreadable) == [
        "unbuildable-cp1252.yaml",
        "unbuildable-utf16-nomark.yaml",
        "unbuildable-utf32-nomark.yaml",
    ]
    assert "UnicodeDecodeError" in unreadable["unbuildable-cp1252.yaml"], unreadable
    assert (
        "UTF-16 text without a byte-order mark"
        in unreadable["unbuildable-utf16-nomark.yaml"]
    )
    assert (
        "UTF-32 text without a byte-order mark"
        in unreadable["unbuildable-utf32-nomark.yaml"]
    )
    assert found.unparseable == []
    assert found.skipped == []
    assert len(found.templates) == 4


@pytest.mark.unit
def test_a_value_that_cannot_be_built_in_a_file_without_resources_is_not_a_template(
    context,
):
    """The same unbuildable int tag in a file with no Resources mapping is no
    template in any encoding: the structure read that finds the mapping in the test
    above finds none here, so the non-UTF-8 copy is skipped as not CloudFormation and
    the UTF-16 copy is not named at all, as their UTF-8 twin is not."""
    source = Path(context.source_dir)
    settings = "# Queue settings\nsettings:\n  DelaySeconds: !!int forty-two\n"
    accent = settings.replace("# Queue settings", "# Warteschlange für die Queue")
    (source / "settings-utf8.yaml").write_bytes(settings.encode("utf-8"))
    (source / "settings-cp1252.yaml").write_bytes(accent.encode("cp1252"))
    (source / "settings-utf16-nomark.yaml").write_bytes(settings.encode("utf-16-le"))

    found = discover_templates(context, "source")

    assert [shown for shown, _ in found.skipped] == ["settings-cp1252.yaml"]
    assert [p.name for p, _ in found.unmodelable] == ["custom.yaml"]
    assert found.unreadable == []
    assert found.unparseable == []
    assert len(found.templates) == 4


@pytest.mark.unit
def test_a_second_read_that_fails_is_answered_as_a_template(context):
    """The judgment reads the candidate again; a file gone or swapped under the
    first read fails that read. At the previous tip the callers each caught OSError
    around it and one of them (discovery) let TreeInputRefused, a plain Exception,
    escape. The judgment answers the failure itself, as the doubt: a template."""
    from automated_security_helper.utils.cfn_template_model import (
        UNDECODABLE_TEMPLATE,
        judge_undecodable_candidate,
    )

    source = Path(context.source_dir)
    gone = source / "gone.yaml"
    assert not gone.exists()

    assert judge_undecodable_candidate(gone, source) == UNDECODABLE_TEMPLATE


@pytest.mark.unit
@pytest.mark.skipif(not hasattr(os, "link"), reason="no hard links")
def test_a_hard_linked_non_utf8_candidate_is_judged_like_its_twin(context):
    """The first read of a candidate admits a hard-linked regular file; at the
    previous tip the second read, made to judge a non-UTF-8 candidate from its text,
    opened with the default that refuses a hard link, so TreeInputRefused escaped
    the UnicodeDecodeError arm (which catches OSError only) and one hard-linked
    Latin-1 .yaml ended the discovery of the whole target. Both names are now
    skipped, as the unlinked file is."""
    source = Path(context.source_dir)
    (source / "latin-notes.yaml").write_bytes(b"greeting: caf\xe9\n")
    os.link(source / "latin-notes.yaml", source / "linked-notes.yaml")

    found = discover_templates(context, "source")

    assert [shown for shown, _ in found.skipped] == [
        "latin-notes.yaml",
        "linked-notes.yaml",
    ]
    assert found.unreadable == []
    assert len(found.templates) == 4


@pytest.mark.integration
def test_cfn_nag_selects_the_same_templates(context):
    """The agreement test the discovery module's docstring promises."""
    handed_to_cfn_nag = []
    stage = cfn_nag_scanner._stage_cfn_nag_input

    # cfn_nag_scan reads a staged copy of each template's checked text, so the
    # template it was given is the one staged, not the --input-path it opens.
    def record_stage(results_file_dir, cfn_file, text):
        handed_to_cfn_nag.append(Path(cfn_file))
        return stage(results_file_dir, cfn_file, text)

    def fake_run(self, command, **kwargs):
        return {
            "stdout": '{"version": "2.1.0", "runs": [{"tool": {"driver": '
            '{"name": "cfn_nag"}}, "results": []}]}',
            "stderr": "",
            "returncode": 0,
        }

    scanner = CfnNagScanner(context=context)
    with (
        patch.object(CfnNagScanner, "validate_plugin_dependencies", return_value=True),
        patch.object(CfnNagScanner, "_run_subprocess", fake_run),
        patch.object(cfn_nag_scanner, "_stage_cfn_nag_input", record_stage),
    ):
        scanner.scan(target=Path(context.source_dir), target_type="source")

    discovered = discover_templates(context, "source")
    assert sorted(p.resolve() for p in handed_to_cfn_nag) == sorted(
        p.resolve() for p in discovered.templates
    )
    # And they count the unmodelable template the same way.
    assert scanner.targets_failed == len(discovered.unmodelable) == 1


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


@pytest.mark.integration
def test_a_symlinked_template_is_refused_by_both(context):
    """A template reached through a symlink is read by neither, and named by both.

    The link points inside the tree, so the scan set keeps it and the readers' own
    check is what refuses it; a link out of the tree is left out before that (below).
    """
    link = Path(context.source_dir) / "linked.yaml"
    _symlink_or_skip(link, Path(context.source_dir) / "stack.yaml")

    discovered = discover_templates(context, "source")

    assert link not in discovered.templates
    assert [shown for shown, _ in discovered.refused] == ["linked.yaml"]
    test_cfn_nag_selects_the_same_templates(context)


@pytest.mark.integration
def test_a_template_linked_from_outside_the_tree_is_left_out_by_the_scan_set(
    context, ash_temp_path, caplog
):
    """The scan set both readers take their files from leaves such a link out.

    So neither reader's own check sees it: it is not a template and not refused,
    and the warning is the scan set's, naming the link and not its target.
    """
    outside = ash_temp_path / "elsewhere" / "outside.yaml"
    outside.parent.mkdir()
    outside.write_text(TREE["stack.yaml"], encoding="utf-8")
    link = Path(context.source_dir) / "linked.yaml"
    _symlink_or_skip(link, outside)

    with caplog.at_level("WARNING"):
        discovered = discover_templates(context, "source")

    assert link not in discovered.templates
    assert discovered.refused == []
    assert "Not scanning 'linked.yaml': link leaves the scanned tree" in caplog.text
    assert outside.as_posix() not in caplog.text
    test_cfn_nag_selects_the_same_templates(context)


@pytest.mark.unit
@pytest.mark.parametrize("honor", [True, False])
def test_the_gitignore_applies_as_the_config_says(context, honor):
    """The scan set discovery computes itself follows ``honor_ignore_files``, as
    cfn-nag's does."""
    source = Path(context.source_dir)
    (source / ".gitignore").write_text("stack.yaml\n", encoding="utf-8")
    context.config.honor_ignore_files = honor

    names = {
        p.relative_to(source).as_posix() for p in candidate_files(context, "source")
    }

    assert ("stack.yaml" in names) is not honor
    assert "nested/stack.json" in names


@pytest.mark.unit
def test_display_path_is_relative_inside_and_absolute_outside(tmp_path):
    source = tmp_path / "src"
    assert display_path(source / "a" / "b.yaml", source) == "a/b.yaml"
    outside = tmp_path / "out" / "c.yaml"
    assert display_path(outside, source) == outside.absolute().as_posix()
