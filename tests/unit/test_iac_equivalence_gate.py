"""Positive controls for deploy/tests/iac-equivalence.py.

WHY THIS FILE EXISTS
--------------------
iac-equivalence.py compares ASH's CloudFormation templates against its
Terraform modules. It currently exits 0, and a check that has only ever been
run against matching inputs is indistinguishable from a check that always
passes. These tests plant divergences and require the check to reject each one.

EVERY TEST PROVES ITS OWN MUTATION WAS REAL
-------------------------------------------
A mutation that does not change the PARSED representation -- an edit to a
comment, a resource added to a file the parser never reads, a regex that
silently stopped matching -- produces a check that fails for the wrong reason
or passes for the wrong reason, and either way the test still looks green. So
each test asserts twice:

  1. the parsed representation actually changed, using the checker's OWN
     parser against the mutated tree, and
  2. the check's verdict flipped, with the message naming the planted problem.

Assertion 1 is the one that makes assertion 2 worth anything.

The checker is exercised as a copied file inside a scratch tree rather than
through an injected root path. That keeps the shipped script free of a
test-only seam, and means these tests run the file as it actually ships --
including its own `Path(__file__).parent.parent` path resolution, which an
injected root would bypass and therefore never test.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
CHECKER_REL = Path("deploy/tests/iac-equivalence.py")


# ---------------------------------------------------------------------------
# Scratch trees
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def pristine(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One copy of the parts of deploy/ the checker reads."""
    root = tmp_path_factory.mktemp("iac-equivalence-pristine")
    deploy = root / "deploy"

    templates = deploy / "cdk" / "templates"
    templates.mkdir(parents=True)
    sources = sorted((REPO / "deploy/cdk/templates").glob("*.template.json"))
    if not sources:
        pytest.fail(
            "deploy/cdk/templates holds no *.template.json, so these tests "
            "would run against an empty tree and prove nothing."
        )
    for src in sources:
        shutil.copy2(src, templates / src.name)

    shutil.copytree(
        REPO / "deploy/terraform/modules",
        deploy / "terraform" / "modules",
        ignore=shutil.ignore_patterns(".terraform", ".terraform.lock.hcl"),
    )

    (deploy / "tests").mkdir(parents=True)
    shutil.copy2(REPO / CHECKER_REL, deploy / "tests" / CHECKER_REL.name)
    return root


@pytest.fixture
def tree(pristine: Path, tmp_path: Path) -> Path:
    """A fresh mutable copy per test."""
    root = tmp_path / "wt"
    shutil.copytree(pristine, root)
    return root


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def run_checker(tree: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(tree / "deploy" / "tests" / CHECKER_REL.name)],
        capture_output=True,
        text=True,
        check=False,
    )


def load_checker(tree: Path) -> ModuleType:
    """Import the copied checker so its own parser can be called directly.

    Imported under a per-tree module name so two trees in one session cannot
    collide in sys.modules and hand a test the other tree's baked-in paths.
    """
    path = tree / "deploy" / "tests" / CHECKER_REL.name
    name = f"iac_equivalence_{abs(hash(str(tree)))}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        pytest.fail(f"could not import the checker from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def template(tree: Path, stack: str) -> Path:
    return tree / "deploy/cdk/templates" / f"{stack}.template.json"


def tf_main(tree: Path, module: str) -> Path:
    return tree / "deploy/terraform/modules" / module / "main.tf"


def add_cfn_resource(path: Path, logical_id: str, rtype: str) -> None:
    doc = json.loads(path.read_text())
    doc["Resources"][logical_id] = {"Type": rtype, "Properties": {}}
    path.write_text(json.dumps(doc, indent=1))


def drop_tf_resource(text: str, rtype: str) -> str:
    """Remove the first `resource "<rtype>" "..." { ... }` block.

    Leans on the same column-0 invariant the checker does: formatted HCL puts
    top-level blocks at column 0 and closes them with `}` at column 0, and
    ash-iac-drift.yml enforces `terraform fmt -check`.
    """
    pattern = re.compile(
        r'^resource\s+"' + re.escape(rtype) + r'"\s+"[^"]+"\s*\{.*?^\}\n',
        re.MULTILINE | re.DOTALL,
    )
    mutated, count = pattern.subn("", text, count=1)
    if count != 1:
        raise AssertionError(
            f'expected to remove exactly one `resource "{rtype}"` block, '
            f"removed {count}. The fixture no longer matches the tree, so a "
            "test built on it would prove nothing."
        )
    return mutated


# ---------------------------------------------------------------------------
# The negative control. Without this the suite cannot tell a working check
# from one that rejects everything.
# ---------------------------------------------------------------------------
def test_the_unmutated_tree_passes(tree: Path) -> None:
    result = run_checker(tree)
    if result.returncode != 0:
        pytest.fail(
            "the checker rejected an unmutated copy of the real tree, so every "
            "rejection below would be meaningless:\n"
            f"{result.stdout}\n{result.stderr}"
        )
    assert "No unrecorded divergence" in result.stdout


def test_the_checker_reads_all_five_pairs(tree: Path) -> None:
    """A pass over zero pairs would also exit 0."""
    result = run_checker(tree)
    for stack in (
        "AshImagePipeline",
        "AshAgentCore",
        "AshCodeCommitGate",
        "AshDistributedPipeline",
        "AshFargate",
    ):
        assert f"=== {stack}" in result.stdout, (
            f"{stack} was not compared. The checker exits 0 over an empty pair "
            "set too, so coverage has to be asserted separately from the verdict."
        )


# ---------------------------------------------------------------------------
# Planted divergences
# ---------------------------------------------------------------------------
def test_an_unmapped_cfn_resource_type_is_rejected(tree: Path) -> None:
    """The check that closes the stated gap: a NEW kind nobody has classified."""
    path = template(tree, "AshImagePipeline")
    before = load_checker(tree).load_cfn("AshImagePipeline")
    add_cfn_resource(path, "PlantedQueue", "AWS::SQS::Queue")
    after = load_checker(tree).load_cfn("AshImagePipeline")

    # The mutation was real: the parsed representation gained the type.
    assert "AWS::SQS::Queue" not in before
    assert after.get("AWS::SQS::Queue") == 1

    result = run_checker(tree)
    assert result.returncode != 0
    assert "AWS::SQS::Queue" in result.stdout
    assert "not in this check's vocabulary" in result.stdout


def test_an_unmapped_terraform_resource_type_is_rejected(tree: Path) -> None:
    path = tf_main(tree, "ash-image-pipeline")
    before = load_checker(tree).load_tf("ash-image-pipeline")
    path.write_text(
        path.read_text() + '\nresource "aws_sns_topic" "planted" {\n  name = "x"\n}\n'
    )
    after = load_checker(tree).load_tf("ash-image-pipeline")

    assert "aws_sns_topic" not in before
    assert after.get("aws_sns_topic") == 1

    result = run_checker(tree)
    assert result.returncode != 0
    assert "aws_sns_topic" in result.stdout
    assert "not in this check's vocabulary" in result.stdout


def test_a_mapped_kind_added_to_cfn_alone_is_rejected(tree: Path) -> None:
    """A known kind on the CFN side that the Terraform side does not have."""
    path = template(tree, "AshImagePipeline")
    checker = load_checker(tree)
    before = checker.load_cfn("AshImagePipeline")
    add_cfn_resource(path, "PlantedLb", "AWS::ElasticLoadBalancingV2::LoadBalancer")
    after = load_checker(tree).load_cfn("AshImagePipeline")

    assert "AWS::ElasticLoadBalancingV2::LoadBalancer" not in before
    assert after.get("AWS::ElasticLoadBalancingV2::LoadBalancer") == 1
    # And the Terraform side really does lack it, so the divergence is genuine
    # rather than an artifact of the pair being mismatched.
    assert "aws_lb" not in checker.load_tf("ash-image-pipeline")

    result = run_checker(tree)
    assert result.returncode != 0
    assert "load-balancer" in result.stdout
    assert "diverges" in result.stdout


def test_a_kind_removed_from_terraform_alone_is_rejected(tree: Path) -> None:
    """Drift in the other direction: Terraform stops provisioning something."""
    path = tf_main(tree, "ash-image-pipeline")
    before = load_checker(tree).load_tf("ash-image-pipeline")
    path.write_text(drop_tf_resource(path.read_text(), "aws_ecr_repository"))
    after = load_checker(tree).load_tf("ash-image-pipeline")

    assert before.get("aws_ecr_repository") == 1
    assert "aws_ecr_repository" not in after

    result = run_checker(tree)
    assert result.returncode != 0
    assert "ecr-repository" in result.stdout
    assert "diverges" in result.stdout


def test_a_non_provider_lambda_is_still_counted(tree: Path) -> None:
    """Proves the custom-resource exclusion is narrow, not a blanket one.

    provider_functions() removes the Lambda backing Custom::AshImageBootstrap.
    If that exclusion were broad -- matching on type, or on a name pattern --
    it would also swallow a real Lambda and the check would stop being able to
    see one appear on only one side. AshImagePipeline has no custom resource at
    all, so a Lambda planted there must be counted and must diverge.
    """
    path = template(tree, "AshImagePipeline")
    before = load_checker(tree).load_cfn("AshImagePipeline")
    add_cfn_resource(path, "PlantedFn", "AWS::Lambda::Function")
    after = load_checker(tree).load_cfn("AshImagePipeline")

    assert "AWS::Lambda::Function" not in before
    assert after.get("AWS::Lambda::Function") == 1, (
        "the planted Lambda was dropped by the parser, so this test would pass "
        "whether or not the exclusion is narrow"
    )

    result = run_checker(tree)
    assert result.returncode != 0
    assert "lambda-function" in result.stdout


def test_the_provider_lambda_really_is_excluded(tree: Path) -> None:
    """The other half of the exclusion: it does fire where it should.

    Without this, test_a_non_provider_lambda_is_still_counted would also pass
    if provider_functions() excluded nothing at all.
    """
    checker = load_checker(tree)
    raw = json.loads(template(tree, "AshAgentCore").read_text())["Resources"]
    providers = checker.provider_functions(raw)

    assert providers, (
        "no custom-resource provider was identified in AshAgentCore, which "
        "carries Custom::AshImageBootstrap. The structural lookup has stopped "
        "working and its exclusion is now a no-op."
    )
    for logical_id in providers:
        assert raw[logical_id]["Type"] == "AWS::Lambda::Function"
    # Present in the raw template, absent from the parsed census.
    assert "AWS::Lambda::Function" in {b["Type"] for b in raw.values()}
    assert "AWS::Lambda::Function" not in checker.load_cfn("AshAgentCore")


def test_fixing_a_baselined_divergence_is_rejected_as_stale(tree: Path) -> None:
    """A baseline that outlives its divergence is the wildcard it exists to avoid."""
    path = tf_main(tree, "ash-image-pipeline")
    before = load_checker(tree).load_tf("ash-image-pipeline")
    path.write_text(
        path.read_text()
        + '\nresource "aws_kms_key" "planted" {\n  description = "x"\n}\n'
    )
    after = load_checker(tree).load_tf("ash-image-pipeline")

    assert "aws_kms_key" not in before
    assert after.get("aws_kms_key") == 1

    result = run_checker(tree)
    assert result.returncode != 0
    assert "kms-key" in result.stdout
    assert "delete this baseline entry" in result.stdout


def test_a_pair_table_that_disagrees_with_its_example_is_rejected(
    tree: Path,
) -> None:
    """The positive control on PAIRS itself.

    PAIRS asserts that AshAgentCore's counterpart is agentcore PLUS
    ash-image-pipeline. If the example stops composing the image build, the
    union PAIRS describes no longer exists and every census built on it is
    measuring the wrong thing.
    """
    example = tree / "deploy/terraform/modules/agentcore/examples/basic/main.tf"
    text = example.read_text()
    assert "../../../ash-image-pipeline" in text
    example.write_text(text.replace("../../../ash-image-pipeline", "../.."))

    result = run_checker(tree)
    assert result.returncode != 0
    assert "composes" in result.stdout
    assert "AshAgentCore" in result.stdout


# ---------------------------------------------------------------------------
# Stack-level coverage.
#
# The census used to iterate PAIRS and never glob CFN_DIR, so a committed
# template absent from PAIRS was never opened: exit 0, its name absent from the
# output, and its resource types never checked against the vocabulary. These
# tests hold the glob up.
# ---------------------------------------------------------------------------
PLANTED_STACK = "AshPlantedStack"


def add_unclassified_template(tree: Path, stack: str = PLANTED_STACK) -> Path:
    """A committed template, named in neither table, with unmapped types.

    The stack name is invented so it can never collide with a real template.
    The types are real CloudFormation types that no KINDS entry maps; the
    tests that use this assert that before relying on it.
    """
    path = template(tree, stack)
    path.write_text(
        json.dumps(
            {
                "Resources": {
                    "Nodegroup": {
                        "Type": "AWS::EKS::Nodegroup",
                        "Properties": {},
                    },
                    "Addon": {
                        "Type": "AWS::EKS::Addon",
                        "Properties": {},
                    },
                }
            },
            indent=1,
        )
    )
    return path


def test_an_unclassified_template_is_rejected(tree: Path) -> None:
    """The defect: a template read by nobody, reported as no divergence."""
    checker = load_checker(tree)
    before = sorted(p.name for p in checker.CFN_DIR.glob("*.template.json"))
    add_unclassified_template(tree)
    after_checker = load_checker(tree)
    after = sorted(p.name for p in after_checker.CFN_DIR.glob("*.template.json"))

    # The mutation was real, and it is real in the terms the FIX uses: the glob
    # the checker now performs sees one more template than it did.
    assert len(after) == len(before) + 1
    assert f"{PLANTED_STACK}.template.json" in after
    assert f"{PLANTED_STACK}.template.json" not in before
    # And it really is unclassified -- neither table names it.
    assert PLANTED_STACK not in {str(p["stack"]) for p in after_checker.PAIRS}
    assert PLANTED_STACK not in after_checker.STACKS_WITHOUT_TERRAFORM
    # And its types really are outside the vocabulary, so the type-level teeth
    # would have had something to say had the stack been read at all.
    mapped = {t for m in after_checker.KINDS.values() for t in m["cfn"]}
    assert "AWS::EKS::Nodegroup" not in mapped

    result = run_checker(tree)
    assert result.returncode != 0
    assert PLANTED_STACK in result.stdout
    assert "classified nowhere" in result.stdout


def test_a_declared_uncompared_stack_still_has_its_types_checked(tree: Path) -> None:
    """Declaring "no Terraform counterpart" removes the census, not the type check.

    If it removed both, STACKS_WITHOUT_TERRAFORM would be a way to make an
    unclassified stack disappear rather than a way to record one.
    """
    add_unclassified_template(tree)
    path = tree / "deploy/tests" / CHECKER_REL.name
    text = path.read_text()
    anchor = "STACKS_WITHOUT_TERRAFORM: dict[str, str] = {"
    assert anchor in text
    path.write_text(
        text.replace(
            anchor,
            anchor + f'\n    "{PLANTED_STACK}": "planted by a test",',
        )
    )
    mapped = {t for m in load_checker(tree).KINDS.values() for t in m["cfn"]}
    assert "AWS::EKS::Nodegroup" not in mapped

    result = run_checker(tree)
    # The coverage error is gone -- the stack is classified now.
    assert "classified nowhere" not in result.stdout
    # But the stack is named in the report rather than silently dropped...
    assert f"=== {PLANTED_STACK}  <->  (no Terraform counterpart)" in result.stdout
    # ...and its unmapped types still fail the run.
    assert result.returncode != 0
    assert "AWS::EKS::Nodegroup" in result.stdout
    assert "not in this check's vocabulary" in result.stdout


def test_the_committed_eks_stack_is_read_and_type_checked(tree: Path) -> None:
    """AshEksOperator has no Terraform module; it must still be opened.

    The EKS stack and this check arrived on separate branches. Combined, the
    template was unclassified and its AWS::EKS::* and generic custom-resource
    types were outside the vocabulary, so the run failed. This holds the
    resolution: it is declared uncompared, and every one of its types is mapped.
    """
    checker = load_checker(tree)
    assert "AshEksOperator" in checker.STACKS_WITHOUT_TERRAFORM
    assert (checker.CFN_DIR / "AshEksOperator.template.json").is_file()
    types = {
        body["Type"]
        for body in json.loads(template(tree, "AshEksOperator").read_text())[
            "Resources"
        ].values()
    }
    mapped = {t for m in checker.KINDS.values() for t in m["cfn"]}
    excluded = set(checker.CFN_EXCLUDED)
    assert "AWS::EKS::AccessEntry" in types
    assert types <= mapped | excluded, types - mapped - excluded

    result = run_checker(tree)
    assert result.returncode == 0, result.stdout
    assert "=== AshEksOperator  <->  (no Terraform counterpart)" in result.stdout


def test_a_generic_custom_resource_in_a_paired_stack_is_reported(
    tree: Path,
) -> None:
    """AWS::CloudFormation::CustomResource is mapped, not excluded.

    Excluding it would make one added to a paired stack invisible. Mapped to a
    kind with no Terraform side, it surfaces as an unrecorded cfn-only
    divergence.
    """
    path = template(tree, "AshImagePipeline")
    add_cfn_resource(path, "PlantedCustom", "AWS::CloudFormation::CustomResource")
    checker = load_checker(tree)
    assert "AWS::CloudFormation::CustomResource" in checker.load_cfn("AshImagePipeline")

    result = run_checker(tree)
    assert result.returncode != 0
    assert "cfn-generic-custom-resource" in result.stdout


def test_a_declared_stack_with_no_template_is_rejected(tree: Path) -> None:
    """A stale STACKS_WITHOUT_TERRAFORM entry would suppress a real coverage error."""
    path = tree / "deploy/tests" / CHECKER_REL.name
    text = path.read_text()
    anchor = "STACKS_WITHOUT_TERRAFORM: dict[str, str] = {"
    path.write_text(
        text.replace(anchor, anchor + '\n    "AshGhostStack": "planted by a test",')
    )
    result = run_checker(tree)
    assert result.returncode != 0
    assert "AshGhostStack" in result.stdout
    assert "is not committed" in result.stdout


def test_a_stack_in_both_tables_is_rejected(tree: Path) -> None:
    path = tree / "deploy/tests" / CHECKER_REL.name
    text = path.read_text()
    anchor = "STACKS_WITHOUT_TERRAFORM: dict[str, str] = {"
    path.write_text(
        text.replace(anchor, anchor + '\n    "AshFargate": "planted by a test",')
    )
    result = run_checker(tree)
    assert result.returncode != 0
    assert "both PAIRS and" in result.stdout


def test_an_empty_template_directory_is_rejected(tree: Path) -> None:
    """Zero templates would make every check below vacuous."""
    for path in (tree / "deploy/cdk/templates").glob("*.template.json"):
        path.unlink()
    result = run_checker(tree)
    assert result.returncode != 0
    assert "Nothing was compared" in result.stdout


# ---------------------------------------------------------------------------
# Stale-baseline diagnosis. An entry can stop matching three ways and they call
# for opposite actions; the message used to say "fixed, delete it" for all of
# them, which on a deletion instructed the one repair that destroys the record.
# ---------------------------------------------------------------------------
def test_a_kind_leaving_both_sides_is_not_reported_as_fixed(tree: Path) -> None:
    """The regression case. Must NOT tell the maintainer to delete the entry."""
    path = template(tree, "AshFargate")
    before = load_checker(tree).load_cfn("AshFargate")

    doc = json.loads(path.read_text())
    dropped = [
        lid
        for lid, body in doc["Resources"].items()
        if body.get("Type") in ("AWS::S3::Bucket", "AWS::S3::BucketPolicy")
    ]
    for lid in dropped:
        del doc["Resources"][lid]
    path.write_text(json.dumps(doc, indent=1))
    after = load_checker(tree).load_cfn("AshFargate")

    # The mutation was real: the parsed representation lost the buckets.
    assert before.get("AWS::S3::Bucket") == 2
    assert "AWS::S3::Bucket" not in after
    assert "AWS::S3::BucketPolicy" not in after
    assert len(dropped) == 4

    result = run_checker(tree)
    assert result.returncode != 0
    assert "NEITHER representation declares it any more" in result.stdout
    assert "is not a fix" in result.stdout
    assert "Do NOT delete the entry" in result.stdout
    # The old, harmful instruction must be gone for this case.
    assert "was fixed -- delete this baseline entry" not in result.stdout


def test_a_genuinely_fixed_divergence_says_delete_the_entry(tree: Path) -> None:
    """The converged case must still say delete -- otherwise the baseline rots.

    This is the counterpart to the test above: without it, the fix could have
    been "never say delete", which would leave stale entries accumulating.
    """
    path = tf_main(tree, "ash-image-pipeline")
    before = load_checker(tree).load_tf("ash-image-pipeline")
    path.write_text(
        path.read_text()
        + '\nresource "aws_kms_key" "planted" {\n  description = "x"\n}\n'
    )
    after = load_checker(tree).load_tf("ash-image-pipeline")

    assert "aws_kms_key" not in before
    assert after.get("aws_kms_key") == 1

    result = run_checker(tree)
    assert result.returncode != 0
    assert "BOTH representations now declare it" in result.stdout
    assert "delete this baseline entry" in result.stdout


def test_a_reversed_divergence_is_reported_as_reversed(tree: Path) -> None:
    """Present on the other side only: not closed, reversed."""
    tpl = template(tree, "AshCodeCommitGate")
    tf = tf_main(tree, "codecommit-gate")
    cfn_before = load_checker(tree).load_cfn("AshCodeCommitGate")
    tf_before = load_checker(tree).load_tf("codecommit-gate")

    # BASELINE carries ("AshCodeCommitGate", "cfn-only", "kms-key"). Take the
    # key off the CFN side and put one on the Terraform side. (This used the
    # "secret" entry until the gate stack stopped creating the MCP auth secret.)
    doc = json.loads(tpl.read_text())
    removed = [
        lid
        for lid, body in doc["Resources"].items()
        if body.get("Type") == "AWS::KMS::Key"
    ]
    for lid in removed:
        del doc["Resources"][lid]
    tpl.write_text(json.dumps(doc, indent=1))
    tf.write_text(tf.read_text() + '\nresource "aws_kms_key" "planted" {\n}\n')

    cfn_after = load_checker(tree).load_cfn("AshCodeCommitGate")
    tf_after = load_checker(tree).load_tf("codecommit-gate")

    # Both halves of the mutation landed in the parse, in opposite directions.
    assert cfn_before.get("AWS::KMS::Key") == 1
    assert "AWS::KMS::Key" not in cfn_after
    assert "aws_kms_key" not in tf_before
    assert tf_after.get("aws_kms_key") == 1

    result = run_checker(tree)
    assert result.returncode != 0
    assert "REVERSED" in result.stdout
    assert "was fixed -- delete this baseline entry" not in result.stdout


# ---------------------------------------------------------------------------
# Integrity of the mapping tables themselves. None of these is reachable from
# the census, so without these tests a corrupted table still exits 0.
# ---------------------------------------------------------------------------
def test_a_baseline_entry_for_an_unpaired_stack_is_rejected(tree: Path) -> None:
    path = tree / "deploy/tests" / CHECKER_REL.name
    text = path.read_text()
    anchor = "BASELINE: dict[tuple[str, str, str], str] = {"
    assert anchor in text
    path.write_text(
        text.replace(
            anchor,
            anchor + '\n    ("AshNotAPair", "cfn-only", "kms-key"): "planted",',
        )
    )
    result = run_checker(tree)
    assert result.returncode != 0
    assert "which is not in PAIRS" in result.stdout


def test_a_baseline_entry_for_an_unknown_kind_is_rejected(tree: Path) -> None:
    """A typo'd kind would otherwise be reported stale on every run forever."""
    path = tree / "deploy/tests" / CHECKER_REL.name
    text = path.read_text()
    anchor = "BASELINE: dict[tuple[str, str, str], str] = {"
    path.write_text(
        text.replace(
            anchor,
            anchor + '\n    ("AshFargate", "cfn-only", "kms-keyy"): "planted",',
        )
    )
    result = run_checker(tree)
    assert result.returncode != 0
    assert "not in KINDS" in result.stdout


def test_a_type_mapped_to_two_kinds_is_rejected(tree: Path) -> None:
    path = tree / "deploy/tests" / CHECKER_REL.name
    text = path.read_text()
    # Give an existing CFN type a second owner.
    original = '"codepipeline": {\n        "cfn": ("AWS::CodePipeline::Pipeline",),'
    assert original in text, "the fixture no longer matches KINDS"
    path.write_text(
        text.replace(
            original,
            '"codepipeline": {\n        "cfn": '
            '("AWS::CodePipeline::Pipeline", "AWS::IAM::Role"),',
        )
    )
    result = run_checker(tree)
    assert result.returncode != 0
    assert "mapped to both" in result.stdout


def test_a_type_both_mapped_and_excluded_is_rejected(tree: Path) -> None:
    path = tree / "deploy/tests" / CHECKER_REL.name
    text = path.read_text()
    original = '"log-group": {\n        "cfn": ("AWS::Logs::LogGroup",),'
    assert original in text, "the fixture no longer matches KINDS"
    path.write_text(
        text.replace(
            original,
            '"log-group": {\n        "cfn": '
            '("AWS::Logs::LogGroup", "Custom::AshImageBootstrap"),',
        )
    )
    result = run_checker(tree)
    assert result.returncode != 0
    assert "_EXCLUDED" in result.stdout


def test_an_empty_kind_is_rejected(tree: Path) -> None:
    path = tree / "deploy/tests" / CHECKER_REL.name
    text = path.read_text()
    anchor = "KINDS: dict[str, dict[str, tuple[str, ...]]] = {"
    assert anchor in text
    path.write_text(
        text.replace(
            anchor,
            anchor + '\n    "planted-empty": {"cfn": (), "tf": ()},',
        )
    )
    result = run_checker(tree)
    assert result.returncode != 0
    assert "names no type on either side" in result.stdout


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------
def test_an_unparseable_template_is_rejected(tree: Path) -> None:
    template(tree, "AshFargate").write_text("{not json")
    result = run_checker(tree)
    assert result.returncode != 0
    assert "not parseable JSON" in result.stdout


def test_a_template_with_no_resources_is_rejected(tree: Path) -> None:
    template(tree, "AshFargate").write_text(json.dumps({"Resources": {}}))
    result = run_checker(tree)
    assert result.returncode != 0
    assert "declares no Resources" in result.stdout


def test_a_resource_with_no_type_is_rejected(tree: Path) -> None:
    path = template(tree, "AshFargate")
    doc = json.loads(path.read_text())
    doc["Resources"]["Typeless"] = {"Properties": {}}
    path.write_text(json.dumps(doc, indent=1))

    result = run_checker(tree)
    assert result.returncode != 0
    assert "has no Type" in result.stdout


def test_a_missing_terraform_module_is_rejected(tree: Path) -> None:
    shutil.rmtree(tree / "deploy/terraform/modules/agentcore")
    result = run_checker(tree)
    assert result.returncode != 0
    assert "could not be compared" in result.stdout


def test_a_terraform_module_with_no_resources_is_rejected(tree: Path) -> None:
    """A module whose resources vanish must fail, not compare as empty."""
    module = tree / "deploy/terraform/modules/agentcore"
    for path in module.glob("*.tf"):
        path.write_text("# emptied by a test\n")
    result = run_checker(tree)
    assert result.returncode != 0
    assert "declares no `resource` block" in result.stdout


def test_a_missing_template_is_rejected(tree: Path) -> None:
    template(tree, "AshCodeCommitGate").unlink()
    result = run_checker(tree)
    assert result.returncode != 0
    assert "could not be compared" in result.stdout


# ---------------------------------------------------------------------------
# Comments.
#
# The Terraform regexes are anchored at column 0, which already keeps a `#` or
# `//` line comment from matching. A `/* */` block comment does not: the lines
# inside it still start at column 0, so before strip_hcl_comments() a resource
# wrapped in one was counted as present.
# ---------------------------------------------------------------------------
def wrap_tf_resource_in_block_comment(text: str, rtype: str) -> str:
    pattern = re.compile(
        r'^resource\s+"' + re.escape(rtype) + r'"\s+"[^"]+"\s*\{.*?^\}\n',
        re.MULTILINE | re.DOTALL,
    )
    mutated, count = pattern.subn(lambda m: "/*\n" + m.group(0) + "*/\n", text, 1)
    if count != 1:
        raise AssertionError(f'expected to wrap exactly one `resource "{rtype}"`')
    return mutated


def test_a_block_commented_resource_is_not_counted(tree: Path) -> None:
    path = tf_main(tree, "fargate")
    before = load_checker(tree).load_tf("fargate")
    path.write_text(wrap_tf_resource_in_block_comment(path.read_text(), "aws_lb"))
    after = load_checker(tree).load_tf("fargate")

    assert before.get("aws_lb") == 1
    assert "aws_lb" not in after
    # Everything else in the file is still read, so the comment ended where it
    # should and did not swallow the rest of the module.
    assert {k: v for k, v in before.items() if k != "aws_lb"} == after

    result = run_checker(tree)
    assert result.returncode != 0
    assert "load-balancer" in result.stdout
    assert "diverges" in result.stdout


def test_a_block_commented_module_is_not_composed(tree: Path) -> None:
    """check_composition() reads examples through the same stripping."""
    example = tree / "deploy/terraform/modules/agentcore/examples/basic/main.tf"
    example.write_text(
        example.read_text()
        + '\n/*\nmodule "retired" {\n  source = "../../../fargate"\n}\n*/\n'
    )
    result = run_checker(tree)
    assert result.returncode == 0, result.stdout
    assert "No unrecorded divergence" in result.stdout


def test_line_comments_are_not_counted(tree: Path) -> None:
    path = tf_main(tree, "ash-image-pipeline")
    before = load_checker(tree).load_tf("ash-image-pipeline")
    path.write_text(
        path.read_text()
        + '\n# resource "aws_sns_topic" "a" {}\n// resource "aws_sqs_queue" "b" {}\n'
        + 'resource "aws_ecr_repository" "c" {} # resource "aws_sns_topic" "d" {}\n'
    )
    after = load_checker(tree).load_tf("ash-image-pipeline")
    assert "aws_sns_topic" not in after and "aws_sqs_queue" not in after
    assert after["aws_ecr_repository"] == before["aws_ecr_repository"] + 1


def test_a_line_commented_module_source_is_not_read(tree: Path) -> None:
    """A `#` or `//` line ahead of the real `source` must not be taken for it.

    TF_MODULE_SOURCE is anchored at the `module` line, not at `source`, so it
    takes the first `source = "..."` inside the block, indented or not. Only
    the line-comment branch of strip_hcl_comments() keeps a commented-out
    source from being that first match.
    """
    checker = load_checker(tree)
    for marker in ("#", "//"):
        text = f'module "a" {{\n  {marker} source = "../old"\n  source = "../new"\n}}\n'
        assert checker.TF_MODULE_SOURCE.findall(checker.strip_hcl_comments(text)) == [
            "../new"
        ], marker

    # The same through check_composition(): a commented-out sibling module
    # ahead of the real source would read as composing fargate.
    example = tree / "deploy/terraform/modules/agentcore/examples/basic/main.tf"
    text = example.read_text()
    real = '  source = "../../../ash-image-pipeline"\n'
    assert text.count(real) == 1
    example.write_text(
        text.replace(
            real,
            '  # source = "../../../fargate"\n'
            '  // source = "../../../fargate"\n' + real,
        )
    )
    result = run_checker(tree)
    assert result.returncode == 0, result.stdout
    assert "No unrecorded divergence" in result.stdout


def test_escapes_inside_strings_do_not_end_or_open_them(tree: Path) -> None:
    """`\\"` does not close a string and `$${` does not open a template.

    Each input puts a comment marker where a stripper that got the escape
    wrong would be outside the string, so the resource after it is lost.
    """
    checker = load_checker(tree)
    for text in (
        'x = "a\\"/*"\nresource "aws_sns_topic" "t" {}\n',
        'x = "$${"\ny = "/*"\nresource "aws_sns_topic" "t" {}\n',
        'x = "%%{"\ny = "/*"\nresource "aws_sns_topic" "t" {}\n',
    ):
        stripped = checker.strip_hcl_comments(text)
        assert stripped == text, text
        assert checker.TF_RESOURCE.findall(stripped) == [("aws_sns_topic", "t")]


def test_comment_markers_inside_strings_and_heredocs_are_kept(tree: Path) -> None:
    """The tree has ARNs ending in `/*`; a naive stripper would eat resources."""
    checker = load_checker(tree)
    text = (
        'resource "aws_iam_policy" "p" {\n'
        '  policy = "arn:aws:s3:::bucket/*"\n'
        '  name   = "${var.prefix}/* and \\"quoted\\" ${lookup(var.m, "k/*")} //"\n'
        '  lit    = "$${not_a_template} /*"\n'
        "  doc    = <<-EOT\n"
        "    # not a comment, /* not a block\n"
        "    EOT\n"
        "}\n"
        'resource "aws_sns_topic" "t" {}\n'
        "/* a real\n"
        'resource "aws_sqs_queue" "q" {}\n'
        "comment */\n"
        'resource "aws_kms_key" "k" {}\n'
    )
    stripped = checker.strip_hcl_comments(text)
    assert stripped.count("\n") == text.count("\n")
    assert [t for t, _ in checker.TF_RESOURCE.findall(stripped)] == [
        "aws_iam_policy",
        "aws_sns_topic",
        "aws_kms_key",
    ]
    assert '"arn:aws:s3:::bucket/*"' in stripped
    assert "# not a comment, /* not a block" in stripped
    assert 'and \\"quoted\\"' in stripped


def test_the_real_tree_parses_the_same_with_comments_stripped(tree: Path) -> None:
    """No committed .tf file loses a resource or module block to the stripper."""
    checker = load_checker(tree)
    files = sorted((tree / "deploy/terraform/modules").rglob("*.tf"))
    assert files
    for path in files:
        raw = path.read_text()
        stripped = checker.strip_hcl_comments(raw)
        assert checker.TF_RESOURCE.findall(raw) == checker.TF_RESOURCE.findall(
            stripped
        ), path
        assert checker.TF_MODULE_SOURCE.findall(
            raw
        ) == checker.TF_MODULE_SOURCE.findall(stripped), path
