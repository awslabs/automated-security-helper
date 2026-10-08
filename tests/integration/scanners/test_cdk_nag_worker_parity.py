# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The cdk-nag worker child answers exactly what the in-process wrapper answers.

``utils/cdk_nag_worker.py`` moved cdk-nag's evaluation out of the ASH process so the
scanner sandbox can wrap it. The unit tests pin the protocol with a fake child; this
runs the real one against real cdk-nag, beside the in-process wrapper, on templates
covering every outcome the scanner distinguishes:

- findings, including a resource the template's own cdk_nag metadata suppresses;
- a CDK-synthesized template;
- a template that has a Resources mapping but cannot be modeled, which is a failure;
- a JSON document that is not CloudFormation, which is a skip;
- a YAML file that does not parse, which raises.

For each template it compares the response's failure, its packs in order, and every
finding three ways (``exclude_unset``, plain, ``by_alias``) together with the nested
``model_fields_set``. The comparison is that strict because the scanner writes its
SARIF with ``exclude_unset=True``, so a field that came back set when it had been unset
would change the report even when its value is the default. Exceptions are compared by
class name, text, and whether they are a ``YAMLError``.

Runs only with the [cdk] extra, under --run-integration, the same as
test_cdk_nag_real_pack.py, and fails rather than skips when ASH_REQUIRE_CDK_EXTRA is set.
"""

import os
import shutil
from pathlib import Path

import pytest

PACKS = ["AwsSolutionsChecks", "HIPAASecurityChecks"]
TEST_DATA = Path(__file__).resolve().parents[2] / "test_data" / "scanners"


def _require_cdk_nag():
    try:
        import cdk_nag  # noqa: F401
    except Exception as exc:  # pragma: no cover - environment-dependent
        if os.environ.get("ASH_REQUIRE_CDK_EXTRA", "").strip() in (
            "1",
            "YES",
            "TRUE",
            "true",
        ):
            pytest.fail(
                "ASH_REQUIRE_CDK_EXTRA is set but the [cdk] extra is not importable "
                f"({type(exc).__name__}: {exc})."
            )
        pytest.skip(f"[cdk] extra not installed ({type(exc).__name__})")


def _fields_set(model):
    from pydantic import BaseModel, RootModel

    if isinstance(model, RootModel):
        return ("root", _fields_set(model.root))
    if isinstance(model, BaseModel):
        return {
            name: _fields_set(getattr(model, name))
            for name in sorted(model.model_fields_set)
        }
    if isinstance(model, list):
        return [_fields_set(item) for item in model]
    return None


def _outcome(fn, template: Path, outdir: Path):
    from yaml import YAMLError

    try:
        response = fn(
            template_path=template,
            nag_packs=PACKS,
            outdir=outdir,
            include_compliant_checks=False,
            honor_template_suppressions=True,
        )
    except Exception as exc:
        return ("raised", type(exc).__name__, str(exc), isinstance(exc, YAMLError))
    if response is None:
        return ("none",)
    results = {
        pack: [
            (
                f.model_dump_json(exclude_unset=True),
                f.model_dump_json(),
                f.model_dump_json(by_alias=True),
                _fields_set(f),
            )
            for f in findings
        ]
        for pack, findings in (response.results or {}).items()
    }
    return ("response", response.failure, list(results), results)


@pytest.mark.integration
def test_the_worker_child_answers_what_the_in_process_wrapper_answers(
    tmp_path, monkeypatch
):
    _require_cdk_nag()
    from automated_security_helper.utils import cdk_nag_worker, cdk_nag_wrapper

    source = tmp_path / "src"
    source.mkdir()
    shutil.copy(TEST_DATA / "cdk" / "insecure-s3-template.yaml", source / "s3.yaml")
    shutil.copy(
        TEST_DATA / "cfn_nag" / "opensearch_open_access_policy.yaml",
        source / "opensearch.yaml",
    )
    shutil.copy(
        TEST_DATA / "cdk" / "test.yaml_cdk_nag_results" / "test-yaml.template.json",
        source / "synth.template.json",
    )
    (source / "suppressed.yaml").write_text(
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Metadata:\n"
        "      cdk_nag:\n"
        "        rules_to_suppress:\n"
        "          - id: AwsSolutions-S1\n"
        "            reason: Access logs are shipped by the org trail.\n",
        encoding="utf-8",
    )
    (source / "unmodelable.yaml").write_text(
        "Resources:\n  Weird: 42\n", encoding="utf-8"
    )
    (source / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    (source / "broken.yaml").write_text(
        "Resources: [unclosed\n  a: : b\n", encoding="utf-8"
    )
    templates = sorted(source.iterdir())
    monkeypatch.chdir(tmp_path)

    in_process = {
        t.name: _outcome(
            cdk_nag_wrapper.run_cdk_nag_against_cfn_template, t, tmp_path / "a"
        )
        for t in templates
    }
    with cdk_nag_worker.cdk_nag_worker_batch(
        [t.as_posix() for t in templates], tmp_path / "b"
    ):
        worker = {
            t.name: _outcome(
                cdk_nag_worker.run_cdk_nag_against_cfn_template, t, tmp_path / "b"
            )
            for t in templates
        }

    assert worker == in_process
    # Proves the fixture reaches every outcome; parity over five skips would be vacuous.
    kinds = {name: outcome[0] for name, outcome in in_process.items()}
    assert kinds["package.json"] == "none"
    assert kinds["broken.yaml"] == "raised" and in_process["broken.yaml"][3] is True
    assert in_process["unmodelable.yaml"][1] is not None
    assert any(findings for findings in in_process["s3.yaml"][3].values())
    assert not (tmp_path / "b" / ".cdk-nag-worker").exists()
