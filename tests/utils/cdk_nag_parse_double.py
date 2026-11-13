"""cdk-nag's template wrapper up to the point it synthesizes, for unit tests.

The real wrapper (``utils/cdk_nag_wrapper.run_cdk_nag_against_cfn_template``)
imports cdk-nag, which starts node through jsii, before it parses the template.
Without the cdk extra it fails every template, and with it a unit test starts the
host's node. What these tests are about is the scanner's accounting of what the
parser answers, so this double reads and parses the template exactly as the
wrapper does and answers as the wrapper does for each outcome: None for a document
that is not CloudFormation, a failure for one the model rejects, an evaluation with
no findings otherwise, and the parse error raised as the worker raises it.

The scanner calls the wrapper through the cdk-nag worker (``utils/cdk_nag_worker``),
which runs it in a child and raises a child's exception again in the parent by name
and text only: the class is rebuilt, so ``isinstance`` and attributes such as a
YAML error's line do not cross. This double raises through the same function.
"""

from __future__ import annotations


def parse_like_the_cdk_nag_wrapper(template_path, *, scan_root=None, **_options):
    """Stand-in for ``run_cdk_nag_against_cfn_template``; same keyword arguments."""
    from automated_security_helper.utils.cdk_nag_worker import (
        _exception_kind,
        _raise_as_reported,
    )
    from automated_security_helper.utils.cdk_nag_wrapper import CdkNagWrapperResponse
    from automated_security_helper.utils.cfn_template_model import (
        CloudFormationTemplateModelError,
        get_model_from_template_text,
        read_template_text,
    )
    from automated_security_helper.utils.scanned_tree import TreeInputRefused

    try:
        text = read_template_text(template_path, scan_root)
        model = get_model_from_template_text(text, template_path)
    except CloudFormationTemplateModelError as exc:
        return CdkNagWrapperResponse(
            results={}, failure=f"not modeled ({type(exc.error).__name__})"
        )
    except Exception as exc:
        answer = {
            "type": type(exc).__name__,
            "message": str(exc),
            "kind": _exception_kind(exc),
        }
        if isinstance(exc, TreeInputRefused):
            answer.update(path=str(exc.path), reason=exc.reason)
        _raise_as_reported(answer)
    if model is None:
        return None
    return CdkNagWrapperResponse(results={"AwsSolutions": []}, failure=None)


def use_the_parse_double(monkeypatch) -> None:
    """cdk-nag with its tool present and the double above in the worker's place."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cdk_nag_scanner,
    )

    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    monkeypatch.setattr(
        cdk_nag_scanner,
        "run_cdk_nag_against_cfn_template",
        parse_like_the_cdk_nag_wrapper,
    )
