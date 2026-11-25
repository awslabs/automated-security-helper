## cdk-nag: issues #887 and #809

### #887 — templates without violations were reported as not evaluated

Since aws-cdk-lib 2.258.0 ([aws/aws-cdk#38009](https://github.com/aws/aws-cdk/pull/38009), commit f396892), `buildPluginReports` skips every validation plugin that succeeded with zero violations and nothing suppressed:

```ts
if (rep.success && rep.violations.length === 0 && !suppressed) continue;
```

A compliant template's `validation-report.json` is therefore `{"pluginReports": []}` — byte-identical to the report of a synth where no pack ran at all. The wrapper read that as `contains no plugin reports. No pack evaluated this template.` (or, where another plugin's entry was present, as `requested pack(s) with no entry in the report`), the scanner counted the template as a failed target, and a repository of compliant templates read as a cdk-nag ERROR. `include_compliant_checks: true` could not help, because the report carries violations only.

The report alone can no longer distinguish "evaluated, found nothing" from "never ran", so the wrapper now records the evidence at its own boundary. Each requested pack is registered through a subclass whose `validate()` notes whether CDK called it, whether it raised, and the success flag and violation count of the report it returned. When the validation report has no entry for a requested pack, that record decides:

- returned success with zero violations → the pack evaluated the template; it stands into the results as `{pack: []}`, the compliant evaluation's shape, and the scanner counts the template as evaluated with zero findings;
- anything less fails closed exactly as before — no record (the pack never ran), a `validate()` that raised, a non-success return, a report object whose fields could not be read, and a recorded success whose violations the report file then failed to carry (they would be lost, not absent) all leave the pack missing and the template failed.

A pack that reports failure in the report file, a missing report, an unparsable report, and a requested pack that never ran keep their existing failure handling; the distinction the issue thread asked to survive — an intentionally failing validation plugin with no violations is rejected — is pinned by tests on both the report path and the new record path.

Verified against the locked dependencies (aws-cdk-lib 2.273.0, cdk-nag 3.0.2, constructs 10.8.1, jsii 1.141.0, Python 3.12.15, Node 22): before the change, the new integration test fails with the issue's exact symptom (`... contains no plugin reports. No pack evaluated this template.`); after it, a bare `AWS::CloudFormation::WaitConditionHandle` template evaluates clean (`failure=None`, `results == {"AwsSolutions": []}`), and the non-compliant control template still yields its AwsSolutions findings through the same recording subclass, which proves the subclass is transparent to jsii's callback path.

- `automated_security_helper/utils/cdk_nag_wrapper.py`: the recording subclass in `_build_nag_pack`, the `_record_validate_outcome` helper, and the completion-record admission in `_violations_from_validation_report`.
- `tests/unit/utils/test_cdk_nag_wrapper_behavior.py`: the doubles now let a test opt in to synth driving `validate()`, plus six tests covering the clean-template shape, a clean pack beside a violating pack, and the fail-closed controls.
- `tests/integration/scanners/test_cdk_nag_real_pack.py`: a compliant-template fixture and a real-synthesis regression test against the installed aws-cdk-lib.

The issue's "Related" note (non-template YAML such as a multi-document `pnpm-lock.yaml` counted as a failed target) is already fixed on `main`: the scanner un-counts files that hold no CloudFormation template (`_uncount_a_file_that_holds_no_template`).

Closes #887.

### #809 — cdk-nag deps could not install in uv-synced containers (no pip in the venv)

Already fixed on `main` by #830 (2babd286): `get_installation_commands` routes through `python_package_install_command` (`automated_security_helper/utils/python_installer.py`), which picks the installer that owns the environment — pip where the interpreter can import it, otherwise `uv pip install --no-config --python <interpreter>` with the uv found beside ASH or on PATH, and a refusal naming `ensurepip` and uv when neither exists. The issue reporter re-checked the published repro against `main` and confirmed the install now succeeds in a `uv sync` venv with no pip (`uv pip install --no-config --python /venv/bin/python aws-cdk-lib<3.0.0,>=2.273.0 cdk-nag<4.0.0,>=3.0 constructs<11.0.0,>=10.8` → exit 0, all three import).

No code change was needed in this PR. The behavior is pinned by existing regression tests (`tests/unit/utils/test_python_package_installs.py`: a uv environment without pip installs with uv, a uv-tool environment installs with uv even with pip present, an environment with pip keeps using pip, and no-pip-no-uv is refused with what to do; `tests/unit/utils/test_python_installer_probe_and_messages.py`; `tests/unit/plugin_modules/test_cdk_nag_container_deps.py`), all of which pass on this branch.

Closes #809.
