# Completeness gate default (#579)

Closes #579.

## What the issue asked for

#579 tracked flipping `fail_on_incomplete_scanners` from its original fail-open
default (`False`) to `True`, gated on two prerequisites: cdk-nag evaluating all
of its targets, and the CI scanners that reported `MISSING` for provisioning
reasons getting an explicit decision. Its closing step: set the default to
`True`, update the `Field` description, and update the default-pinning test.

## Current state: every closing condition is met on main

No code change is needed. The flip and both prerequisites landed on main
(v3.8.0 release notes, #640); this section records the verification so the
issue can close with a traceable record.

**The default is `True`.** `automated_security_helper/config/ash_config.py`
(`AshConfig.fail_on_incomplete_scanners`): the field is annotated `] = True`
and its description reads "Defaults to True, so a scanner recorded ERROR or
MISSING does not report the exit code of a clean scan." The committed schema
(`automated_security_helper/schemas/AshConfig.json`,
`$defs/AshConfig/properties/fail_on_incomplete_scanners`) carries
`"default": true`.

**Where the value is read** (the resolution chain, CLI flag > scan's own
config > model default, each copy pinned by a test that compares it against
the model field):

- `automated_security_helper/interactions/run_ash_scan.py::_resolve_fail_on_incomplete_scanners`
  (the exit-code gate; final fallback literal `True`)
- `automated_security_helper/cli/scan.py` `--fail-on-incomplete-scanners /
  --no-fail-on-incomplete-scanners` ("Defaults to unset, which prefers the
  configuration value and then on")
- `automated_security_helper/cli/merge.py::_resolve_require_scanner_completion`
  (the merge verdict's copy)
- `automated_security_helper/interactions/run_ash_container.py` (forwards the
  flag into the in-container scan)
- the MCP server's `_resolve_config_fail_on_incomplete_scanners` (config-only;
  MCP scans take no CLI flags)

**Prerequisite 1 (cdk-nag target loss) is fixed.**
`tests/integration/scanners/test_cdk_nag_real_pack.py` records it: "That
defect is now fixed -- `fail_on_incomplete_scanners` defaults to on and reads
those counters", and pins that only real templates count as targets while
parse failures stay visible in `exitCodeDescription`
(`tests/unit/plugin_modules/ash_builtin/test_cdk_nag_unevaluated_is_not_skipped.py`
holds the control).

**Prerequisite 2 (CI scanners MISSING) is resolved.** The reusable scan
workflow (`.github/workflows/run-ash-security-scan.yml`) installs every
default-enabled scanner's tool (`install-grype`, `install-syft`,
`install-opengrep`, `install-cfn-nag`, `install-actionlint`,
`install-cfn-guard`, `install-gitleaks`, `install-trivy` all default `true`,
documented in the workflow's BEHAVIOR CHANGE note), and
`tests/unit/test_scan_workflow_installs_default_scanners.py` holds every
`install-*` input to that default.

**ASH passes its own completeness gate.** The repository's own required
self-scan check (`ash / SAST, SCA, and IaC Scan`) on the change that produced
main's tip `253fe6cec57fb3a4635cdfa2ae4b32715da516fd` ran all 16 selected
scanners to completion: 14 PASSED, detect-secrets and gitleaks FAILED with
findings, "Missing dependencies: 0", no incomplete scanner anywhere in the
run. The job exited 2 ("Exiting due to 5 actionable findings found in ASH
scan") -- the `fail_on_findings` gate, a separate matter from completeness;
the completeness gate (exit 1) did not fire.
Run: https://github.com/awslabs/automated-security-helper/actions/runs/45544242361/job/138969880217

**The default and the opt-out are pinned**
(`tests/unit/interactions/test_fail_on_incomplete_scanners.py`):

- `TestConfigModelAndValidator::test_config_field_defaults_to_on` asserts the
  model literal (`AshConfig(...).fail_on_incomplete_scanners is True`).
- `TestIncompleteScannersTripTheGate::test_the_default_is_on_and_the_opt_out_is_what_ungates`
  pins both directions in one test: a MISSING + ERROR pair exits 1 on the
  default path, and the same input with `fail_on_incomplete_scanners=False`
  exits 0. This is the updated form of the
  `test_the_default_is_off_and_the_opt_in_is_what_gates` test the issue's
  closing step names.
- `test_the_default_comes_from_the_config_model_not_just_the_fallback` and
  `test_the_model_default_and_the_resolver_fallback_agree` keep the model
  field, the resolver fallback, and the merge copy from drifting apart.
- `TestAScanThatRanNothingIsNotACleanScan::test_the_operator_opt_out_still_wins`
  pins the opt-out against the every-scanner-SKIPPED shape.

## Verification (clean Linux x86_64 host, Python 3.12.15, frozen env)

- `tests/unit/interactions/test_fail_on_incomplete_scanners.py`: 54 passed.
- Mutation control: with the field's default flipped to `False`, 3 of the
  pinning tests fail (`test_config_field_defaults_to_on`: "assert False is
  True"; `test_the_default_comes_from_the_config_model_not_just_the_fallback`:
  "a real AshConfig carries the model default, which is on";
  `test_the_model_default_and_the_resolver_fallback_agree`); restored, all
  pass. The default cannot move without a red test.
- Live behavior at main's bytes, on a host without the scanner binaries
  (`ash scan --only-scanners cfn-lint,grype,syft`): the default gate exits 1
  with "Exiting because the scan was incomplete: 3 selected scanner(s) did
  not evaluate everything they were given" naming each MISSING scanner;
  the same scan with `--no-fail-on-incomplete-scanners` exits 0. The shipped
  default catches the false clean, and the opt-out restores the old exit
  code, exactly as #579's closing step requires.
- `ruff format --check .` (4403 files already formatted) and `ruff check .`
  ("All checks passed!") both clean.
