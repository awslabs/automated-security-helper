# cfn-lint scanner (opt-in)

[cfn-lint](https://github.com/aws-cloudformation/cfn-lint) validates AWS CloudFormation templates against the CloudFormation resource schemas and its own rule set: misspelled or invalid properties, values a service rejects, end-of-life Lambda runtimes, unused parameters and similar problems. It checks that a template is correct, not that it is secure, which is why ASH treats it as an opt-in companion to cfn-nag, cfn-guard and checkov rather than a default scanner.

## Enabling it

cfn-lint is off until you turn it on. A scanner that is not enabled leaves no trace in a scan: it is not run, and it does not appear in the results, summaries or reports.

Enable it in your ASH config:

```yaml
scanners:
  cfn-lint:
    enabled: true
```

or name it for one run, which runs it even if the config says `enabled: false`:

```bash
ash scan --scanners cfn-lint
ash scan --config-overrides 'scanners.cfn-lint.enabled=true'
```

`--exclude-scanners cfn-lint` still wins over both. Once enabled, cfn-lint behaves like every other scanner: if the tool is missing it is reported as MISSING and the scan exits 1 (pass `--no-fail-on-incomplete-scanners` to accept a partial scan).

## Installation

cfn-lint is a Python package (MIT-0). ASH installs it with `uv tool install 'cfn-lint[sarif]>=1.43.3,<2.0.0'`, either on first use or ahead of time:

```bash
ash dependencies install --tool cfn-lint
```

The `sarif` extra is required; it provides the SARIF output format ASH reads. An existing cfn-lint on `PATH` is used when it satisfies that requirement. The ASH container image ships cfn-lint, and the Nix flake supplies nixpkgs' cfn-lint with the `sarif` extra.

## Which files it scans

The same files cfn-nag scans: every `.json`, `.yaml` and `.yml` file in the scan set (after ASH's ignore paths and `.gitignore`) that parses as YAML or JSON and has a top-level `Resources` mapping. A file with a `Resources` mapping that ASH cannot model as CloudFormation is reported as a target the scanner could not evaluate, so it counts toward partial coverage instead of disappearing.

## Configuration

```yaml
scanners:
  cfn-lint:
    enabled: true
    options:
      # A .cfnlintrc to use, relative to the source directory. When unset, ASH
      # gives cfn-lint an empty configuration (see "Configuration files" below).
      config_file: .cfnlintrc
      # Regions to validate against. Defaults to cfn-lint's own default (us-east-1).
      regions: [us-east-1, eu-west-1]
      # Rule ids or prefixes to skip everywhere, or to enable (e.g. "I" for
      # informational rules, which cfn-lint does not run by default).
      ignore_checks: [W3005]
      include_checks: [I]
      # Version constraint for the installed tool.
      tool_version: ">=1.43.3,<2.0.0"
      # Seconds before cfn-lint is killed.
      scan_timeout: 1800
```

Region names, rule ids and prefixes are validated when the config is loaded, so a value cannot be passed through to cfn-lint as an option of its own.

### Configuration files

Left to itself, cfn-lint reads a `.cfnlintrc` from the directory it runs in (the scanned repository) and from your home directory. ASH does not let it: unless `config_file` names a file, ASH passes cfn-lint an empty configuration of its own, which stops both lookups. A `.cfnlintrc` is not passive settings. Its `append_rules` key loads Python files as rules, which runs them during the scan, and `ignore_checks: [E, W]` turns every finding off without anything showing up in ASH's suppression reporting. In a repository whose changes you scan before trusting them, such as a pull request in CI, that is code execution and a silent bypass.

Naming a file in `config_file` uses it, with the same trust you give the ASH config that names it, `append_rules` included.

## Severity mapping

cfn-lint classifies every rule by the first letter of its id. ASH maps that letter to an ASH severity and sets the SARIF level to match, so every report agrees:

| cfn-lint rule | Meaning                                                       | ASH severity | SARIF level |
|---------------|---------------------------------------------------------------|--------------|-------------|
| `E....`       | The template is invalid or will fail to deploy                | MEDIUM       | `warning`   |
| `W....`       | Best-practice or hygiene problem                               | LOW          | `note`      |
| `I....`       | Informational (only with `include_checks: [I]`)                | INFO         | `none`      |

These sit below the severities of security scanners on purpose. At ASH's default threshold (MEDIUM) an invalid template fails the scan and a warning does not. Raise or lower that per scanner with `scanners.cfn-lint.options.severity_threshold`. cfn-lint's own class is never lost: it is the first character of the rule id.

`E0003` is not reported as a finding. cfn-lint uses it for its own configuration errors, including a template path it could not open, so ASH counts the affected templates as not evaluated.

## Suppressions

ASH suppressions apply to cfn-lint findings by `rule_id`, `path`, and `line_start`/`line_end`:

```yaml
global_settings:
  suppressions:
    - rule_id: E2533
      path: templates/legacy.yaml
      line_start: 14
      line_end: 14
      reason: The function is pinned to this runtime until it is retired.
```

Package-scoped suppressions do not apply (cfn-lint reports on templates, not packages), and neither do symbol-scoped ones, which target functions and classes in source code. cfn-lint's own template-level controls also work, for example `Metadata: cfn-lint: config: ignore_checks: [W2001]` on a resource. ASH does not see findings that cfn-lint suppressed itself, so these do not appear in ASH's suppressed counts or its unused-suppressions report; treat them like inline `nosec` comments when reviewing changes.

## Offline use

cfn-lint needs no network to scan. Its resource schemas ship inside the package, and it only downloads updates when asked to (`--update-specs` and similar), which ASH never does. A scan inside a network namespace with no interfaces produced the same results as one with network access. Installing cfn-lint needs network once; in offline mode (`ASH_OFFLINE=true`) a cfn-lint that is not already installed is reported as MISSING with the reason.

## How ASH runs it

```text
cfn-lint --format sarif --output-file=<results> [options] -- <template> ...
```

from the source directory, with template paths relative to it, so the SARIF locations are repository-relative. Template paths are escaped before they are passed, because cfn-lint expands each filename argument as a glob pattern: a template named `a[1].yaml` would otherwise not be linted at all. Long template lists are split across several invocations to stay within command-line length limits.

cfn-lint's exit status is a bitmask of the levels it reported (2 error, 4 warning, 8 informational); any combination of those is a completed run. Other exit statuses, a timeout, missing output, or an `E0003` result mark every template in that invocation as not evaluated, so one such template costs the findings of the others in its batch. The scan then reports partial coverage and exits 1 by default, so nothing is lost silently.

## License

cfn-lint is MIT-0 (MIT No Attribution). It is installed as a separate tool and is not bundled into ASH's Python package.
