# Conftest Plugin

[Conftest](https://www.conftest.dev/) (Apache-2.0) tests configuration files against policies written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/), the Open Policy Agent policy language. ASH runs `conftest test` over the configuration files in the scan target and reports each policy failure and warning as a finding.

Conftest ships no rules, by design. The scanner is useful once you bring your own policies; without them it does nothing and reports SKIPPED.

## Enabling it

Conftest is an alpha plugin that ships with ASH. Its plugin module is loaded only when you list it, so an `ash scan` that does not list it is unchanged: no row in the results, the summary, the reports or the SARIF.

```yaml
# .ash/.ash.yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_conftest_plugins
```

<!-- doctest: illustrative reason="runs a full scan, which needs every scanner installed" -->
```bash
# For one run
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.ash_conftest_plugins
```

With the module listed, `conftest` runs by default, like every other scanner. `scanners.conftest.enabled: false` turns it off again, and `--scanners` and `--exclude-scanners` select it as they select any scanner. `--scanners conftest` without the module listed is refused, with a message naming the module to add. If the tool is not installed and the policy directory has Rego, the scanner is reported `MISSING` and the scan exits 1 (the incomplete-scan gate).

## The policy gate

Like the opt-in `snyk-code` scanner, which waits for its credential, Conftest waits for something you provide: Rego policies. The policy directory is `scanners.conftest.options.policy_dir`, or `policy/` (Conftest's own convention) under the source directory when unset.

- No `.rego` file in the policy directory: ASH does not start Conftest. It logs one INFO line naming the directory, and the scanner is reported SKIPPED with that reason, not PASSED. A missing Conftest binary in that state is also SKIPPED, since the tool would have had nothing to do.
- At least one `.rego` file: Conftest runs.
- A tree with no file Conftest can parse (for example the converted tree of a notebook project): Conftest is not started and the scanner is reported SKIPPED for that tree.

Rego is code Conftest evaluates, so the directory it comes from is your choice. A `policy_dir` set by a config file inside the scanned repository (or by an MCP client), or one that leads out of the scanned tree through a symbolic link, is ignored with a warning and `policy/` under the source directory is used. If `policy/` itself is a symbolic link out of the tree, the scanner is reported SKIPPED and says so.

## Installing Conftest

ASH pins Conftest v0.62.0: one release archive per platform, with a SHA256 for each archive and for the executable inside it. The archive digests are the ones the release publishes in its `checksums.txt`; the executable digests were read from those checked archives.

- **Local mode:** `ash dependencies install --tool conftest`, with the module listed in `ash_plugin_modules` (or added with `--config-overrides`, as below), downloads the pinned release archive from GitHub and verifies it against the SHA256 digest pinned in ASH. A download that does not hash to its pin is refused. Linux, macOS and Windows on x86_64 and arm64 are supported.
- **Container mode:** the ASH container image installs the same pinned binary.
- Any `conftest` already on `PATH` is also used.

<!-- doctest: illustrative reason="downloads a release binary" -->
```bash
ash dependencies install --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_conftest_plugins"]' --tool conftest
```

## What is scanned

ASH lists the files under the scan target that Conftest has a parser for (YAML, JSON, TOML, HCL, Terraform, Dockerfile, INI, XML, properties, CUE, Jsonnet, EDN, VCL and HOCON) and hands them to Conftest after `--`. It does not hand over the directory, because Conftest stops on the first file it has no parser for. Symbolic links, `.git`, `node_modules`, `.venv`, `__pycache__`, the policy directory and ASH's own output directory are skipped.

ASH runs `conftest test --output=sarif --no-fail --no-color --policy=<dir> --all-namespaces -- <files>` with the source directory as its working directory, so reported paths are source-relative. `--no-fail` makes Conftest exit 0 when a policy fails, so any other exit code means the run itself failed. Conftest makes no network call unless a policy does, and ASH never passes `--update`.

## Configuration

```yaml
scanners:
  conftest:
    enabled: true
    options:
      # Directory of Rego policies, relative to the source directory or absolute.
      # Unset means "policy".
      policy_dir: null
      # Test the policies of every namespace (Rego package). Conftest tests only
      # `main` by default.
      all_namespaces: true
      # Seconds for the whole Conftest scan (default 1800; null for no limit).
      scan_timeout: 1800
      # Scanner-level severity threshold override.
      severity_threshold: null
```

## Severity

Conftest's SARIF carries a level per result, from the kind of rule that produced it. ASH keeps `deny` and `warn` results as findings and drops the rest (`allow` exceptions, and the "policy satisfied" and "skipped" entries Conftest adds for files with no failure).

| Conftest result | SARIF level | ASH severity |
|---|---|---|
| `deny` | `error` | HIGH |
| `warn` | `warning` | MEDIUM |
| no level | `warning` | MEDIUM |
| any other level | `error` | HIGH |

A failed `deny` is HIGH, not the CRITICAL that ASH's generic `error` level maps to: the rule is your requirement, not a proven exploit. A level ASH does not recognize is rated the more severe way. With ASH's default `severity_threshold` of `MEDIUM`, both kinds of finding fail the scan.

## Limits

- A file Conftest cannot parse (invalid YAML, for example) fails the whole run, so the scan fails instead of skipping that file.
- The file list travels on one command line. A tree with more configuration files than fit (about 100,000 characters of paths, 30,000 on Windows) fails with a message; narrow the scan with ASH ignore paths.
- Policies in the scanned tree are code Conftest evaluates. They run inside the scanner sandbox, which has no network access and passes no credentials.

## Suppressions

ASH suppressions by rule and path work as for any scanner. The rule id is `<namespace>/deny` or `<namespace>/warn`, for example `main/deny`:

```yaml
global_settings:
  suppressions:
    - rule_id: main/deny
      path: deploy/legacy.yaml
      reason: a legacy workload with an accepted exception
```

Conftest reports the file and no line, so a suppression names no line range. Package-scoped and symbol-scoped suppressions do not apply: no Conftest finding names a package or a symbol.

## Offline and air-gapped use

Conftest reads only the files it is given and the policies in the policy directory, so it behaves the same offline. Install it before going offline.

## License

Conftest is Apache-2.0 licensed. The ASH container image redistributes the pinned release binary, so it carries the release archive's `LICENSE` beside it (the `conftest` entry in `THIRD_PARTY_LICENSES`; the file is byte-identical to the repository's `LICENSE` at the pinned commit). Nothing of Conftest is shipped in the ASH Python package itself.
