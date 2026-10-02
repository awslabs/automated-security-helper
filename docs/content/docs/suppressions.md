# Global Suppressions

ASH v3 supports global suppressions, allowing you to suppress specific security findings across your project. This feature helps reduce noise from known issues that have been reviewed and accepted, allowing teams to focus on new and relevant security findings.

## Understanding Suppressions vs. Ignore Paths

ASH provides two mechanisms for excluding findings:

1. **Ignore Paths**: Files matching these patterns are completely excluded from scanning and do not appear in final results. Use this when you want to completely skip scanning certain files or directories (like test data, third-party code, or generated files).
2. **Suppressions**: Findings matching these rules are still scanned but marked as suppressed in the final report, making them visible but not counted toward failure thresholds. Use this for specific known issues that have been reviewed and accepted.

Key differences:

| Feature     | Ignore Paths                 | Suppressions                                    |
|-------------|------------------------------|-------------------------------------------------|
| Scope       | Entire files/directories     | Specific findings                               |
| Visibility  | Files not scanned at all     | Findings still visible but marked as suppressed |
| Granularity | File-level only              | Rule ID, file path, line number, package, symbol |
| Tracking    | No tracking of ignored files | Suppressed findings are tracked and reported    |
| Expiration  | No expiration mechanism      | Can set expiration dates                        |

## Configuring Suppressions

Suppressions are defined in the `.ash.yaml` configuration file under the `global_settings` section:

```yaml
global_settings:
  suppressions:
    - rule_id: 'RULE-123'
      path: 'src/example.py'
      line_start: 10
      line_end: 15
      reason: 'False positive due to test mock'
      expiration: '2025-12-31'
    - rule_id: 'RULE-456'
      path: 'src/*.js'
      reason: 'Known issue, planned for fix in v2.0'
```

### Suppression Properties

Each suppression rule can include the following properties:

| Property     | Required | Description                                    |
|--------------|----------|------------------------------------------------|
| `path`       | Yes      | File path or glob pattern to match             |
| `reason`     | Yes      | Justification for the suppression              |
| `rule_id`    | Yes      | The scanner-specific rule ID to suppress       |
| `line_start` | No       | Starting line number for the suppression       |
| `line_end`   | No       | Ending line number for the suppression         |
| `expiration` | No       | Date when the suppression expires (YYYY-MM-DD) |
| `package_name`    | No  | Only suppress findings about this package (dependency scanners) |
| `package_version` | No  | Only suppress findings about this installed version of the package |
| `package_path`    | No  | Only suppress findings about the package copy installed at this path |
| `symbol`          | No  | Only suppress findings inside the function or class with this qualified name |

### Matching Rules

- **Rule ID**: Must match exactly the rule ID reported by the scanner
- **File Path**: Supports glob patterns (e.g., `src/*.js`, `**/*.py`)
- **Line Range**: If specified, only findings within this line range will be suppressed
- **Package fields**: If specified, only findings about that package copy will be suppressed. See [Suppressing one package copy](#suppressing-one-package-copy).
- **Symbol**: If specified, only findings inside that function, method or class will be suppressed, wherever it sits in the file. See [Suppressing by symbol](#suppressing-by-symbol).

## Suppressing one package copy

Dependency scanners report one finding per advisory per installed copy of a
package, but the location they report is the lockfile. grype puts every finding
at line 1 of it. Two copies of the same package in one lockfile, such as a
top-level `brace-expansion` and another copy bundled inside `aws-cdk-lib`, then
have the same rule ID, path and line, and a suppression written with only
those fields covers both copies.

The package fields narrow a suppression to one copy:

- `package_name`: the package name. Glob, case-insensitive.
- `package_version`: the installed version, not the advisory's vulnerable
  range. Glob, case-insensitive.
- `package_path`: where the copy is installed, relative to the scan root. For an
  npm lockfile this is the lockfile's directory joined with the key of the
  copy's entry in the lockfile's `packages` map, for example
  `deploy/cdk/node_modules/aws-cdk-lib/node_modules/brace-expansion`. Glob, with
  `**` support like `path`. ASH reports it with forward slashes and no drive
  letter on every platform, so one entry works on Windows, Linux and macOS.
  `path` and `package_path` treat `\` as a separator, so a pattern written with
  backslashes compares the same way everywhere.

Every package field you set has to match. A finding that doesn't report a field
you set is not suppressed, so when a scanner can't tell which copy a finding
is about, the finding stays visible and nothing is hidden by mistake. A
suppression that sets none of the package fields matches the same findings it
always did.

```yaml
suppressions:
  # Suppresses the copy bundled inside aws-cdk-lib in any lockfile. A top-level
  # brace-expansion at the same version is still reported.
  - rule_id: 'GHSA-6j4f-fj2g-mc7p*'
    path: '*'
    package_name: 'brace-expansion'
    package_version: '5.0.9'
    package_path: '**/node_modules/aws-cdk-lib/node_modules/brace-expansion'
    reason: 'Bundled by aws-cdk-lib; no fixed release yet'
    expiration: '2026-10-30'
```

Here `path: '*'` is safe because `package_path` does the narrowing. It is
there because npm-audit and grype report different paths for the same finding
(see below), so one entry can cover both.

### What each scanner reports

| Scanner    | `package_name` | `package_version`       | `package_path`                                     |
|------------|----------------|-------------------------|----------------------------------------------------|
| npm-audit  | Yes            | Yes, from the lockfile  | Yes, for every node npm audit lists                |
| trivy-repo | Yes            | Yes                     | npm lockfiles only                                 |
| grype      | Yes            | Yes                     | npm lockfiles only, and only when the name and version occur once in the lockfile |

The rule IDs also differ: grype appends the package name to the advisory
(`GHSA-6j4f-fj2g-mc7p-brace-expansion`), npm-audit uses the bare GHSA ID, and
trivy-repo uses the CVE alias when the advisory has one. A glob such as
`GHSA-6j4f-fj2g-mc7p*` covers the first two. trivy-repo needs its own entry keyed
on the CVE.

Paths differ too. grype and trivy-repo report the lockfile, for example
`deploy/cdk/package-lock.json`. npm-audit reports
`node_modules/<path>/package.json` with each `node_modules/` segment removed
from the middle, and without the lockfile's directory. That shape predates the
package fields and is unchanged so existing suppressions keep matching. Use
`package_path` to tell trees apart.

Known limits:

- When the same name and version is installed at two places in one lockfile,
  grype reports two findings that are identical in its output, so ASH cannot
  say which one is which. Neither gets a `package_path`, and a suppression
  that sets `package_path` matches neither. `package_name` and
  `package_version` alone would match both.
- trivy-repo reports that case as one finding with one location per copy.
  ASH splits it into one finding per copy, each with its own `package_path`,
  when every location can be resolved to a lockfile entry.
- `package_path` is only available for npm lockfiles (`package-lock.json` and
  `npm-shrinkwrap.json`, format v2 and later). Other ecosystems get
  `package_name` and `package_version` only.
- ASH versions without these fields ignore unknown suppression keys, so an
  older ASH reading a package-scoped suppression applies it without the
  package fields, which is broader. Make sure every environment that reads the
  config runs a version that supports them.

## Suppressing by symbol

A suppression with `line_start` and `line_end` covers whatever is on those
lines. Add a line above them and it covers the wrong code. `symbol` names a
definition instead, so the suppression follows the code when it moves within
the file, and across files when `path` is a glob.

```yaml
suppressions:
  - rule_id: 'B602'
    path: 'src/deploy.py'
    symbol: 'Deployer.run_hook'
    reason: 'hook command comes from the signed manifest, never from input'
```

This suppresses B602 findings in `src/deploy.py` only when the finding's lines
are inside the `run_hook` method of class `Deployer`. A B602 finding in another
method of `Deployer`, or at module level, is still reported.

### Installing the extra

Symbol suppressions parse source files with
[tree-sitter](https://tree-sitter.github.io/), which ASH installs as an optional
extra:

```bash
pip install "automated-security-helper[symbols]"
# or
uv tool install "automated-security-helper[symbols]"
```

The ASH container image includes it. Without it, an entry that sets `symbol`
matches nothing: the findings it names stay visible, the scan logs a warning
naming the missing extra, the entry shows up in the unused-suppressions report,
and `ash config lint` warns about it.

### Supported languages

| Language   | Extensions                      | Definitions that have a name |
|------------|---------------------------------|------------------------------|
| Python     | `.py`, `.pyi`                   | `def`, `async def`, `class` |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs`   | function and class declarations, class methods and fields, `const f = () => ...` and other functions or classes assigned to a variable |
| TypeScript | `.ts`, `.mts`, `.cts`, `.tsx`   | as JavaScript, plus abstract classes, interfaces, enums, namespaces, overload signatures and method signatures |
| Java       | `.java`                         | classes, interfaces, enums, records, annotation types, methods and constructors |

A file with any other extension can't be resolved, so a symbol entry never
matches in it.

### How names are written

A qualified name is the chain of definition names from the top of the file down
to the symbol, joined with dots:

- `module_function`: a function at the top of a file.
- `MyClass.my_method`: a method.
- `Outer.Inner.method`: a method of a nested class.
- `outer_function.inner_function`: a function defined inside another one.

Names are exact and case-sensitive. There are no wildcards and no suffix
matching, so `my_method` alone names only a top-level `my_method`, never
`MyClass.my_method`. Only definitions add to the name. A function defined inside
an `if` or `try` block at module level is just `name`. Python's `<locals>`
marker is not part of it.

A `symbol` that isn't a dotted list of identifiers, such as
`MyClass.my_method()` or `MyClass::my_method`, is an error in `ash config lint`,
and a scan refuses to load a config that contains one.

### What counts as inside

- A finding matches when every line it reports, from its start line to its end
  line, is between the symbol's first and last line. A finding that starts
  inside the symbol and ends after it doesn't match.
- The first and last lines count. Decorators and Java annotations are part of
  the symbol, and so is `export` in front of a JavaScript or TypeScript
  declaration, so a finding reported on a decorator line is inside.
- A symbol contains everything nested in it. `MyClass` covers findings in all of
  its methods.
- When several definitions share a name, the name covers all of them. That
  includes a Python property's getter and setter, `typing.overload` stubs,
  Java and TypeScript overloads, and a function defined twice in one file.
- A finding with no line number never matches.
- `symbol` combines with every other field: `rule_id`, `path`, the line range,
  the package fields and `expiration` all still have to match.

### When ASH can't find the span

In each of these cases the entry doesn't match in that file, the finding stays
visible, and the scan logs a warning that names the file and the reason:

- the `symbols` extra is not installed;
- the file's extension has no grammar (see the table above);
- the file can't be read, or resolves to a path outside the scan root;
- tree-sitter reports a syntax error anywhere in the file. ASH doesn't use a
  partial parse, because an error can cut a definition short and give it the
  wrong span.

A symbol that no longer exists in the file matches nothing and is listed in the
unused-suppressions report, the same as an entry for a deleted file.

Line endings don't matter: LF, CRLF and bare CR files give the same spans. A file
that isn't valid UTF-8 still parses when its identifiers are ASCII, as with a
Latin-1 Python file whose non-ASCII text is all in strings and comments. A
UTF-16 file doesn't parse.

ASH parses a file only when a symbol entry has matched a finding in it on every
other field, and parses it once per scan however many findings it has.

Known limits:

- A JavaScript method in an object literal (`const api = { handle() {} }`) has
  no qualified name, because neither `api` nor `handle` is a class or function
  definition. Computed and string-named methods (`[Symbol.iterator]()`,
  `'name'()`) have none either.
- Anonymous definitions, such as `export default class {}`, add no segment;
  their methods are named as if they were at the enclosing level.
- ASH versions without `symbol` ignore unknown suppression keys, so an older
  ASH reading a symbol-scoped entry applies it to the whole file, which is
  broader. Make sure every environment that reads the config runs a version
  that supports it.

## Examples

### Suppress a Specific Rule in a File

```yaml
suppressions:
  - rule_id: 'B605'  # Bandit rule for os.system
    path: 'src/utils.py'
    reason: 'Command is properly sanitized'
```

### Suppress a Rule in Multiple Files

```yaml
suppressions:
  - rule_id: 'CKV_AWS_123'
    path: 'terraform/*.tf'
    reason: 'Approved exception per security review'
```

### Suppress a Rule for Specific Lines

```yaml
suppressions:
  - rule_id: 'detect-secrets'
    path: 'config/settings.py'
    line_start: 45
    line_end: 47
    reason: 'Test credentials used in CI only'
```

### Suppress with Expiration Date

```yaml
suppressions:
  - rule_id: 'RULE-789'
    path: 'src/legacy.py'
    reason: 'Will be fixed in next sprint'
    expiration: '2025-06-30'
```

## Temporarily Disabling Suppressions

To temporarily ignore all suppressions and see all findings, use the `--ignore-suppressions` flag:

```bash
ash --ignore-suppressions
```

This is useful when you want to:

- Verify if previously suppressed issues have been fixed
- Get a complete view of all security findings in your codebase
- Perform a comprehensive security review

When this flag is used, ASH will process all findings as if no suppressions were defined, but will still respect the `ignore_paths` settings.

## Expiring Suppressions

When a suppression has an expiration date:

1. The suppression will only be applied until that date
2. When the date is reached, the suppression will no longer be applied
3. ASH will warn you when suppressions are about to expire within 30 days

This helps ensure that temporary exceptions don't become permanent security gaps.

## Best Practices

1. **Always provide a reason**: Document why the finding is being suppressed
2. **Use expiration dates**: Set an expiration date for temporary suppressions
3. **Be specific**: Use `symbol`, or line numbers, to limit the scope of suppressions. A symbol keeps pointing at the same code when lines move
4. **Regular review**: Periodically review suppressions to ensure they're still valid
5. **Document approvals**: Include reference to security review or approval in the reason

## Identifying Unused Suppressions

ASH automatically tracks which suppressions are actually being applied to findings and generates a report of unused suppressions. This helps you maintain a clean configuration by identifying:

- Suppressions for files that no longer exist
- Suppressions for findings that have been fixed
- Suppressions that are no longer applicable due to code changes

### Unused Suppressions Report

After each scan, ASH generates two reports for unused suppressions:

1. **JSON Report**: `.ash/ash_output/reports/ash.unused-suppressions.json`
2. **Markdown Report**: `.ash/ash_output/reports/ash.unused-suppressions.md` (human-readable)

#### JSON Report Format

```json
{
  "summary": {
    "total_suppressions": 10,
    "used_suppressions": 7,
    "unused_suppressions": 3
  },
  "unused_suppressions": [
    {
      "path": "src/old_file.py",
      "rule_id": "B201",
      "line_start": 42,
      "line_end": 42,
      "reason": "False positive - debug mode only in development",
      "expiration": "2026-12-31"
    }
  ]
}
```

#### Markdown Report Format

The markdown report provides a human-readable summary with:
- Overall statistics (total, used, unused counts)
- Percentage of unused suppressions
- Detailed list of each unused suppression
- Recommendations for cleanup

### Reviewing Unused Suppressions

Check the summary after a scan:

```bash
# View summary statistics
jq '.summary' .ash/ash_output/reports/ash.unused-suppressions.json

# View all unused suppressions
jq '.unused_suppressions' .ash/ash_output/reports/ash.unused-suppressions.json

# Or view the markdown report
cat .ash/ash_output/reports/ash.unused-suppressions.md
```

### Cleaning Up Unused Suppressions

For each unused suppression, determine the appropriate action:

1. **File no longer exists**: Remove the suppression from your configuration
2. **Finding was fixed**: Remove the suppression as it's no longer needed
3. **Path/rule/line/symbol mismatch**: Update the suppression to match the current code structure. An entry whose `symbol` was renamed or removed lands here
4. **Still needed**: Verify the suppression is correctly configured (check path, rule_id, line numbers)

Example cleanup workflow:

```bash
# 1. Run scan
ash --mode local

# 2. Check for unused suppressions
cat .ash/ash_output/reports/ash.unused-suppressions.md

# 3. Edit configuration to remove unused suppressions
vim .ash/.ash.yaml

# 4. Re-run scan to verify
ash --mode local
```

### Configuration Options

The unused suppressions reporter is enabled by default. To customize its behavior, add to your `.ash/.ash.yaml`:

```yaml
reporters:
  unused-suppressions:
    enabled: true  # Set to false to disable
    options:
      output_format: "json"  # "json" or "markdown"
```

### Integration with CI/CD

You can use the unused suppressions report in your CI/CD pipeline:

```bash
# Check if there are unused suppressions
UNUSED_COUNT=$(jq '.summary.unused_suppressions' .ash/ash_output/reports/ash.unused-suppressions.json)

if [ "$UNUSED_COUNT" -gt 0 ]; then
  echo "Warning: $UNUSED_COUNT unused suppressions found"
  echo "Review: .ash/ash_output/reports/ash.unused-suppressions.md"
  # Optionally fail the build
  # exit 1
fi
```

## Suppressions in GitLab Security Dashboard

When using the GitLab SAST reporter, ASH handles suppressed findings in a way that integrates with GitLab's Security Dashboard:

### Default Behavior

By default, suppressed findings are **included** in the GitLab SAST report (`ash.gl-sast-report.json`) with two modifications:

- **Severity is downgraded to `Info`** — suppressed findings won't trigger alerts or block pipelines
- **The suppression reason is added to the `solution` field** — GitLab admins can see why the finding was suppressed

This approach provides an audit trail: security teams can see that a finding was detected and deliberately suppressed, and use GitLab's built-in vulnerability dismissal workflow to close it.

### Dismissing Suppressed Findings in GitLab

Once suppressed findings appear in the GitLab Security Dashboard as Info-level vulnerabilities:

1. Navigate to **Security & Compliance > Vulnerability Report**
2. Filter by severity **Info** to find suppressed findings
3. Select the finding and click **Dismiss**
4. Choose a reason: "Acceptable risk", "False positive", or "Used in tests"
5. Paste the ASH suppression reason from the solution field as the dismissal comment

Once dismissed, GitLab tracks the dismissal across future scans — the finding won't reappear as active even if ASH reports it again.

For automation, GitLab's REST API supports programmatic dismissal:

```bash
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  "https://gitlab.example.com/api/v4/projects/:id/vulnerabilities/:vulnerability_id/dismiss" \
  --data "comment=Suppressed by ASH: <reason>"
```

### Excluding Suppressed Findings

If you prefer suppressed findings to not appear in the GitLab Security Dashboard at all, set `exclude_suppressed: true` in your ASH configuration:

```yaml
reporters:
  gitlab-sast:
    enabled: true
    options:
      exclude_suppressed: true
```

With this option, suppressed findings are omitted entirely from the GitLab SAST report. This results in a cleaner dashboard but removes the audit trail from GitLab.
