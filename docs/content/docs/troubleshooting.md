# Troubleshooting

Common issues you may hit while running ASH, with the cause and fix for each. For UV-specific installation problems, see [Troubleshooting UV Tool Installation](troubleshooting-uv-installation.md).

## Semgrep Login Prompt During Scan

**Symptom**

`ash` pauses mid-scan with a prompt like:

```
Enter your Semgrep registry token, or hit ENTER to skip login:
```

The scan hangs or fails in CI because stdin is not interactive.

**Cause**

Semgrep is trying to authenticate to the Semgrep App registry to fetch rulesets. This happens when registry-hosted rules (e.g. `p/ci`, `p/owasp-top-ten`) are in use and no token is configured.

**Fix**

Provide a token via the `SEMGREP_APP_TOKEN` environment variable:

```bash
export SEMGREP_APP_TOKEN=your-token-here
ash --mode local
```

Or run in offline mode with pre-cached rulesets:

```bash
ash --mode container --offline
```

Or disable the Semgrep scanner if you don't need it:

```bash
ash --config-overrides 'scanners.semgrep.enabled=false'
```

## cfn-nag Fails Because Ruby Is Missing

**Symptom**

```
cfn-nag skipped: Ruby gem 'cfn-nag' is not installed
```

Or a `bundle: command not found` error during scan setup.

**Cause**

`cfn-nag` is a Ruby gem. Local mode requires a system Ruby installation and the gem on the PATH. Fresh systems (and minimal CI images) often don't have Ruby.

**Fix**

Install Ruby and the gem:

```bash
# macOS
brew install ruby
gem install cfn-nag

# Debian/Ubuntu
sudo apt install ruby-full
gem install cfn-nag
```

Or switch to container mode, which bundles Ruby and cfn-nag:

```bash
ash --mode container
```

## Grype Cannot Fetch Vulnerability Database

**Symptom**

```
failed to load vulnerability db: failed to download: unable to fetch latest.json
```

**Cause**

Grype downloads a vulnerability database from `toolbox-data.anchore.io` on startup. In corporate networks this often fails behind a proxy or TLS inspection gateway.

**Fix**

Set proxy environment variables before running ASH:

```bash
export HTTPS_PROXY=http://proxy.corp.example:8080
export HTTP_PROXY=http://proxy.corp.example:8080
export NO_PROXY=localhost,127.0.0.1
ash --mode local
```

For air-gapped environments, pre-populate the Grype database cache and run in offline mode:

```bash
# On a connected machine
grype db update
# Copy ~/.cache/grype to the air-gapped host

ash --mode container --offline --no-build
```

`--no-build` runs the image already on the host. Without it container mode rebuilds
the image first, and the first build on a new UTC day upgrades the OS packages and
downloads the databases again, which needs network access.

In local mode, ASH reads grype's database from `GRYPE_DB_CACHE_DIR` when it is set,
else from `$XDG_CACHE_HOME/grype/db` when `XDG_CACHE_HOME` is an absolute path, else
`~/.cache/grype/db` (`~/Library/Caches/grype/db` on macOS). The container image sets
`GRYPE_DB_CACHE_DIR` to `/deps/.grype`. A `db.cache-dir` in a grype config is not
used, and when the grype config ASH passes to grype sets it, ASH logs a warning
naming the file:

```
The grype config at .grype.yaml sets db.cache-dir, which ASH does not use: grype reads its database from the directory ASH refreshes and checks the age of. Set GRYPE_DB_CACHE_DIR to move it.
```

To keep the database somewhere else, set `GRYPE_DB_CACHE_DIR` instead.

A grype run with no database at all is recorded `ERROR`, not `PASSED` with no
findings: grype exits 1 when it cannot load its database, and ASH also asks grype for
the database's status after the scan. When grype reports `database does not exist`,
the scanner is `ERROR` whatever `content_db_staleness` or `--allow-stale-content-db`
says, and its error says how to create the database.

## A Scanner Is ERROR With an Exit Code It Does Not Accept

**Symptom**

A scanner's row is `ERROR`, and its error names the tool's exit code:

```
Failed to execute semgrep scanner on source: SemgrepScanner scan failed: its tool exited with code 7, which this scanner does not accept as a completed run, so its results file is not graded (exit code 7: not an accepted exit code; success_exit_codes=[0, 1]). No stderr captured; checked .ash/ash_output/scanners/semgrep/source/SemgrepScanner.stderr.log, which the tool did not write. .ash/ash_output/scanners/semgrep/source/results_sarif.sarif reports: Invalid YAML file ...
```

**Cause**

The tool reported that it failed. Each scanner accepts the exit codes its tool uses
for a run that completed, with or without findings, and nothing else. A failed tool
can still leave a results file (semgrep exits 7 and writes SARIF holding only error
notifications when it cannot read a rule configuration; grype exits 1 and writes a
zero-byte report when it cannot load its database), so ASH does not read the file of
a run with any other code: an empty or error-only file would otherwise be graded
`PASSED` with no findings. A tool ended by a signal shows as `128 + N` (129 for
SIGHUP, 130 for SIGINT, 137 for SIGKILL). 127 is a tool the OS could not start, or
a run ASH itself failed to carry out (the scanner's errors name ASH's error).

| Scanner | Accepted exit codes | What the tool uses other codes for |
|---|---|---|
| bandit | 0, 1 (issues found) | 2: any error (`bandit/cli/main.py`) |
| checkov | 0, 1 (failed checks) | 2: the run crashed (`checkov/main.py`) |
| grype | 0, 2 (a match at or above `--fail-on`) | 1: any error, such as a database it cannot load (`cmd/grype/cli/cli.go`) |
| semgrep | 0, 1 (findings) | 2: fatal; 3 and up: specific failures, 7 for a rule configuration it cannot read (`semgrep/error.py`) |
| opengrep | 0, 1 | the same values as semgrep (`src/osemgrep/core/Exit_code.ml`) |
| trivy, trivy-repo | 0 | 1: any error (`cmd/trivy/main.go`) |
| syft | 0 | 1: any error (`cmd/syft/main.go`) |
| ferret-scan | 0, 3 (coverage cut short under `fail_on_incomplete`: the findings are reported and the row is `ERROR`, as its target counts as failed) | 1: any error |
| snyk-code | 0, 1 (issues found) | 2: an error; 3: no supported project (`src/cli/exit-codes.ts`) |

trivy exits 0 for a run with findings unless its `exit-code` setting names another
code. ASH passes `--exit-code=0` to trivy and trivy-repo, which outranks an
`exit-code` in the operator's trivy config and `TRIVY_EXIT_CODE` (measured with trivy
0.75.0), and neither scanner reads a `trivy.yaml` from the scanned directory, so a
run with findings exits 0 and a nonzero exit only ever means trivy failed. ASH
decides the scan's exit code from the findings itself.

cfn-nag, npm audit, detect-secrets and cdk-nag are not in this table. cfn-nag exits
with its count of failing violations and is judged per template; npm audit exits 1
both for advisories and for errors and is judged by whether it wrote a report;
detect-secrets and cdk-nag run in ASH's own worker processes.

**Fix**

Read what the message quotes, and fix what the tool reported: its stderr, or, when
it wrote none (semgrep and opengrep report a rule file they cannot read only in
their SARIF), the error-level notifications from its results file, which the
message names. The full text is in the `<Scanner>.stderr.log`, the
`<Scanner>.stdout.log` and the results file under `scanners/<name>/<target>/` in the
output directory; the message names the ones the tool wrote.
For semgrep and opengrep under `--offline`, see
[Seeding the semgrep and opengrep rule cache](advanced-usage.md#seeding-the-semgrep-and-opengrep-rule-cache).
For grype, see [Grype Cannot Fetch Vulnerability Database](#grype-cannot-fetch-vulnerability-database).

The scan exits 1 for an `ERROR` scanner while `fail_on_incomplete_scanners` is on,
which is the default. With it off, the exit code comes from the findings alone, so a
scan whose only problem is the failed scanner exits 0; see
[Failing on an incomplete scan](configuration-guide.md#failing-on-an-incomplete-scan).

## Container Image Build Fails

**Symptom**

`ash build-image` exits with a Docker or Podman error — network timeout, `no space left on device`, or an `apt-get` failure mid-build.

**Cause**

Most common causes, in order:

1. Disk pressure on the Docker daemon's storage (layers, volumes, old images)
2. Network reachability to package mirrors (pip, apt, Alpine)
3. A stale intermediate image left from a previous failed build

**Fix**

Free space and rebuild from scratch:

```bash
docker system prune -af
ash build-image --force
```

If the network is the issue, check that the daemon can reach the registries you need (often the host can but the container build context cannot). Configure proxies in `~/.docker/config.json` or `/etc/containers/containers.conf` for Podman.

## "Scanner Dependencies Not Satisfied"

**Symptom**

A scanner is skipped with a warning like:

```
Scanner 'checkov' skipped: required tool 'checkov' not found on PATH
```

**Cause**

Local mode requires each scanner's underlying tool to be installed and resolvable. If the tool isn't present, the scanner self-disables rather than failing the entire run.

ASH searches only the absolute entries on PATH, plus its own bin directory. An entry that is relative (`bin`, `.`) or empty names a directory under the working directory, usually the repository being scanned, so ASH skips it: a tool reachable only through such an entry is reported as not found, and a command naming it fails with exit 127 and a reason that names the copy ASH did not run. If the tool is installed in a project directory such as `node_modules/.bin`, add that directory to PATH by its absolute path.

**Fix**

Install the missing tool. Most tools are Python packages installable via `uv tool install`:

```bash
uv tool install checkov
uv tool install bandit
```

Or run in container mode, which bundles every supported scanner:

```bash
ash --mode container
```

Or explicitly exclude the scanner if you don't need it:

```bash
ash --exclude-scanners checkov
```

## Docker Permission Denied on Socket

**Symptom**

```
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

**Cause**

The user running `ash` is not in the `docker` group, so they can't talk to `dockerd` over the default socket.

**Fix**

Add your user to the `docker` group (requires logout/login to take effect):

```bash
sudo usermod -aG docker $USER
newgrp docker
```

Or use Podman instead, which runs rootless by default:

```bash
ash --mode container --oci-runner podman
```

## Windows Path Separator Errors

**Symptom**

On Windows, paths like `C:\Users\me\project` fail config validation, or suppressions configured with Windows-style paths don't match.

**Cause**

ASH uses forward slashes internally for path patterns (matching SARIF conventions). Config files that mix `\` and `/` can fail to match the files they target.

**Fix**

Use forward slashes in config paths, even on Windows:

```yaml
global_settings:
  suppressions:
    - rule_id: RULE-123
      path: src/example.py   # not src\example.py
```

ASH v3 runs natively on Windows PowerShell and `cmd`. WSL2 is not required. If you do use WSL2, run ASH inside the Linux side rather than crossing the `/mnt/c` boundary — file I/O there is an order of magnitude slower.

## `uv` or `uvx` Not Found

**Symptom**

```
ash: command not found
```

Or:

```
Error: uvx not found on PATH
```

**Cause**

ASH is installed via `uv tool install`, but UV itself isn't on the PATH, or a previous UV installation left stale shims.

**Fix**

Install UV and ensure its bin directory is on your PATH:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc   # or ~/.zshrc, ~/.profile, etc.
```

Verify:

```bash
uv --version
uvx --version
```

If `ash` still can't be found after UV is installed, reinstall it:

```bash
uv tool install --force git+https://github.com/awslabs/automated-security-helper.git@v3
```

For deeper diagnostics, see [Troubleshooting UV Tool Installation](troubleshooting-uv-installation.md).

## Scan Completes With No Findings

**Symptom**

The run exits cleanly and a report is generated, but `total_findings` is `0` for a codebase you expect to have findings in.

**Cause**

One of three things:

1. `--source-dir` points somewhere that doesn't contain your code (e.g. the repo root when the code lives in a subdirectory).
2. A broad `.gitignore` or `.ignore` file, or an ASH `ignore_paths` entry, is excluding everything the scanners would look at.
3. Every scanner that would produce findings is disabled or excluded.

**Fix**

Confirm the source directory:

```bash
ash --source-dir ./src --debug
```

Check how many files the repository's ignore files removed. The scan metadata in
`ash.summary.txt` and `ash.summary.md` has an `Ignore files:` line with the total,
and `metadata.ignore_file_exclusions.by_ignore_file` in `ash_aggregated_results.json`
gives the count for each `.gitignore` and `.ignore`. To scan the files they exclude,
pass `--no-honor-ignore-files`; see
[Ignore files and the scan set](configuration-guide.md#ignore-files-and-the-scan-set).

Check for overly broad ignore paths in your config:

```yaml
global_settings:
  ignore_paths:
    - path: "**/*"        # this will hide everything
      reason: "..."
```

List which scanners actually ran and their status with `--debug`, then look for:

```
Scanner 'bandit' status: SKIPPED
```

If a scanner you expected is skipped, check dependencies and the `scanners.<name>.enabled` config flag.

## Sandbox Settings in a Config File Are Ignored

**Symptom**

Under `--sandbox`, a scanner gets no network, or cannot read a path listed in
`sandbox.extra_read_paths`, and the log has a warning like:

```
Ignoring sandbox.network_scanners from the config built on /home/me/dotfiles/ash.yaml: the file is inside a git checkout or the scanned directory, so someone other than the operator may have written it, and it cannot grant sandbox access. ...
```

**Cause**

`sandbox.network_scanners`, `sandbox.extra_read_paths`, `sandbox.read_path_scanners`
and `sandbox.env_scanners` grant access, and a config file inside any git checkout
cannot set them, because someone who can push to that checkout could have written
it. That includes a config you keep in a checkout of your own, such as an ops or
dotfiles repository. For a scanned directory outside any checkout, a config file
inside that directory cannot set them either. Under the MCP server, a file a
client delivered and named as `config_path` cannot set them wherever it is, and the
warning says that an MCP client supplied the file.

**Fix**

Pass the setting on the command line:

```bash
ash --sandbox auto --config-overrides 'sandbox.network_scanners=[grype,trivy-repo]'
```

Or move the config file somewhere outside every git checkout and outside the
scanned directory, and pass it with `--config`. Such a file can extend the
repository's own config: it keeps the sandbox settings it writes itself, and the
warning then names the repository's file. What the file inherits from its bases,
or adds with `patch`, is dropped, so write each grant in the file itself. A `mode`
its own `patch` sets counts as the mode it wrote.

## A Plugin Module From a Config File Is Not Imported

**Symptom**

```
Ignoring ash_plugin_modules entries 'my_plugins' (it is at /home/me/tools/.venv/lib/python3.12/site-packages/my_plugins, and it is inside the git checkout at /home/me/tools) from .ash/.ash.yaml: ...
```

**Cause**

A config file the scanned repository could have written imports only installed
modules outside every git checkout and the scanned directory. A virtualenv inside a
git checkout counts as inside it.

**Fix**

Name the module with `--ash-plugin-modules my_plugins`, or install it into an
environment outside every git checkout and outside the scanned directory.

## A Sandboxed Scanner Does Not Get a Path or Variable Its Options Name

**Symptom**

```
my-scanner's settings ask for host paths the default policy does not allow, and those settings can come from the scanned repository, so the sandbox does not grant them. ...
```

or, for detect-secrets:

```
Not reading the detect-secrets baseline /opt/baselines/.secrets.baseline: it is outside the source tree, and under the sandbox a file outside the tree is read only for a scanner named in sandbox.read_path_scanners. Candidates the baseline would have marked are reported.
```

**Cause**

A scanner's options can come from the scanned repository, so under `--sandbox` the
paths and environment variables they name are granted only to scanners the operator
lists in `sandbox.read_path_scanners` or `sandbox.env_scanners`.

**Fix**

Name the scanner, and put the file's directory in `sandbox.extra_read_paths`:

```bash
ash --sandbox auto \
  --config-overrides 'sandbox.read_path_scanners=[detect-secrets]' \
  --config-overrides 'sandbox.extra_read_paths=[/opt/baselines]'
```

A path outside the source tree has to be inside a `sandbox.extra_read_paths` entry
whether ASH reads it, as it does detect-secrets' baseline, or a plugin scanner
reads it inside the sandbox:

```bash
ash --sandbox auto \
  --config-overrides 'sandbox.read_path_scanners=[my-scanner]' \
  --config-overrides 'sandbox.extra_read_paths=[/opt/my-scanner-rules]'
```

## Landlock Is Unavailable on an Older Kernel

**Symptom**

With `--sandbox landlock`, every scanner is recorded `MISSING` with a reason like:

```
Landlock ABI 2 is below 3 (Linux 6.2), so it cannot stop a scanner from truncating files it may only read, and the source tree would not be read-only
```

With `--sandbox auto` on a machine without a working bubblewrap or firejail, the
scanners are recorded `MISSING` with the same reason in the list of backends `auto`
tried.

**Cause**

Landlock controls truncation only from ABI 3, which Linux 6.2 introduced. On an
older kernel a scanner could truncate files in the source tree, so ASH does not use
Landlock there.

**Fix**

Install bubblewrap and use `--sandbox bwrap` (or `auto`, which tries it first), run
on a kernel with Landlock ABI 3 or later, or use container mode.

## A Scanner Is MISSING Because It Was Found Only Inside the Scanned Tree

**Symptom**

A scanner you have installed is reported `MISSING`, and the scan exits 1 with a line like:

```
Found only inside the scanned tree, so not run: bandit (/home/me/repo/.venv/bin/bandit). To use them, install it outside the scanned tree, or set ASH_ALLOW_IN_TREE_TOOLS=1 or pass --allow-in-tree-tools to allow tools from the tree.
```

The scanner's row in `ash_aggregated_results.json` carries the same reason in `missing_reason`.

**Cause**

ASH does not start tools from inside the directory it scans. `uv run ash scan .` puts the repository's `.venv/bin` first on `PATH`, and `npm run` puts `node_modules/.bin` there, so a scanner installed as a project dependency is a file in the repository being scanned. ASH skips it and uses the next copy on `PATH`; with no other copy the scanner is `MISSING`. The programs the scanner sandbox starts (`bwrap`, `firejail`, `readlink`, `true`) are found the same way.

**Fix**

Install the scanner outside the repository, for example with `uv tool install bandit`, a system package or Homebrew, and run ASH as usual.

Or, if you trust the repository's tools, allow them for this run:

```bash
ash scan --allow-in-tree-tools
# or
ASH_ALLOW_IN_TREE_TOOLS=1 ash scan
```

ASH then logs a warning naming each in-tree tool it uses. A repository's `.ash/.ash.yaml` cannot turn this on, and `ash mcp` ignores both, so for MCP use install the scanners outside the repository. See [Tools inside the scanned directory](advanced-usage.md#tools-inside-the-scanned-directory).

## The Scan Stops Because Something in the Output Directory Is a Symlink

**Symptom**

The scan exits 3 before any scanner runs, with a message like:

```
ERROR (3) The output directory /home/me/out is a symlink. ASH does not write to, clear or mount its output directory through a link, whatever the sandbox mode. Pass --output-dir with a directory that is not a link, or replace the link with a directory.
```

The first sentence names the link; it can be a directory on the way to the output directory, a working directory such as `.ash/ash_output/reports`, or a file such as `.ash/ash_output/ash.log`. Over MCP the message ends with a remedy for the MCP caller instead.

**Cause**

Before a scan ASH removes and recreates `analysis`, `reports`, `scanners` and `converted` under the output directory, writes its logs and results there, and a sandboxed scan mounts it, so each of these has to be a real directory or file. ASH checks this in every sandbox mode and in local, container, nix, workspace and MCP scans, and `ash report` and `ash merge` check the same links below the current directory. In workspace mode a link at `projects/` or `.workspace-spool` stops the whole run, and a link at `projects/<key>` fails that project with the same message; over MCP, `run_ash_workspace_scan` refuses the whole call for either. See [Output directory](concepts.md#output-directory) for the full list.

**Fix**

Point `--output-dir` at a real directory:

```bash
ash scan --output-dir "$HOME/ash-output"
```

or replace the link with a directory. A link above an output directory outside the scanned tree, such as `/tmp` on macOS, is your own spelling and is accepted.

## The Scan Exits 1 Because Conversion Was Incomplete

**Symptom**

```
ERROR (1) Exiting because conversion was incomplete: 1 converter(s) did not process the files they were given
  jupyter: could not convert 1 input: notebooks/report.ipynb
```

**Cause**

A converter could not convert some of its inputs, so the scanners never saw those files in converted form: nbconvert exited non-zero, timed out or wrote no output for a notebook, or a `.zip`, `.tar` or `.gz` file is not an archive Python can read. Each is recorded under `converter_results.<converter>.failed_inputs` in `ash_aggregated_results.json`, with the reason. A `.gz` that is one compressed file rather than a tarball, such as `data.json.gz`, is decompressed and scanned, and is a failed input only when it cannot be decompressed. A Git LFS pointer named like an archive is reported as not scanned and does not fail the scan. `ash merge` combines every shard's failed inputs, and workspace mode reports them per project in `incomplete_converters`.

A notebook's name is not the cause: nbconvert reads its notebook argument as a glob pattern and its output name as a format string, so ASH converts a copy named `notebook.ipynb` and names the result after the original, and `[x].ipynb` or `{a,b}.ipynb` convert. cfn-nag likewise is given a copy of each template named `template.json`, `template.yaml` or `template.yml`, so a template's name does not change how it is scanned, on Windows too.

**Fix**

Read the reason in `failed_inputs`, or rerun with `--debug` to see nbconvert's own error output. Then fix or remove the notebook or archive, exclude it with `ignore_paths`, disable the converter if its inputs are not wanted, or accept the partial scan with `--no-fail-on-incomplete-scanners`.


## An Archive Makes the Scan Incomplete

**Symptom**

The scan exits 1 with `Exiting because conversion was incomplete`, naming the
`archive` converter and one or more `.zip`, `.tar` or `.gz` files, or the summary
lists an archive under "Converter inputs not scanned".

**Cause**

One of three things, named in `converter_results.archive` in
`ash_aggregated_results.json`:

1. The archive is over an extraction limit: its `refused_inputs` record names the
   limit, such as `max_total_bytes`.
2. The archive cannot be read (damaged, truncated, a tar cut off between members,
   empty, or a `.tar.gz` that is not a tarball): it is in `failed_inputs`.
3. The file is a Git LFS pointer rather than the archive, because the checkout did not
   fetch the LFS objects. This is reported but does not fail the scan.

**Fix**

For a limit, raise it as the operator; a config file inside the scanned tree cannot
raise it:

```bash
ash scan --config-overrides 'converters.archive.options.max_total_bytes=4294967296'
```

For an archive that cannot be read, replace it with an intact copy, or exclude it with
`global_settings.ignore_paths` if its contents need not be scanned.

For an LFS pointer, fetch the LFS objects before the scan: `git lfs pull`, or
`lfs: true` on the CI checkout step. See
[Archive Converter](plugins/builtin/converters.md#archive-converter).

## A Scanner Is ERROR Because a Path Below the Output Directory Is a Symlink

**Symptom**

A scanner row is `ERROR`, and its error ends with:

```
.ash/ash_output/scanners/detect-secrets/source/results_sarif.sarif was not written: .ash/ash_output/scanners/detect-secrets/source/results_sarif.sarif is a symlink, and ASH does not write through a symlink below its output directory
```

**Cause**

ASH found a symlink at a path it writes below its output directory, or at a
directory on the way to it, and did not write through it. This holds with and
without `--sandbox`. With a sandbox, a symlink anywhere below the scanner's results
directory before the scanner starts is refused the same way. The default output
directory is inside the scanned tree, so the link usually came with the repository.

An error that ends with `<n> names refer to it, and ASH does not write to a file
below its output directory that another name refers to` is the same refusal for a
hard link: the file at that path is also reachable under another name, possibly
outside the output directory, so ASH did not change it. Archives can carry hard
links.

**Fix**

Remove the link, or pass an `--output-dir` outside the scanned tree.
