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

ash --mode container --offline
```

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
Failed to execute semgrep scanner on source: SemgrepScanner scan failed: its tool exited with code 7, which this scanner does not accept as a completed run, so its results file is not read (exit code 7: not an accepted exit code; success_exit_codes=[0, 1]). Stderr: ...
```

**Cause**

The tool reported that it failed. Each scanner accepts the exit codes its tool uses
for a run that completed, with or without findings, and nothing else. A failed tool
can still leave a results file (semgrep exits 7 and writes SARIF holding only error
notifications when it cannot read a rule configuration; grype exits 1 and writes a
zero-byte report when it cannot load its database), so ASH does not read the file of
a run with any other code: an empty or error-only file would otherwise be graded
`PASSED` with no findings.

| Scanner | Accepted exit codes | What the tool uses other codes for |
|---|---|---|
| bandit | 0, 1 (issues found) | 2: any error (`bandit/cli/main.py`) |
| checkov | 0, 1 (failed checks) | 2: the run crashed (`checkov/main.py`) |
| grype | 0, 2 (a match at or above `--fail-on`) | 1: any error, such as a database it cannot load (`cmd/grype/cli/cli.go`) |
| semgrep | 0, 1 (findings) | 2: fatal; 3 and up: specific failures, 7 for a rule configuration it cannot read (`semgrep/error.py`) |
| opengrep | 0, 1 | the same values as semgrep (`src/osemgrep/core/Exit_code.ml`) |
| trivy-repo | 0 | 1: any error (`cmd/trivy/main.go`) |
| syft | 0 | 1: any error (`cmd/syft/main.go`) |
| ferret-scan | 0, 3 (coverage cut short under `fail_on_incomplete`) | 1: any error |
| snyk-code | 0, 1 (issues found) | 2: an error; 3: no supported project (`src/cli/exit-codes.ts`) |

trivy exits 0 for a run with findings unless its `exit-code` setting names another
code. ASH never passes one, but trivy also reads it from a `trivy.yaml` in the
directory it runs in, which is the scanned directory, and from `TRIVY_EXIT_CODE`. With
`exit-code: 1` set there, every trivy-repo run that finds something exits 1, and the
scanner is `ERROR` rather than reporting those findings: ASH cannot tell that exit
from trivy's own error exit. Remove the setting; ASH decides the scan's exit code
from the findings itself.

cfn-nag, npm audit, detect-secrets and cdk-nag are not in this table. cfn-nag exits
with its count of failing violations and is judged per template; npm audit exits 1
both for advisories and for errors and is judged by whether it wrote a report;
detect-secrets and cdk-nag run in ASH's own worker processes.

**Fix**

Read the stderr in the message, or the `<Scanner>.stderr.log` it names under
`scanners/<name>/<target>/` in the output directory, and fix what the tool reported.
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
2. A broad `.gitignore` or ASH `ignore_paths` entry is excluding everything the scanners would look at.
3. Every scanner that would produce findings is disabled or excluded.

**Fix**

Confirm the source directory:

```bash
ash --source-dir ./src --debug
```

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
or changes with `patch`, is dropped, so write each grant in the file itself.

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

The scan exits 1 before any scanner runs, with a message like:

```
ERROR (1) The output directory /home/me/out is a symlink. ASH does not write to, clear or mount its output directory through a link, whatever the sandbox mode. Pass --output-dir with a directory that is not a link, or replace the link with a directory.
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

A converter could not convert some of its inputs, so the scanners never saw those files in converted form: nbconvert exited non-zero, timed out or wrote no output for a notebook, or a `.zip`, `.tar` or `.gz` file is not an archive Python can read. Each is recorded under `converter_results.<converter>.failed_inputs` in `ash_aggregated_results.json`, with the reason. A `.gz` that is one compressed file rather than a tarball, such as `data.json.gz`, is not an archive and is skipped, not counted. `ash merge` combines every shard's failed inputs, and workspace mode reports them per project in `incomplete_converters`.

A notebook's name is not the cause: nbconvert reads its notebook argument as a glob pattern and its output name as a format string, so ASH converts a copy named `notebook.ipynb` and names the result after the original, and `[x].ipynb` or `{a,b}.ipynb` convert. cfn-nag likewise is given a copy of each template named `template.json`, `template.yaml` or `template.yml`, so a template's name does not change how it is scanned, on Windows too.

**Fix**

Read the reason in `failed_inputs`, or rerun with `--debug` to see nbconvert's own error output. Then fix or remove the notebook or archive, exclude it with `ignore_paths`, disable the converter if its inputs are not wanted, or accept the partial scan with `--no-fail-on-incomplete-scanners`.

