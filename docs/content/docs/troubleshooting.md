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
Ignoring sandbox.network_scanners from /home/me/dotfiles/ash.yaml: the file is inside a git checkout or the scanned directory, so someone other than the operator may have written it, and it cannot grant sandbox access. ...
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
ash --sandbox auto --config-overrides 'sandbox.network_scanners=[grype,trivy]'
```

Or move the config file somewhere outside every git checkout and outside the
scanned directory, and pass it with `--config`.

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

Name the scanner:

```bash
ash --sandbox auto --config-overrides 'sandbox.read_path_scanners=[detect-secrets]'
```

That is all detect-secrets needs, because ASH reads the baseline itself. For a
plugin scanner that reads the path inside the sandbox, the path also has to be
inside the source tree or a `sandbox.extra_read_paths` entry before it is mounted:

```bash
ash --sandbox auto \
  --config-overrides 'sandbox.read_path_scanners=[my-scanner]' \
  --config-overrides 'sandbox.extra_read_paths=[/opt/my-scanner-rules]'
```

## Sandboxed Scan Stops Because the Output Directory Is a Symlink

**Symptom**

```
ERROR (1) The scanner sandbox is on, and the output directory path /repo/build is a symlink, so mounting the output directory would expose wherever it points. Choose an output directory that is not reached through a symlink.
```

**Cause**

The output directory is a symlink, or is reached through one below the source
directory. ASH stops before writing anything there. Whether the sandbox is on is
decided the way the scan decides it, so a config file in the scanned repository, or
one an MCP client supplied, that sets `sandbox.mode: off` does not skip the check
while `--sandbox`, `ASH_CONFIG` or your own config file turns the sandbox on.

**Fix**

Pass an `--output-dir` that is not reached through a symlink, or run with
`--sandbox off`.
