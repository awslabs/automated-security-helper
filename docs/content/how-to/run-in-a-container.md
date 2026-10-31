# Run ASH in a container

Container mode runs the scan inside ASH's container image, which carries every scanner
tool, so the host needs ASH and a container runtime and nothing else. ASH publishes no
prebuilt image: the first container-mode scan on a machine builds one, and later scans
reuse it.

Prerequisites:

- ASH installed on the host ([Install ASH](install.md)).
- One of finch, docker, nerdctl, or podman on `PATH`.
- Network access while the image builds. The build pulls the Python base image from
  Amazon ECR Public, clones ASH from GitHub unless it builds a local source tree, and
  downloads the scanner tools.

## Scan in container mode

Run container-mode scans from a directory that is not the repository you scan and holds
no `Dockerfile` of its own. Name the repository with `--source-dir`, and keep the source
and the output in separate directory trees:

<!-- doctest: illustrative reason="needs a container runtime and network access to build the image" -->
```bash
cd ~/work
ash scan --mode container --source-dir src/my-app --output-dir ash-output/my-app
```

ASH builds the image (several minutes the first time; later builds reuse the layer
cache), runs the scan inside it, reads the results back from the output directory, and
exits with the same [exit codes](../reference/exit-codes.md) as a local scan. A container
that fails to start, and a build that fails, exit with the runtime's own status instead.

These `ash scan` options control the image:

<!-- doctest: options of=cli.scan -->
| Option | Effect |
|---|---|
| `--no-build` | Run the existing image instead of building it. |
| `--force` | Rebuild without the layer cache. |
| `--no-run` | Build the image and stop. |
| `--build-target ci` | Build the root image instead of the non-root one. |

`ash build-image` builds the image and then scans the current directory with it, writing
to `.ash/ash_output` there. Add `--no-run` to build only. It takes no `--source-dir`,
`--output-dir`, or other scan option: an argument its help does not list stops it with
exit code 5 before anything is built, so use `ash scan --mode container` to choose the
directories. Every option of both commands is in the
[CLI reference](../reference/cli.md#build-image).

Spell options out in full: the short flags differ between the two commands. On `ash scan`,
`-o` is `--oci-runner` and `-r` is `--run`; on `ash build-image`, `-r` is `--oci-runner`.

## Choose the container runtime {#runtime}

ASH uses the first of finch, docker, nerdctl, and podman that it finds on `PATH`. To pick
one, pass `--oci-runner podman` or set `OCI_RUNNER=podman`. To prefix every runtime call
with another command, such as `sudo`, set `OCI_RUNNER_WRAPPER=sudo`.

Each of these takes a command name or an absolute path, and so does the `oci_runner` of a
`--cli-json-input` document, which ASH reads as if you had typed it as `--oci-runner`. A
`~` or `~user` at the start is expanded, so `~/bin/docker` names `$HOME/bin/docker`; in
`OCI_RUNNER_WRAPPER` that applies to the first word. A `$` in the document's value is
not expanded, so `$HOME/bin/docker` there is a relative path. With no usable home
directory (`HOME` empty or relative, or unset with no absolute home in the passwd entry),
a value that starts with `~/` is not used: ASH logs a warning about `HOME` and picks a
runtime as if none were named, or, for the wrapper, starts the runtime without one. A
relative path with a directory part, such as `bin/docker`, is read against the directory
you run ASH in when you pass it to `--oci-runner` or give it in the document. In
`OCI_RUNNER` it is not run: ASH logs a warning and picks a runtime as if none were named.
As the first word of `OCI_RUNNER_WRAPPER` it is not used either, and the runtime starts
without a wrapper, with a warning.

## Root and non-root images {#build-target}

The Dockerfile has two final stages:

- `non-root`, the default, runs as `ash-user`. `ash build-image` and container-mode scans
  give that user the UID and GID of the user running ASH, so the scan can write to the
  mounted output directory. Pass `--container-uid` and `--container-gid` to choose other
  values.
- `ci` runs as root.

`--build-target` chooses the stage (`-BuildTarget` for `Invoke-ASH`). Without it, ASH
builds `non-root`, or `ci` on Windows, where the non-root user cannot write the mounted
output directory. `--custom-containerfile` always builds on `ci`. The CI variables `CI`,
`IsCI`, `ISCI`, and `CODEBUILD_BUILD_ID` do not change the stage.

The `non-root` user cannot have UID 0 or GID 0, which are root's. A `non-root` build that
would give it either stops with exit code 3 before anything is built. That happens when
ASH runs as root, as it does in many CI jobs, such as AWS CodeBuild and container-based
GitLab and Jenkins jobs, and when you pass `--container-uid 0` or `--container-gid 0`.
Pass `--build-target ci` there to build the image that runs as root. Other
`--container-uid` and `--container-gid` values work only when that user can write the
output directory.

The image is tagged `automated-security-helper:non-root` or `automated-security-helper:ci`.
Set `ASH_IMAGE_NAME` to build and run an image under another name.

## Which ASH goes into the image {#revision}

The image installs ASH from source, chosen from how ASH was installed on the host:

| Host install | Source of the image |
|---|---|
| From a git URL with a tag, such as `@v3.7.1` | That tag, cloned from GitHub when the image builds. |
| From a git URL with a branch, such as `@main` | The tip of that branch when the image builds, which can differ from the commit installed on the host. |
| From a git URL with no ref | The installed commit, fetched from GitHub by its commit ID. |
| A clone of the ASH repository, an editable install of one, or `pip install <directory>` | That source tree, built with its own `Dockerfile`, so the image holds the same ASH as the host. |
| Any other install, such as Homebrew, a wheel or sdist file, or an archive URL | The commit the package was built from, fetched by its commit ID. A package built outside a git checkout of ASH, such as from a source tarball, records no commit: the image then installs the release tag of the installed version, such as `v3.7.1`, and ASH logs a warning that this is a guess. A development or pre-release version has no release tag, so the build stops before it starts and asks for `--ash-revision-to-install`. |

`--ash-revision-to-install` overrides the table with a tag, a branch, or a full
40-character commit ID. It accepts letters, digits, dots, hyphens, underscores, and
slashes. Run from the top directory of a checkout of ASH, `ash build-image` and
container-mode scans build that checkout whatever the revision says; to build another
revision, run them from another directory.

A branch, or the floating `v3` tag, is cloned again on every build, because it can have
moved since the last one. A release tag or a commit ID is cloned once, and later builds
take that clone from the build cache.

## Mounts and network {#mounts}

The container sees two host directories: the source directory at `/src` and the output
directory at `/out`. Keep the two in separate directory trees, such as
`~/work/src/my-app` and `~/work/ash-output/my-app`, as in the example above; ASH then
mounts the source read-only. The default output directory, `.ash/ash_output`, is inside
the scanned directory.

Every path ASH mounts has to be UTF-8: the source and output directories, the config file
and each file it extends, the file `ASH_CONFIG` names and each file it extends, and a
workspace policy. A path holding a byte that is not UTF-8 stops the scan with exit code 3
before the container runtime runs. The error names the path with each such byte written
as `\udcNN`, as in `caf\udce9`. A scan of one directory is refused before it creates the
output directory, and the previous run's `ash.log` is left as it was. `./ash` refuses
the same source directory, output directory, and config file, with the same exit code.

A source or output directory that a local scan refuses, such as a source directory that
does not exist or an output directory that cannot be created, stops
`ash scan --mode container` with exit code 5, also with `--no-run`, and with the line a
local scan prints ([Exit codes](../reference/exit-codes.md#scan)). `./ash` refuses them
as well: it prints the line after `ERROR: ` and exits 5.

An output directory that is a symlink, or that a symlink below the source directory leads
to, such as a committed `.ash` link for the default `.ash/ash_output`, stops
`ash scan --mode container` and `ash build-image` with exit code 3
([Exit codes](../reference/exit-codes.md#container)), because the scan inside the
container would write wherever the link points. The refusal comes before a container
runtime is looked up, with `--no-run` too, so nothing is built, created, or mounted.
`./ash` and `Invoke-ASH` refuse the same output directory.

Inside the container ASH runs a local-mode scan of `/src`. Some things do not carry over:

- Environment variables. The container gets only the variables ASH sets for it and the
  ones the operator's config files read ([The config file](#config)), so AWS credentials
  and other settings in the host environment are not passed in, and neither are the
  host's AWS credential files.
- The scanner sandbox. Container mode never sandboxes the scanners inside the image; the
  container is the boundary ([The scanner sandbox](#sandbox)).
- `--changed-files-only`. The scan stops with exit code 5 before anything is built or run,
  also when `ASH_CHANGED_FILES_ONLY` sets it. Scan with `--mode local` to report only the
  findings in changed files.
- Third-party plugin modules. `--ash-plugin-modules` is passed in, but only modules
  installed in the image load. Add packages with `--custom-containerfile`.

`--ignore-suppressions` reaches the scan inside and works there as in a local scan: it
lifts suppressions and ignore paths for every scanner, and ASH's own output directory
stays out of the results ([See every finding](suppress-findings.md#ignore-suppressions)).

The container uses the runtime's default bridge network. `--offline` runs it with no
network and builds an offline image ([Run ASH offline](run-offline.md)).
`ash build-image --container-network` takes another network mode, such as `none` or a
named network.

### The config file {#config}

`--config` names the config file, or `ASH_CONFIG` when no `--config` is given. With
neither, the scan inside the container finds the repository's own config file under
`/src` the way a local scan does. ASH checks a file you name on the host before it builds
or runs anything, in `ash scan --mode container`, `ash --mode container`, `./ash`, and
`Invoke-ASH`. A path that names no file stops the scan with exit code 3:

<!-- doctest: run expect-exit=3 -->
```bash
ash scan --mode container --config missing.yaml
```

<!-- doctest: output -->
```text
Config file not found: missing.yaml. ...
```

A file ASH cannot read stops it the same way. With `--no-run` nothing is scanned, and
the config is not checked.

Beside a `--config`, the file `ASH_CONFIG` names is still the trusted base, as in a local
scan: ASH reads it first, and when the config is a repository's, takes from it the
settings a repository may not choose
([Configuration trust model](../concepts/trust-model.md#how-the-tier-is-decided)).
`ash scan --mode container` and `ash --mode container` mount that file, and each file it
`extends`, read-only under `/ash-env-config`, and the scan inside reads it as its
`ASH_CONFIG`. A file of that chain the host counts as written by a repository is marked
for the scan inside, file by file. An `ASH_CONFIG` file that is missing, cannot be read,
does not parse, or is not a valid config stops the scan with exit code 3 on the host,
before anything is built, run, mounted, or cleared, even when `--config` names a valid
file.

A relative path is taken from the directory you run ASH in, not from `--source-dir`. The
scan inside is given the file's path in the container:

- A file inside `--source-dir` is read through the source mount, at `/src/<path>`, and
  so is every file it `extends`, which has to be inside `--source-dir` too, as in a
  local scan.
- Any other file is mounted read-only under `/ash-config`: `~/ash/ash.yaml` is
  `/ash-config/ash.yaml`. Container mode also mounts each file of its `extends` chain,
  at its place relative to the config, and no other file. `./ash` and `Invoke-ASH` mount
  the config alone, so they refuse a config outside the source directory that has an
  `extends` entry, with exit code 3.

ASH refuses these with exit code 3 before anything runs, because each would let the
repository being scanned choose a host file to mount:

- A config named inside the scanned tree, the outermost git checkout at or above
  `--source-dir`, that is a symbolic link, or is reached through one, to a file outside
  that tree. A link that stays inside the tree is followed.
- A config outside `--source-dir` whose `extends` chain includes a file inside
  `--source-dir`, or in which a file of the scanned checkout extends a file outside that
  checkout.
- In workspace mode, a workspace policy (`ash-workspace.yaml` or `--workspace-config`)
  that is a symbolic link, or is reached through one, out of the workspace's tree. A
  policy outside the workspace root is mounted read-only under `/ash-workspace-config`.

`ash scan --mode container` and `ash --mode container` also refuse, with exit code 3, a
chain they cannot place in the container where the host reads it, such as an `extends`
entry that names its base by an absolute path. Write each base relative to the file that
extends it.

A config the host counts as written by a repository, one inside any git checkout or
inside `--source-dir`, keeps a repository config's limits inside the container, so the
host and the container give the same file the same tier
([Configuration trust model](../concepts/trust-model.md#how-the-tier-is-decided)). A file
under `/src` is in the scanned directory there. For a file mounted from a git checkout,
ASH tells the scan inside that a repository wrote it. It marks each file of the chain on
its own, so a config outside every checkout that extends a base in a git checkout keeps
its own settings, as on the host, and the scan inside drops the same settings with the
same warnings as a local scan.

A workspace scan does the same with a `--config` from another git checkout, such as an
operations repository beside the workspace. The workspace scan inside limits that file,
and every file it extends, for every project and for the plan, with the same settings
dropped and the same warnings as a workspace scan in local mode. A `--config` outside
every checkout is the operator's. A `--config` in the workspace's tree, the git checkout
around the workspace root, or the workspace root itself when it is in no checkout, is
refused with exit code 3 before anything is built or mounted, as in a local workspace scan
([Scan a multi-project workspace](scale-large-repos.md#workspaces)). That covers a file
inside the workspace root, a file in the checkout outside the root, and a path that is a
link, or is reached through one, into that tree or out of it. The error names each file,
says to move the config and every base it extends outside the checkout, or outside the
workspace root when it is in no checkout, and ends
`To keep a setting, move the file outside every git checkout, or pass the setting with --config-overrides. A file inside the scanned directory has to move out of it as well.`

The scan inside the container reads the host's environment only for the variables the
operator's own config files read. Those files are the `--config` file and the file
`ASH_CONFIG` names, with the files each `extends`, when they are outside the scanned
directory and every git checkout. A `--config` inside one of those makes every file it
extends the repository's too, while the files of the `ASH_CONFIG` file's chain are judged
one by one. ASH passes in each variable such a file reads
([Read values from the environment](configure.md#environment)) that is set on the host.
It passes each one by name, so the value is not on the runner's command line. Through
`OCI_RUNNER_WRAPPER`, it writes the values to an env file that only you can read, in a
new directory outside the scanned and output directories, passes the file with the
runtime's own env-file option, and removes it when the run
ends, also after an error, Ctrl-C, or `SIGTERM`. A variable that a config in the scanned
directory or in a git checkout reads is not passed in, so the scan inside reads that file
as though the variable were not set.

A config file that reads a variable ASH sets in the container, or reads as one of its
own settings, such as `ASH_DEBUG` or `ASH_BIN_PATH`, stops the scan with exit code 3
before anything is built or run, when that variable is set. The error names the file,
the variable, and the field, and says to write the value in the file or pass it with
`--config-overrides`. Through `OCI_RUNNER_WRAPPER`, the scan also stops with exit code 3,
before the container runs, when the runner is not `docker`, `finch`, `nerdctl`, or
`podman`, when a value holds a line break or a NUL, or when the temporary directory is
inside the scanned or output directory. None of these errors prints a value.

### The scanner sandbox {#sandbox}

Container mode never sandboxes the scanners inside the image: the container is the
boundary, and every scanner in it shares the container's access. So `--sandbox` with any
mode but `off` stops the scan with exit code 5 before anything is built or run:

<!-- doctest: run expect-exit=5 -->
```bash
ash scan --mode container --sandbox bwrap
```

<!-- doctest: output -->
```text
--sandbox bwrap cannot be used with --mode container: ...
```

To sandbox each scanner, scan with `--mode local --sandbox <mode>`. `./ash` refuses
`--sandbox` the same way, and `Invoke-ASH` sets `$LASTEXITCODE` to 5 and throws.

A `sandbox.mode` from a config file or `--config-overrides` is not refused, so one config
file serves local and container scans. The scan inside the container gets
`sandbox.mode=off` as its last override, and `ash scan --mode container` logs a warning
that names the mode, such as `The scanner sandbox (bwrap, from sandbox.mode in a config
file, --config-overrides or the operator's config) is not applied in container mode`.
The mode can come from `--config-overrides`, the config file, a workspace project's
config, or a trusted config whose mode applies under a repository's own: an operator
`--config` under a workspace project's config, or `ASH_CONFIG` under an in-tree
`--config`. When the host cannot resolve the config, ASH still warns about a mode that
`--config-overrides` or the operator's config asks for. With no sandbox asked for, or
with `--no-run`, it logs no warning. `./ash` and `Invoke-ASH` also give the scan inside
`sandbox.mode=off` as its last override, and log no warning about it.

## Build and host your own image {#own-image}

Build the image once, push it to a registry your organization controls, and run that
image in CI instead of building per run. With `ASH_IMAGE_NAME` set, `ash build-image` tags
the image with your registry's name:

<!-- doctest: illustrative reason="needs a container runtime, network access, and a registry" -->
```bash
export ASH_IMAGE_NAME=registry.example.com/security/ash:3.7.1
ash build-image --no-run --oci-runner docker --ash-revision-to-install v3.7.1 \
  --container-uid 1001 --container-gid 1001
docker push "$ASH_IMAGE_NAME"
```

Set the UID and GID to the user your CI jobs run as. Hosts that have `ASH_IMAGE_NAME`
set run that image with `ash scan --mode container --no-build`, and the runtime pulls it
when it is not present.

To build without ASH installed, build the Dockerfile from a clone. The clone is the build
context, so the image contains exactly the ref it cloned:

<!-- doctest: illustrative reason="needs a container runtime and network access" -->
```bash
git clone --depth 1 --branch v3.7.1 https://github.com/awslabs/automated-security-helper.git
cd automated-security-helper
docker build --target non-root --build-arg UID=1001 --build-arg GID=1001 \
  --tag registry.example.com/security/ash:3.7.1 .
```

Build arguments:

<!-- doctest: options of=dockerfile -->
| Argument | Default | Effect |
|---|---|---|
| `BASE_IMAGE` | `public.ecr.aws/docker/library/python:3.12-slim-bookworm` | Base image for every stage. Point it at a mirror of the same image. |
| `INSTALL_ASH_REVISION` | `LOCAL` | `LOCAL` builds the build context. Any other value is a tag or branch cloned from GitHub, or a full commit ID fetched from it, unless the build context is ASH's own source tree, which is then built instead. |
| `OFFLINE` | `NO` | `YES` downloads the grype and trivy databases and the semgrep and opengrep rulesets into the image, and makes every scan in it offline. |
| `BUILD_DATE_EPOCH` | `-1` | A new value makes an offline build download the databases and rulesets again; with the same value, that step comes from the build cache. ASH passes UTC midnight of the current day, in epoch seconds, for offline builds. |
| `OFFLINE_SEMGREP_RULESETS` | `p/ci` | Space-separated semgrep registry rulesets an offline image downloads. |
| `UID`, `GID` | `500`, `100` | UID and GID of the `non-root` user. |

Scanner tool versions are pinned in
[`tool_downloads.py`](https://github.com/awslabs/automated-security-helper/blob/main/automated_security_helper/utils/tool_downloads.py),
and the build checks each tool against its pin.

To add tools, write a Dockerfile that builds on the ASH image and pass it with
`--custom-containerfile`; ASH passes the base image's name to that build as a build
argument, named in the [option's help](../reference/cli.md#scan--custom-containerfile).
ASH then builds its base image from the root `ci` target and tags the result
`automated-security-helper:custom`. The final image runs as root unless your Dockerfile
sets another user, so secure it yourself.

To run your image in CI with your own configuration, run ASH inside it in local mode and
mount the files it needs. [Roll out ASH across repositories](../getting-started/platform-teams.md)
shows the full setup.

Rebuild on a schedule. The image holds the scanner tools and, for an offline image, the
vulnerability databases, so it ages; see [Run ASH offline](run-offline.md#refresh). A
rebuild whose inputs did not change comes from the build cache, so pass `--force`, which
rebuilds every layer, to install current scanner tools. Without `--force`, an offline
build downloads current databases and rulesets once per UTC day; with `--force`, on
every build. The same holds for `./ash --offline` and `Invoke-ASH -Offline`.

### Third-party license files {#third-party-licenses}

The image carries license and notice files for these third-party components, taken from
the release it carries, in `/usr/share/doc/ash/third-party/<tool>/`: actionlint, cfn-guard
and the AWS Guard Rules Registry rules it reads, gitleaks, grype, opengrep, syft, trivy,
and uv; and the scanners installed from PyPI, bandit, checkov, cfn-lint, semgrep, and
zizmor.

Beside each program's files, a `SOURCE` file names the upstream repository, release tag,
and commit. For the copyleft components, opengrep and semgrep (LGPL-2.1-only), `SOURCE`
also gives the git commands that check out the corresponding source. `index.json` in
`/usr/share/doc/ash/third-party` lists each of these components with its version, license,
repository, commit, and files. The build writes it only after checking each entry
against the built image.

Other Python packages in the image, such as the scanners' dependencies and nbconvert,
keep their license files in their `.dist-info` directories, and Debian packages keep
theirs in `/usr/share/doc/<package>/`. cfn-nag and the Ruby gems it depends on, and the
yarn and pnpm that corepack prepares, have no entry in this directory. The licenses of
libraries built into the bundled programs, such as the modules statically linked into the
Go and Rust programs, are not reproduced.

## Windows and macOS {#platforms}

ASH's own CI tests container mode on Linux only, with docker, podman, finch, and nerdctl.

- On Windows, `ash build-image` always builds the root `ci` image, because the non-root
  user cannot write to the bind-mounted output directory there. `ash scan --mode container`
  does not force it. If `ash` runs a different program, such as the `ash` shell that ships
  with Git for Windows, run `ashv3`, which is the same command.
- On macOS, the image builds for the host's architecture; the Dockerfile supports amd64
  and arm64.
