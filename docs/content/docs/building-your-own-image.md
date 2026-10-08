# Building your own container image

ASH does not publish a container image to a public registry, and is not planning to.
The recommended posture is that the organization running ASH builds the image and
hosts it in its own registry.

## Why you build it yourself

ASH reads your source code. An image that scans your repositories sits in the same
trust position as your build tooling, so the question "what is in this image, when did
it change, and who approved that change" needs an answer that belongs to you rather
than to an upstream publisher.

Building it yourself gives you four things a pulled public image cannot:

- **A known provenance.** The image came from a Dockerfile in a commit you can name,
  built by a pipeline you control.
- **A patching cadence you set.** You decide when the base image and the bundled
  scanner tools move, rather than inheriting whenever an upstream tag was pushed.
- **A scanning surface you can inspect.** The image can be scanned, signed, and
  admitted by the same controls you already apply to your own images.
- **No new external dependency at scan time.** Your CI pulls from your registry, so a
  scan does not fail because a public registry is unavailable or rate-limited.

The tradeoff is real and worth stating plainly: you own the rebuild cadence. An image
built once and never rebuilt ages, and ASH's bundled scanners age with it. See
[Keeping it current](#keeping-it-current).

## Build it once, host it internally

```bash
# Build the image
ashx build-image --build-target non-root

# Tag and push to your own registry
docker tag automated-security-helper:non-root \
  my-registry.example.com/security/ash:3.6.0
docker push my-registry.example.com/security/ash:3.6.0
```

Two build targets exist:

| Target | Runs as | Use when |
|---|---|---|
| `non-root` | An unprivileged user | The default. Prefer it. |
| `ci` | Root | The runner's UID/GID mapping makes an unprivileged user impractical |

Point ASH at your published image with `ASH_IMAGE_NAME`:

```bash
export ASH_IMAGE_NAME="my-registry.example.com/security/ash:3.6.0"
ashx --mode container --source-dir .
```

Tag with the ASH version you built rather than only `latest`, so a scan result can be
traced back to a specific image. A moving `latest` makes two scans that disagree
impossible to explain.

## Keeping it current

ASH orchestrates external scanners, and their versions are not all pinned. A rebuild
can therefore change which findings you get, in both directions — a scanner release
can add checks or drop them. That is an argument for rebuilding on a schedule you
choose and reviewing the delta, not for rebuilding as rarely as possible.

A workable cadence:

- Rebuild when you upgrade ASH, and tag the image with that ASH version.
- Rebuild on a fixed interval regardless, so base-image CVE fixes land.
- Compare a scan of a known repository across the old and new image before promoting
  the new one. A jump in finding counts is usually a scanner version change rather
  than a change in your code.

## Air-gapped and offline builds

Building with `--offline` caches the tool vulnerability databases into the image
itself, so a scan needs no network access:

```bash
ashx build-image --build-target non-root --offline
```

The build itself still requires network access — that is when the dependencies and
databases are fetched. Only the resulting scan is offline. An offline image's
databases are frozen at build time, which makes the rebuild cadence above load-bearing
rather than optional.

**An offline image stops passing once its databases are past their bound.** ASH reads
each database's own build time after the scan and exits 1 when it is too old: grype's
database 5 days (120h) after it was built, which is grype's own default, and the
offline semgrep and opengrep rulesets 30 days after they were downloaded (the build
records that time in `.ash-rules-fetched-at`). This applies in offline mode exactly
as online; before it, an offline scan with a weeks-old database exited 0 with no
warning.

To keep an air-gapped image passing, rebuild it at least every 5 days with
`ashx build-image --offline`, which downloads a current grype database and current
rulesets, and move the new image across the air gap. To scan with an older image
anyway, pass `--allow-stale-content-db` or set `content_db_staleness: warn` in the ASH
config: the scan passes, and the summary reports, `ash.sarif` and `ash.flat.json` all
say which database was stale and how old it was. See
[Failing on a stale content database](configuration-guide.md#failing-on-a-stale-content-database).

## If you would rather not run a container

`--mode local` runs ASH as a Python process with no image involved:

```bash
uvx automated-security-helper --mode local --source-dir .
```

This avoids the image question entirely, at a cost: a few of the tools ASH
orchestrates cannot be installed through Python packaging alone, so local mode runs a
smaller set of scanners than container mode. Check the scanner table in the run summary
to see which ones participated rather than assuming parity.

## If you build per run in CI

Building on every run is supported and is the simplest thing that works, but it is the
slowest. On GitHub Actions, ASH passes `--cache-from`/`--cache-to type=gha`
automatically when `ACTIONS_CACHE_URL` or `ACTIONS_RESULTS_URL` is set, with a separate
cache scope per build target, so a warm cache skips most of the build. Nothing needs
configuring for that.

Even with caching, a registry-hosted image is faster and gives you the provenance
story above. Per-run builds are best treated as a starting point rather than a
destination.

## Extending the image

`--custom-containerfile` builds your own Dockerfile on top of ASH's, with the ASH image
passed in as the `ASH_BASE_IMAGE` build argument:

```bash
ashx build-image --build-target ci --custom-containerfile ./Dockerfile.internal
```

Supplying a custom containerfile forces the `ci` build target, so the run-as-non-root
configuration is not applied. Securing the final image is then yours to do — set a
non-root `USER` in your own Dockerfile if you need one.

## Third-party license files in the image

The image bundles third-party programs that ASH installs from their upstream
releases: grype, syft, trivy, opengrep and uv today. Each one's license and notice
files are in the image under `/usr/share/doc/ash/third-party/<tool>/`, taken from the
exact release the image carries. Beside them, a `SOURCE` file names the upstream
repository, release tag and commit. For a copyleft tool (opengrep is LGPL-2.1), that
file also says where the corresponding source is.

`/usr/share/doc/ash/third-party/index.json` lists every bundled tool with its version,
license expression, repository, commit and files. The image build writes it only
after checking every entry against the built image, so it describes what is
actually installed.

```bash
docker run --rm automated-security-helper:non-root cat /usr/share/doc/ash/third-party/index.json
```

If you redistribute the image, these are the files that go with those programs.
Packages installed from Debian carry their own copyright files under
`/usr/share/doc/<package>/`, and Python packages carry their license metadata in
their `.dist-info` directories.
