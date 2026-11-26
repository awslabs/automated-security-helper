# Scan container images

ASH scans a container image as a first-class subject: the scan's *asset* is the image,
named by a locator, and the filesystem stops being the implicit universal. ASH fetches
nothing itself -- image fetching, caching and preparing belong to a container engine
(the docker daemon, podman) or to the scanner tools' own registry clients -- so what you
submit is always a *name* or a *payload you already hold*, never credentials or a
daemon socket handed to ASH.

## The three submission shapes

One scan has one subject. Name the image in exactly one of three ways, each exclusive
with `--source-dir` and with the others:

<!-- doctest: illustrative reason="needs a container runtime, network access and a registry that holds the image, and grype, syft and trivy installed on the host" -->
```bash
# An indirect reference: resolved by an engine or the tools' own registry clients.
ash scan --image registry.example.com/team/app:1.2.3

# A saved image you already hold: an uncompressed `docker save` tarball.
docker save registry.example.com/team/app:1.2.3 -o app.tar
ash scan --image-archive app.tar

# An OCI image-layout directory (the directory holding the oci-layout marker file).
ash scan --image-layout ./app-layout/
```

Naming two of them in one call is refused before anything runs, with exit code 5 (a
usage error):

<!-- doctest: run expect-exit=5 -->
```bash
ash scan --image registry.example.com/team/app:1.2.3 --image-archive app.tar
```

Prefer a digest-pinned reference (`repo@sha256:...`): two scans of the same pinned
image then agree across machines. A tag-only reference is accepted and handed to the
tool as written; ASH does not resolve it to a digest.

**Current status.** grype, syft and trivy are the scanners that read images; every other
scanner is filesystem-only and is reported SKIPPED. ASH detects an engine (below) to pick
how the tools reach the image, but it does not ask the engine for a digest, and an image
scan is only as complete as those three tools' own coverage.

The two payload shapes are checked at the stat level before anything uses them, the way
a source directory is: the archive must exist, be readable and carry tar magic (a
gzip-compressed archive is refused with the remedy -- save it uncompressed, which is
what `docker save` writes); the layout must be an enterable directory holding the
`oci-layout` marker file. What is *inside* passes to the scanner tools, which report
malformed images themselves.

Image options run in local mode, single-directory, on a fresh scan: they cannot be
combined with any other `--mode` (container, nix and precommit are refused), a workspace
scan, `--use-existing`, `--changed-files-only` or a shard (`--shard-index`,
`--shard-count`). The convert phase does not run (converters read source files, which an
image presents none of), so asking for the convert phase alone is refused. The scan
records the image, not the directory it was started from, as its scan source, and does
not walk that directory.

`--changed-files-only` scopes a scan by git history, and an image has no diff base, so it
means nothing there. It is not refused: ASH warns once that it has no meaning for an image
scan and scans the whole image.

**One subject per scan, several scans per call.** A scan reports on one asset, and each
image keeps its own report, its own identity scope and its own exit code. To scan several
images in one call, repeat `--image` or give a comma-separated list (the two forms mix):

<!-- doctest: illustrative reason="scans two images from a registry, which needs network access and grype, syft and trivy installed on the host" -->
```bash
ash scan --image registry.example.com/team/app:1.2.3 --image registry.example.com/team/db:4.5
ash scan --image registry.example.com/team/app:1.2.3,registry.example.com/team/db:4.5
```

ASH then runs one single-image scan per reference, in the order given, each in its own
report directory under `--output-dir` named `<NN>-<name>-<8 hex of the reference's hash>`
(for example `01-registry.example.com-team-app-1.2.3-3fa9c0de`). The reports are not
merged, so no finding of one image can be attributed to another. The call's exit code is
the worst of the per-image codes, worst first: 5, 3, 4, 1, 2, 0. A 3 or a 5 (a refused
configuration, a missing required scanner) does not depend on which image is scanned, so
it ends the batch at once and the images after it are reported as not scanned. Any other
failure is recorded and the next image still runs. `--image-archive` and `--image-layout`
name one payload each and cannot be repeated, and a list with an empty or repeated entry is refused before anything runs.

`--baseline` is refused with an image. A baseline compares findings against a stored
scan of one scanned directory, keyed on that directory's relative path; an image has no
such directory, and its finding ids carry the image digest, so a baseline taken against
one build of an image would match nothing of the next and the "moved" pairing would pair
unrelated findings. Compare two images by diffing their reports instead.

## Which scanners look at the image

Capability lives in one place: a scanner's operational-facets register row. A scanner
serves container images exactly when its row declares the `container_image` target
kind; every other scanner -- and every third-party plugin that predates the register --
is reported **SKIPPED** for an image scan, with a row naming the declaration, before
its tool or dependencies are ever probed. A scanner that is *selected* but cannot be
built is an **ERROR** row with the reason, on an image scan and on a directory scan
alike: a module that fails to import, and a scanner whose constructor raises. For a
scanner that does not serve images the row adds that this image scan lost none of its
image coverage; a reason never hides a scanner that is missing. A scanner that was
excluded, left out of an allowlist or disabled is still SKIPPED, because nothing
selected it. An image scan's report therefore says which scanners did not look, rather
than looking clean.

When *nothing* scanned the image -- no selected scanner declares the kind, or
no engine is present on an offline host -- the report carries one
informational SARIF result (`kind=informational`, `level=note`, rule
`ASH-container-image-not-scanned`) naming the image. It is information, not a finding:
it never grades, never fails a threshold and never lands in a SIEM as a vulnerability,
so an offline CI run stays green by contract and visibly incomplete rather than
silently clean.

## Engine delegation

At scan start ASH detects what can prepare the image, in this order: the docker daemon
(`DOCKER_HOST` if set, else the platform's default socket), then podman, then none.
With a daemon present, one pull serves every scanner -- the engine's content store is
the dedup. With no engine and network allowed, the tools' own registry clients fetch,
each into its own cache. With no engine and no network, the image portion of the scan
is skipped as described above. The direct-payload shapes (`--image-archive`,
`--image-layout`, and the MCP archive upload) need no engine and no network at all,
which is what air-gapped hosts use.

containerd is reached only through a tool's own options and is never probed by ASH.

trivy reads a reference or a saved archive, not an OCI layout directory, so for
`--image-layout` ASH re-packs the layout as a docker-archive tarball in a temporary file
of the scan's own, in pure Python, and gives trivy that archive. The layout is only read.
A layout whose layers are compressed any way but gzip is reported with the layer named.

### Tag-only references and their digest

A reference that already carries its digest (`repo@sha256:...`) needs no lookup. For a
tag-only reference (`repo:tag`) ASH resolves the digest once at scan start, trying two
rungs in order and stopping at the first that answers:

1. **The local engine.** ASH asks the detected docker or podman daemon, over its unix
   socket, for the image's inspect record and takes the `RepoDigests` entry of the
   reference's own repository (Docker Hub names are normalized), else the image ID. This
   works offline and fetches nothing, but only for an image the engine already holds.
2. **The registry.** `crane digest <ref>`, a registry request for the manifest's digest
   that needs no engine and fetches no layer. `crane` is a pinned tool like grype, and
   the container image carries it. It is skipped when ASH is offline (`--offline`,
   `ASH_OFFLINE`) or `crane` is not installed.

The digest is recorded for the scan, so finding ids and the scan's identity scope key on
it, and one log line names the rung that answered. Ids stay the same when the tag is moved
to another name and change when the tag moves to a different image; a re-tagged image
therefore never archives or overwrites the findings of the image it replaced. Only when
every rung fails do the ids and the scope key on the reference text; ASH then logs one
warning that lists why each rung failed, and the scan itself is never failed or skipped by
it. A reference that begins with `-` is refused before any rung runs.

## Over the MCP server

The MCP server carries both shapes beside its git and zip channels:

- `set_source_image` records a reference on the session; nothing is fetched at
  delivery time.
- `set_source_image_archive_chunk` + `set_source_image_archive_finalize` upload a
  saved image in the zip channel's exact shape: ordered base64 chunks of at most
  1 MiB, a SHA-256 verified at finalize, the same size caps -- and no extraction,
  because the archive is one file the scanner tools read whole.

One session has one subject and the latest delivery wins. `run_ash_scan` with no
`source_dir` scans the delivered image; its output tree goes under the session's own
workspace, since an image has no target directory. See
[Run the MCP server](mcp-server.md).

## Findings, identity and suppressions

A finding inside an image keeps its in-image path as `file_path`, exactly as the tool
reports it (`/usr/lib/libssl.so.3`, not a host path), so a suppression `path` matches it
as written. Three attribution columns say which image it came from:

| Column | Meaning |
|---|---|
| `image_ref` | The image as submitted: the reference, or the archive or layout path. |
| `image_digest` | The image's sha256 digest, when there is one: the tool's own run output (trivy records the image ID), else the digest the lookup ladder resolved for a tag-only reference (the local engine, then `crane digest`; see above), else the digest a pinned reference (`repo@sha256:...`) states. Empty only when every rung failed. |
| `layer_digest` | The digest of the layer the finding comes from, for trivy findings. trivy's SARIF carries no layer data, so ASH runs trivy once more with JSON output, joins each result to the SARIF by finding (vulnerability: CVE and package; secret: rule, target and start line; misconfiguration: check ID and target), and writes the layer's `Digest`, else its `DiffID`. A finding two layers both report, or one the JSON pass cannot match, stays empty. If the second pass fails the scan still succeeds with the column empty. syft reports no findings and grype's output has no layer data, so their findings carry none. Attribution only. |

A finding's id keys on the in-image path and the image's digest, or on the submitted
reference when there is no digest. Pin the reference by digest when ids must survive a
tag moving. Two scans of one pinned image therefore agree
across machines and output directories, a re-tagged image that resolves to the same
digest keeps its ids, and an image finding never shares an id with a source finding at
the same path. The layer digest is not part of the id: a rebuilt layer that still
carries the same vulnerable file at the same path is the same finding.

To scope a suppression to one image, add `image`, a case-insensitive glob matched
against the submitted reference and the resolved digest:

```yaml
global_settings:
  suppressions:
    - path: /usr/lib/**
      rule_id: CVE-2024-*
      image: registry.example.com/team/app:*
      reason: Base image CVE, fixed in the next rebuild
```

A suppression without `image` applies to any finding, image or filesystem, as before.
One with `image` never applies to a filesystem finding.

`ignore_paths` filters image findings by the in-image path, through the same matcher as a
directory scan and after the scan, like a suppression: an entry names the path as the tool
reports it, leading slash included (`/usr/share/doc/`), and a finding whose every location
is under one is dropped. The directory the scan was started from only anchors it, so no
path is read relative to it. That filter always runs. Where the tool can also be told to
skip the path, ASH passes it as well, so the tool does less work:

| Tool | What ASH passes | Notes |
|---|---|---|
| trivy | `trivy --skip-files <glob>` per entry | Measured on trivy 0.76.2: `trivy --skip-dirs` removed nothing from an image scan in any spelling, so it is not used. A path with no glob becomes the path and `<path>/**`. |
| grype | `--exclude <glob>` per entry | Absolute in-image globs only; the `./` spelling matches nothing. |
| syft | `--exclude <glob>` per entry | Same rule as grype. |

Only an entry that starts with `/` or `**` is translated. A relative pattern, a glob that
ends in `/`, a pattern that names no path, and one holding a newline, carriage return or
NUL are left to the report filter alone, and ASH logs one line saying so; at most 200
globs are passed to a tool. `--changed-files-only` has no meaning for an image and is
warned about once, as above. The convert phase stays filesystem-only.

## Tests never pull

ASH's own test fixtures build OCI layout directories and a small saved-image archive from
scratch; no third-party image is pulled by a test, and no engine is required for CI. One
integration test runs the real trivy over that committed archive, and over the same image
re-packed as an OCI layout, and checks that it finds the token the image holds; further
integration tests run the real trivy and syft over it for layer digests and ignore paths,
and the digest ladder against a real unix-socket daemon.

One CI job (`ash-image-scan-live-engine.yml`) covers the live engine and registry. It
builds a small image, pushes it to a local registry container (both base and registry
images pinned by digest from the public.ecr.aws gallery), scans it by tag, and requires
the report's scope to key on the digest the registry holds: once while the engine holds
the image (the engine rung) and once after the image is removed from the engine (the
registry rung).

## Limits that remain

- Only grype, syft and trivy read images. Every other scanner is filesystem-only and is
  reported SKIPPED for an image scan.
- `layer_digest` is filled for trivy findings only.
- `--baseline`, shards, `--staged` and convert-only are refused with an image, as above.
- Ignore paths reach the tools as absolute in-image globs only; relative patterns and
  globs ending in `/` are applied by the report filter after the scan, and trivy gets
  `trivy --skip-files` only because `trivy --skip-dirs` has no effect on images.
- The engine rung needs a docker or podman daemon socket; containerd is never probed.
- The live-engine CI job exercises docker on a Linux runner; podman and other platforms
  rely on unit tests and the unix-socket fake daemon.
