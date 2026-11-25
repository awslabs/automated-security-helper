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

```bash
# An indirect reference: resolved by an engine or the tools' own registry clients.
ash scan --image registry.example.com/team/app:1.2.3

# A saved image you already hold: an uncompressed `docker save` tarball.
docker save registry.example.com/team/app:1.2.3 -o app.tar
ash scan --image-archive app.tar

# An OCI image-layout directory (the directory holding the oci-layout marker file).
ash scan --image-layout ./app-layout/
```

Prefer a digest-pinned reference (`repo@sha256:...`): two scans of the same pinned
image then agree across machines. A tag-only reference is accepted and handed to the
tool as written, and ASH asks the registry which digest the tag points at (see
[Tag-only references](#tag-only-references-and-their-digest)) so its finding ids key on
that digest; where that lookup cannot run, the ids key on the reference text.

**Current status.** grype, syft and trivy are the scanners that read images; every other
scanner is filesystem-only and is reported SKIPPED. ASH detects an engine (below) to pick
how the tools reach the image, and an image scan is only as complete as those three
tools' own coverage.

The two payload shapes are checked at the stat level before anything uses them, the way
a source directory is: the archive must exist, be readable and carry tar magic (a
gzip-compressed archive is refused with the remedy -- save it uncompressed, which is
what `docker save` writes); the layout must be an enterable directory holding the
`oci-layout` marker file. What is *inside* passes to the scanner tools, which report
malformed images themselves.

Image options run in local mode, single-directory, on a fresh scan: they cannot be
combined with any other `--mode` (container, nix and precommit are refused), a workspace
scan, `--use-existing`, `--staged`, `--baseline` or a shard (`--shard-index`,
`--shard-count`). The convert phase does not run (converters read source files, which an
image presents none of), so asking for the convert phase alone is refused. The scan
records the image, not the directory it was started from, as its scan source, and does
not walk that directory.

`--changed-files-only` scopes a scan by git history, and an image has no diff base, so it
means nothing there. It is not refused: ASH warns once that it has no meaning for an image
scan and scans the whole image.

**One subject per scan, by design.** A scan reports on one asset, and each image keeps its
own report, its own identity scope (`image_ref`, `image_digest`) and its own exit code.
To scan several images, call ASH once per image and loop in the caller; the reports are not
merged, so no finding of one image can be attributed to another.

## Which scanners look at the image

Capability lives in one place: a scanner's operational-facets register row. A scanner
serves container images exactly when its row declares the `container_image` target
kind; every other scanner -- and every third-party plugin that predates the register --
is reported **SKIPPED** for an image scan, with a row naming the declaration, before
its tool or dependencies are ever probed. A filesystem-only scanner whose constructor
raises is SKIPPED the same way. A module that fails to import is still reported as an
error, because without the class ASH cannot tell whether it would have read the image.
An image scan's report therefore says which scanners did not look, rather than looking
clean.

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

For a tag-only reference (`repo:tag`) ASH runs `crane digest <ref>` once at scan start, a
registry request for the manifest's digest that needs no engine and fetches no layer.
`crane` is a pinned tool like grype, and the container image carries it. The digest it prints is recorded for the scan, so finding ids
key on it: they stay the same when the tag is moved to another name and change when the tag
moves to a different image.

The lookup is skipped, and the ids key on the reference text exactly as before, when the
reference already carries its digest (no notice: nothing is missing), when ASH is offline
(`--offline`, `ASH_OFFLINE`), when `crane` is not installed, and when the registry answers
with an error. Each of those three cases logs one notice naming the fallback; the scan
itself is never failed or skipped by it. Pin the reference by digest for ids that need no lookup at all.

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
| `image_digest` | The image's sha256 digest, when there is one: the tool's own run output (trivy records the image ID), else the digest the registry gave for a tag-only reference (`crane digest`, above), else the digest a pinned reference (`repo@sha256:...`) states. Empty only when the lookup could not run (offline, no `crane`, a registry error). |
| `layer_digest` | Empty today. No wired tool writes a per-result layer digest into its SARIF, so the column stays empty until one does; a tool (or a plugin's post-process) that writes the `layerDigest` result property fills it with no further change. Attribution only. |

A finding's id keys on the in-image path and the image's digest, or on the submitted
reference when there is no digest. Pin the reference by digest when ids must survive
without a registry lookup. Two scans of one pinned image therefore agree
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
path is read relative to it. Because the tool is handed the whole image, an ignore path
leaves findings out of the report but never saves the tool any work.
`--changed-files-only` has no meaning for an image and is warned about, as above.

## Tests never pull

ASH's own test fixtures build OCI layout directories and a small saved-image archive from
scratch; no third-party image is pulled by a test, and no engine is required for CI. One
integration test runs the real trivy over that committed archive, and over the same image
re-packed as an OCI layout, and checks that it finds the token the image holds. A live
container engine or registry read is the part CI does not cover: those paths are tested
with fakes.
