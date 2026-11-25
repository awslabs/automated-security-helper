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
image then agree across machines. A tag-only reference is accepted and resolved to a
digest at scan start where an engine is present.

The two payload shapes are checked at the stat level before anything uses them, the way
a source directory is: the archive must exist, be readable and carry tar magic (a
gzip-compressed archive is refused with the remedy -- save it uncompressed, which is
what `docker save` writes); the layout must be an enterable directory holding the
`oci-layout` marker file. What is *inside* passes to the scanner tools, which report
malformed images themselves.

Image options run in local mode, single-directory, on a fresh scan: they cannot be
combined with `--mode container`, a workspace scan, `--use-existing` or
`--changed-files-only`, and the convert phase does not run (converters read source
files, which an image presents none of).

## Which scanners look at the image

Capability lives in one place: a scanner's operational-facets register row. A scanner
serves container images exactly when its row declares the `container_image` target
kind; every other scanner -- and every third-party plugin that predates the register --
is reported **SKIPPED** for an image scan, with a row naming the declaration, before
its tool or dependencies are ever probed. An image scan's report therefore says which
scanners did not look, rather than looking clean.

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

`run_ash_scan` takes an `execution` argument: `auto` and `in_process` run the scan in
the server's own process, and `express` asks for the express daemon. The server answers
`express` with the in-process run today, because the daemon takes over the client's
standard streams, which on the server are the JSON-RPC transport, and the session's
sandbox restrictions have no command-line form. The response's `execution_used` says
which path ran.

## Findings, identity and suppressions

A finding inside an image keeps its in-image path as `file_path`, exactly as the tool
reports it (`/usr/lib/libssl.so.3`, not a host path), so a suppression `path` matches it
as written. Three attribution columns say which image it came from:

| Column | Meaning |
|---|---|
| `image_ref` | The image as submitted: the reference, or the archive or layout path. |
| `image_digest` | The image's sha256 digest, when there is one: the tool's own run output (trivy records the image ID), else the digest a pinned reference (`repo@sha256:...`) states. A tag-only reference scanned by a tool that reports no digest (grype, syft) has none. |
| `layer_digest` | The layer that introduced the finding, for a scanner that reports one. Attribution only. |

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
One with `image` never applies to a filesystem finding. `ignore_paths` and
`--changed-files-only` stay filesystem-only: there is no directory walk inside an image.

## Tests never pull

ASH's own test fixtures build OCI layout directories from scratch; no third-party
image is pulled by a test, and no engine is required for CI.
