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

# A saved image you already hold: an uncompressed `docker save` or
# `podman save` tarball (either archive format; ASH reads which it is).
docker save registry.example.com/team/app:1.2.3 -o app.tar
ash scan --image-archive app.tar

# An OCI image-layout directory (the directory holding the oci-layout marker file).
ash scan --image-layout ./app-layout/
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
scan, `--use-existing`, `--baseline`, the git-history scopes (`--changed-files-only`,
`--staged`) or a shard (`--shard-index`, `--shard-count`). The same rules bind a library
call through `run_ash_scan`, not only the CLI. The convert phase does not run
(converters read source files, which an image presents none of), so asking for the
convert phase alone is refused. The scan records the image, not the directory it was
started from, as its scan source, and does not walk that directory; in-image paths are
reported as the tool wrote them and are never rebased into the host tree. A requested
`--sandbox` is refused for an image scan: the sandbox's read scope is built from the
source tree, which holds neither an image payload nor an engine socket.

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
(`DOCKER_HOST` of any transport if set -- `tcp://`, `ssh://` and `npipe://` count as
declared daemons -- else the platform's default socket), then podman (`CONTAINER_HOST`,
then its sockets), then none. Docker *contexts* are not read: a daemon reachable only
through one (Colima, OrbStack, Docker Desktop without the default socket) counts once
`DOCKER_HOST` names it. With a daemon present, one pull serves every scanner -- the
engine's content store is the dedup; trivy is told
`--image-src=<engine>,remote`, so an image the daemon does not hold still scans from
the registry. With no engine and network allowed, the tools' own registry clients
fetch, each into its own cache.

In `--offline` mode a *reference* is always skipped, engine or no engine: a daemon
asked for an image it does not hold pulls it from the registry, and the tools' own
registry clients always fetch, so offline's no-network promise cannot be kept for any
ref. The direct-payload shapes (`--image-archive`, `--image-layout`, and the MCP
archive upload) need no engine and no network at all, which is what air-gapped and
offline hosts use.

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

## Findings, identity and suppressions

A finding inside an image keeps its in-image path as `file_path`, exactly as the tool
reports it (`/usr/lib/libssl.so.3`, not a host path), so a suppression `path` matches it
as written. Three attribution columns say which image it came from:

| Column | Meaning |
|---|---|
| `image_ref` | The image as submitted: the reference, or the archive or layout path. |
| `image_digest` | The image's sha256 **manifest digest**, when one is named, read from these sources in order: the tool's own run output (trivy records `repoDigests`; its config-blob `imageID` is used only when no repo digest exists, as for a locally built, never-pushed image), a digest the submitting caller already resolved, else the digest a pinned reference (`repo@sha256:...`) states. ASH never asks an engine or a registry for one, so a tag-only reference scanned by a tool that reports no digest (grype, syft) has none. |
| `layer_digest` | The layer that introduced the finding, for a scanner that reports one; the wired scanners' SARIF output does not today. Attribution only. |

**The id-stability contract.** A finding's id keys on the in-image path and the image's
digest; when no digest is named anywhere, it keys on the submitted reference. So:

- a **pinned reference** gives ids that agree across machines, output directories and
  scanners (the manifest digest is one value everywhere);
- a **tag with no resolvable digest** gives ids stable across rescans of that tag --
  until a scan names a digest, which re-keys the findings to the image's content;
- a **rebuild pushed to the same tag** is a new subject wherever a digest is named:
  its contents changed, and diffs showing old findings closed and new ones opened is
  the intended reading. Pin by digest when ids must survive a tag moving.

The layer digest is not part of the id: a rebuilt layer that still carries the same
vulnerable file at the same path is the same finding.

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
**That widens existing configs**: an entry written before image scans existed (say,
`path: "**"` with a CVE rule id, "not affected here") now also hides that CVE inside
every image this project scans. Review broad suppressions when you adopt image
scanning, or scope them with `image:`. One with `image` never applies to a filesystem
finding. Inline `ash-ignore` comments are never read for image findings (there is no
file to read them from), and `ignore_paths` and `--changed-files-only` stay
filesystem-only: there is no directory walk inside an image.

## Tests never pull

ASH's own test fixtures build OCI layout directories from scratch; no third-party
image is pulled by a test, and no engine is required for CI.
