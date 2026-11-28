# Syft SBOM scanner (`syft`) and the sdist lockfile harvest

[syft](https://github.com/anchore/syft) catalogs the packages in the scanned
directory into a CycloneDX SBOM, which ASH stores as the scan's one software
inventory and writes through the `cyclonedx` and `gitlab-cyclonedx` reporters.
The scanner produces no findings; the SBOM is the product. The full options
table is in the [scanner reference](../../../reference/scanners.md).

## The sdist lockfile harvest

A resolved Python dependency whose wheels carry a platform tag ships compiled
native extensions, and those can statically link another toolchain's packages
that no file in your tree describes. The measured case is polars: its runtime
wheel's shared library carries no cargo-auditable audit data, so no SBOM tool
can read the ~581 Rust crates it links from the installed artifact, while the
sdist your own `uv.lock` pins by sha256 ships the upstream workspace
`Cargo.lock` at its root.

ASH closes that gap in two rules, mature tools first:

1. Artifacts that carry audit data (cargo-auditable binaries, Go buildinfo) are
   read by syft's own catalogers in its ordinary pass. Nothing new runs for
   them.
2. Every `uv.lock` entry that names a platform wheel and pins its sdist by
   sha256 is autodetected, the sdist is fetched in online mode and verified
   against the pin before anything is extracted, and only the recognized
   embedded lockfiles (`Cargo.lock`, `go.sum`, `package-lock.json`) are
   materialized into the converted target under
   `sdist-locks/<package>/<version>/`. The pinned syft, grype and trivy then
   read them in the converted-target pass every scanner already runs, so the
   packages land in the SBOM and advisories against them are reported.

Where both rules report a package, the SBOM merge lists it once. The merge keys
a component by its `bom-ref`, and syft's cargo refs end in a package-id hash that
differs between runs, so a crate read in both passes has the same purl under two
refs. A harvested component (one carrying the `ash:sbom-harvest` properties) whose
purl is already listed is folded onto the listed component, and the dependency
entries that named it follow the listed component's ref.

The network statement, in one sentence: online mode only; a GET of the sdist
your own lockfile pins by sha256, bounded by `max_sdist_mb` on the bytes
actually streamed (not only on the lockfile's own size claim) and verified
before extraction; nothing fetched is executed. Offline (or on any refused
fetch: a hash mismatch, an oversize archive or transfer, an sdist with no
recognized lockfile), the affected packages are skipped and recorded as one
informational `ash-sbom-harvest-skipped` entry per cause in the converter's
results, so the SBOM's incompleteness is a visible fact. Verified harvests are
cached under `ash/sdist-harvest/` in the user-level cache directory
(`XDG_CACHE_HOME`, or `~/.cache`), keyed by each sdist's sha256 and with each
cached file's digest recorded beside it; a warmed cache serves entries offline
with no network, re-verifying every file against its recorded digest first and
evicting an entry that does not match. The cache never lives under the scanned
tree -- a directory the scanned repository could commit content into is not
used, whoever named it -- so a tree-shipped "cache" can never be served as a
verified harvest.

With the syft scanner disabled nothing is fetched. grype and trivy still read
the harvested lockfiles, so while either of them runs, the packages missing from
its input are named in an `ash-sbom-harvest-skipped` entry; with neither
running, the harvest records nothing.

```yaml
scanners:
  syft:
    options:
      sdist_harvest:
        # One line turns the harvest off; offline mode disables its fetches
        # either way.
        enabled: true
        # Which embedded lockfiles are harvested.
        ecosystems: ["cargo", "gomod", "npm"]
        # The largest sdist fetched: checked against the lockfile's recorded
        # size before the fetch, enforced on the streamed bytes during it.
        max_sdist_mb: 100
        # A persistent cache location (a CI cache volume). Defaults to
        # ash/sdist-harvest under the user-level cache directory; a directory
        # inside the scanned tree is never used. Operator-set only.
        cache_dir: null
        # The Python lockfiles walked. uv.lock pins each sdist by URL and
        # sha256, which is what authorizes a fetch.
        lockfiles: ["uv.lock"]
```

## Provenance of harvested components

Every SBOM component located under a harvest directory carries three CycloneDX
properties, so it is auditable back to the bytes that produced it:

<!-- doctest: config kind=other reason="one CycloneDX component of the SBOM ASH writes, not an ASH config" -->
```json
{
  "type": "library",
  "name": "rustls",
  "version": "0.23.43",
  "purl": "pkg:cargo/rustls@0.23.43",
  "properties": [
    {"name": "ash:sbom-harvest:sdist-sha256", "value": "b84842f7d621…"},
    {"name": "ash:sbom-harvest:parent-purl", "value": "pkg:pypi/polars-runtime-32@1.44.2"},
    {"name": "ash:sbom-harvest:source-url", "value": "https://files.pythonhosted.org/…/polars_runtime_32-1.44.2.tar.gz"}
  ]
}
```

A harvested lockfile is the upstream workspace's whole lockfile: an upper bound
on what the wheel links, to be read as the dependency tree of the parent
package. Findings against it are fixed by upgrading the parent package, never by
editing anything locally; ASH's own `.ash.yaml` carries worked examples of
time-boxed, evidence-carrying suppressions on harvested findings (the rustls
entries whose `path` globs over `sdist-locks/`). See
[Suppress findings](../../../how-to/suppress-findings.md).
