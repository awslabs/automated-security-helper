#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fetch, verify and hand over the Dockerfile's base image as an OCI image layout.

WHY THIS EXISTS

The container legs used to pull the base image from a registry on every run. Once a shared
runner egress address has spent ECR Public's anonymous 500 GB/month, even a manifest lookup is
refused (`failed to resolve source metadata ... 429 ... Data limit exceeded`), so the only
dependable number of registry calls for a warm run is zero. The pre-pull action therefore keeps
the base image in the Actions cache as an OCI image layout and hands that layout to the build.

A layout rather than a `docker save` tar, because a layout is content-addressed: every blob is
named by its own sha256, so what was restored can be checked against the Dockerfile's pinned
index digest before anything uses it. A `docker save` tar holds uncompressed layers and
runtime-generated manifests whose digests no registry ever served, so there is nothing in it to
check against the pin.

SUBCOMMANDS

  key     print the cache key: tag, pin and runner arch, all read locally, no network
  fetch   download the pinned index, this arch's manifest, its config and its layers from a
          registry into a fresh layout, verifying every digest while downloading
  verify  check a restored layout end to end and print the arch manifest digest it holds
  docker-archive
          write a `docker load`-able tar of this arch's image to stdout, tagged as given

Only the standard library is used, because this runs on the runner's system python before any
project dependency is installed.

WHAT VERIFY GUARANTEES, AND WHAT IT DOES NOT

It guarantees the bytes handed to the build are exactly the bytes the pin names: the index blob
hashes to the pin, the manifest it selects for this arch is present and hashes to its
descriptor, and the config and every layer that manifest lists are present and hash to theirs.
Everything else in the layout is either checked the same way or refused -- a file outside
`blobs/sha256`, a symlink anywhere, a blob whose name is not its hash.

It does not establish that the pin is the right image; that is ARG BASE_IMAGE_DIGEST's job, and
the pull path's tag-versus-pin comparison is what keeps that line honest when the tag moves.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

INDEX_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
MANIFEST_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)
REF_NAME = "org.opencontainers.image.ref.name"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
# GitHub's closed set for RUNNER_ARCH, mapped to OCI platform fields. A variant of None means
# "any variant": the python index lists arm64 with variant v8, which is the only arm64 variant
# in practice, and pinning one here would refuse a correct index that omits the field.
RUNNER_ARCHES = {
    "X64": ("amd64", None),
    "ARM64": ("arm64", None),
    "ARM": ("arm", "v7"),
    "X86": ("386", None),
}
# The cache key's version prefix. Bump it when the layout's shape changes (for example what
# index.json lists), so an old entry is never restored into a consumer that expects a new one.
KEY_PREFIX = "ash-base-image-oci-v1"
HTTP_TIMEOUT = 60
CHUNK = 1 << 20


class LayoutError(Exception):
    """A layout, registry answer or argument that must not be used."""


# --------------------------------------------------------------------------- shared helpers


def _dockerfile_arg(dockerfile: Path, name: str) -> str:
    """The first `ARG <name>=` default in the Dockerfile, as the pull step reads it."""
    prefix = f"ARG {name}="
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    raise LayoutError(f"no '{prefix}' line in {dockerfile}")


def _platform(runner_arch: str) -> tuple[str, str | None]:
    try:
        return RUNNER_ARCHES[runner_arch]
    except KeyError:
        raise LayoutError(
            f"RUNNER_ARCH is '{runner_arch}', which is not one of {sorted(RUNNER_ARCHES)}"
        ) from None


def _check_digest(value: str, what: str) -> str:
    if not DIGEST_RE.match(value or ""):
        raise LayoutError(
            f"{what} is '{value}', which is not sha256:<64 lowercase hex>"
        )
    return value


def _select_manifest(index: dict, runner_arch: str) -> dict:
    """The one linux manifest for this arch that the index lists, or an error."""
    arch, variant = _platform(runner_arch)
    matches = []
    for desc in index.get("manifests") or []:
        plat = desc.get("platform") or {}
        if plat.get("os") != "linux" or plat.get("architecture") != arch:
            continue
        if variant is not None and plat.get("variant") not in (None, variant):
            continue
        matches.append(desc)
    if len(matches) != 1:
        raise LayoutError(
            f"the pinned index lists {len(matches)} linux/{arch} manifest(s); exactly one is "
            "required to know which image this runner builds from"
        )
    desc = matches[0]
    _check_digest(desc.get("digest", ""), "the arch manifest digest")
    if desc.get("mediaType") not in MANIFEST_TYPES:
        raise LayoutError(
            f"the linux/{arch} entry has mediaType '{desc.get('mediaType')}', not an image "
            "manifest"
        )
    return desc


def _blob_path(layout: Path, digest: str) -> Path:
    return layout / "blobs" / "sha256" / digest.split(":", 1)[1]


def _read_json_blob(layout: Path, desc: dict, what: str) -> dict:
    path = _blob_path(layout, desc["digest"])
    if not path.is_file():
        raise LayoutError(f"{what} {desc['digest']} is not in the layout")
    data = path.read_bytes()
    if "size" in desc and len(data) != desc["size"]:
        raise LayoutError(
            f"{what} {desc['digest']} is {len(data)} bytes; its descriptor says {desc['size']}"
        )
    try:
        return json.loads(data)
    except ValueError as exc:
        raise LayoutError(f"{what} {desc['digest']} is not JSON: {exc}") from exc


def _image_blobs(manifest: dict) -> list[dict]:
    config = manifest.get("config")
    layers = manifest.get("layers")
    if not isinstance(config, dict) or not isinstance(layers, list) or not layers:
        raise LayoutError("the arch manifest has no config or no layers")
    return [config, *layers]


# --------------------------------------------------------------------------- key


def cache_key(dockerfile: Path, runner_arch: str) -> str:
    """Tag, pin and runner arch. No network, so restore can run before anything else."""
    base = _dockerfile_arg(dockerfile, "BASE_IMAGE")
    pin = _check_digest(
        _dockerfile_arg(dockerfile, "BASE_IMAGE_DIGEST"), "ARG BASE_IMAGE_DIGEST"
    )
    _platform(runner_arch)
    if "@" in base or ":" not in base.rsplit("/", 1)[-1]:
        raise LayoutError(f"ARG BASE_IMAGE is '{base}', which is not repository:tag")
    tag = base.rsplit(":", 1)[1]
    if not re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$", tag):
        raise LayoutError(f"the tag '{tag}' is not a valid image tag")
    return f"{KEY_PREFIX}-{tag}-{pin}-{runner_arch}"


# --------------------------------------------------------------------------- verify


def verify(layout: Path, pin: str, runner_arch: str) -> str:
    """Check the layout end to end; return the arch manifest digest it holds.

    Raises LayoutError on anything that is not exactly what the pin names.
    """
    _check_digest(pin, "the pin")
    if layout.is_symlink() or not layout.is_dir():
        raise LayoutError(f"{layout} is not a directory")

    allowed_top = {"oci-layout", "index.json", "blobs"}
    for entry in layout.iterdir():
        if entry.name not in allowed_top:
            raise LayoutError(
                f"unexpected entry '{entry.name}' at the top of the layout"
            )

    try:
        marker = json.loads((layout / "oci-layout").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LayoutError(f"oci-layout is missing or unreadable: {exc}") from exc
    if marker.get("imageLayoutVersion") != "1.0.0":
        raise LayoutError(f"oci-layout says {marker!r}, not imageLayoutVersion 1.0.0")

    blobs = layout / "blobs"
    if blobs.is_symlink() or not blobs.is_dir():
        raise LayoutError("blobs/ is missing or not a plain directory")
    for entry in blobs.iterdir():
        if entry.name != "sha256":
            raise LayoutError(f"unexpected entry 'blobs/{entry.name}'")
    sha_dir = blobs / "sha256"
    if sha_dir.is_symlink() or not sha_dir.is_dir():
        raise LayoutError("blobs/sha256 is missing or not a plain directory")

    # Every blob, not only the ones the image uses: a layout carrying an extra file whose name
    # is not its hash is a layout something other than this script wrote.
    present: dict[str, int] = {}
    for entry in sha_dir.iterdir():
        mode = entry.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise LayoutError(f"blobs/sha256/{entry.name} is not a regular file")
        if not HEX_RE.match(entry.name):
            raise LayoutError(f"blobs/sha256/{entry.name} is not named by a sha256")
        digest = hashlib.sha256()
        size = 0
        with entry.open("rb") as handle:
            for chunk in iter(lambda: handle.read(CHUNK), b""):
                digest.update(chunk)
                size += len(chunk)
        if digest.hexdigest() != entry.name:
            raise LayoutError(
                f"blobs/sha256/{entry.name} hashes to sha256:{digest.hexdigest()}; a blob's "
                "name must be its own digest"
            )
        present[f"sha256:{entry.name}"] = size

    if pin not in present:
        raise LayoutError(f"the pinned index {pin} is not in the layout")
    index = _read_json_blob(layout, {"digest": pin}, "the pinned index")
    if index.get("mediaType") not in INDEX_TYPES:
        raise LayoutError(
            f"the pinned blob {pin} has mediaType '{index.get('mediaType')}', not an image index"
        )

    mdesc = _select_manifest(index, runner_arch)
    manifest = _read_json_blob(layout, mdesc, "the arch manifest")
    if manifest.get("mediaType", mdesc["mediaType"]) not in MANIFEST_TYPES:
        raise LayoutError("the arch manifest is not an image manifest")
    for desc in _image_blobs(manifest):
        digest = _check_digest(desc.get("digest", ""), "a config or layer digest")
        if digest not in present:
            raise LayoutError(
                f"blob {digest} named by the arch manifest is not in the layout"
            )
        if present[digest] != desc.get("size"):
            raise LayoutError(
                f"blob {digest} is {present[digest]} bytes; the manifest says {desc.get('size')}"
            )

    # index.json is what podman's `oci:` transport and nerdctl's oci-layout context read, so it
    # has to point at the verified objects and nothing else.
    try:
        top = json.loads((layout / "index.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LayoutError(f"index.json is missing or unreadable: {exc}") from exc
    listed = top.get("manifests") or []
    listed_digests = [d.get("digest") for d in listed]
    if sorted(listed_digests) != sorted([pin, mdesc["digest"]]):
        raise LayoutError(
            f"index.json lists {listed_digests}; it must list exactly the pinned index and the "
            f"arch manifest ({pin}, {mdesc['digest']})"
        )
    for desc in listed:
        if present.get(desc["digest"]) != desc.get("size"):
            raise LayoutError(
                f"index.json's size for {desc['digest']} does not match the blob"
            )
    return mdesc["digest"]


# --------------------------------------------------------------------------- fetch


class _StripAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Blob downloads redirect to a CDN or a presigned object URL on another host.

    urllib forwards every header to the redirect target, and a presigned URL refuses a request
    that also carries a bearer token. The token is only for the registry host, so it is dropped
    whenever the redirect leaves that host.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            old_host = urllib.parse.urlsplit(req.full_url).netloc
            if urllib.parse.urlsplit(newurl).netloc != old_host:
                new.remove_header("Authorization")
        return new


_OPENER = urllib.request.build_opener(_StripAuthOnRedirect)


def _split_repo(repo: str) -> tuple[str, str]:
    host, _, name = repo.partition("/")
    if not name or "." not in host:
        raise LayoutError(f"'{repo}' is not host/name")
    if host == "docker.io":
        host = "registry-1.docker.io"
    return host, name


def _bearer_token(host: str, name: str) -> str | None:
    """Anonymous pull token, from whatever realm the registry's challenge names."""
    try:
        _OPENER.open(f"https://{host}/v2/", timeout=HTTP_TIMEOUT).close()
        return None
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise
        challenge = exc.headers.get("WWW-Authenticate", "")
    if not challenge.lower().startswith("bearer "):
        raise LayoutError(
            f"{host} answered 401 without a bearer challenge: {challenge!r}"
        )
    params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    realm = params.get("realm")
    if not realm:
        raise LayoutError(f"{host}'s challenge names no realm: {challenge!r}")
    query = {"scope": f"repository:{name}:pull"}
    if params.get("service"):
        query["service"] = params["service"]
    url = f"{realm}?{urllib.parse.urlencode(query)}"
    with _OPENER.open(url, timeout=HTTP_TIMEOUT) as resp:
        body = json.loads(resp.read())
    token = body.get("token") or body.get("access_token")
    if not token:
        raise LayoutError(f"{host}'s token endpoint returned no token")
    return token


def _get(url: str, token: str | None, accept: str | None = None):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if accept:
        req.add_header("Accept", accept)
    return _OPENER.open(req, timeout=HTTP_TIMEOUT)


def _download(url: str, token: str | None, digest: str, dest: Path, accept=None) -> int:
    """Stream to dest, refusing the bytes unless they hash to digest."""
    hasher = hashlib.sha256()
    size = 0
    tmp = dest.with_name(dest.name + ".partial")
    with _get(url, token, accept) as resp, tmp.open("wb") as out:
        for chunk in iter(lambda: resp.read(CHUNK), b""):
            hasher.update(chunk)
            size += len(chunk)
            out.write(chunk)
    got = f"sha256:{hasher.hexdigest()}"
    if got != digest:
        tmp.unlink()
        raise LayoutError(f"{url} served {got}, not {digest}")
    tmp.replace(dest)
    return size


def _fetch_from(repo: str, pin: str, runner_arch: str, work: Path) -> None:
    host, name = _split_repo(repo)
    token = _bearer_token(host, name)
    sha_dir = work / "blobs" / "sha256"
    sha_dir.mkdir(parents=True)
    accept = ", ".join(sorted(INDEX_TYPES | MANIFEST_TYPES))
    base = f"https://{host}/v2/{name}"

    index_size = _download(
        f"{base}/manifests/{pin}", token, pin, _blob_path(work, pin), accept
    )
    index = json.loads(_blob_path(work, pin).read_bytes())
    if index.get("mediaType") not in INDEX_TYPES:
        raise LayoutError(
            f"{pin} on {repo} is '{index.get('mediaType')}', not an image index"
        )
    mdesc = _select_manifest(index, runner_arch)
    mdigest = mdesc["digest"]
    _download(
        f"{base}/manifests/{mdigest}", token, mdigest, _blob_path(work, mdigest), accept
    )
    manifest = json.loads(_blob_path(work, mdigest).read_bytes())
    for desc in _image_blobs(manifest):
        digest = _check_digest(desc.get("digest", ""), "a config or layer digest")
        _download(f"{base}/blobs/{digest}", token, digest, _blob_path(work, digest))

    (work / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}', encoding="utf-8")
    top = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            # The pinned index, so the layout carries the object the pin names and podman's
            # `oci:` transport can select this runner's platform out of it, exactly as a
            # registry pull would.
            {
                "mediaType": index["mediaType"],
                "digest": pin,
                "size": index_size,
                "annotations": {REF_NAME: "index"},
            },
            # The arch manifest, LAST, because nerdctl's `--build-context name=oci-layout://DIR`
            # takes the last image-manifest-typed entry of index.json as the image and has no
            # way to be told a digest (pkg/cmd/builder/build.go, parseBuildContextFromOCILayout,
            # identical at v2.2.2 and v2.3.5).
            {
                "mediaType": mdesc["mediaType"],
                "digest": mdigest,
                "size": mdesc["size"],
                "platform": mdesc.get("platform"),
                "annotations": {REF_NAME: "image"},
            },
        ],
    }
    (work / "index.json").write_text(json.dumps(top, indent=2), encoding="utf-8")


def fetch(repos: list[str], pin: str, runner_arch: str, out: Path) -> str:
    """Write a verified layout to out, trying each registry in turn. Returns the manifest digest.

    Every registry is asked for the pin by digest, so which one answers cannot change the bytes;
    a second registry is only a second chance at being served.
    """
    _check_digest(pin, "the pin")
    if out.exists():
        raise LayoutError(f"{out} already exists; refusing to write over it")
    errors = []
    for repo in [r for r in repos if r]:
        work = Path(tempfile.mkdtemp(prefix=".oci-layout-", dir=out.parent))
        try:
            _fetch_from(repo, pin, runner_arch, work)
            digest = verify(work, pin, runner_arch)
            work.replace(out)
            return digest
        except (LayoutError, OSError, ValueError, urllib.error.URLError) as exc:
            errors.append(f"{repo}: {exc}")
            shutil.rmtree(work, ignore_errors=True)
    raise LayoutError("no registry served a verifiable layout: " + "; ".join(errors))


# --------------------------------------------------------------------------- docker-archive


def docker_archive(layout: Path, pin: str, runner_arch: str, tag: str, stream) -> None:
    """A tar `docker load` accepts, holding only this arch's config and layers.

    Verifies first, so the bytes loaded are the bytes verify vouched for. The classic docker
    store reads `manifest.json` and decompresses gzip layers itself, so the registry's
    compressed blobs go in unchanged and the image id it records is the config digest -- the
    same id a registry pull of the pin produces.
    """
    mdigest = verify(layout, pin, runner_arch)
    manifest = json.loads(_blob_path(layout, mdigest).read_bytes())
    config, *layers = _image_blobs(manifest)
    member = lambda d: "blobs/sha256/" + d["digest"].split(":", 1)[1]  # noqa: E731
    docker_manifest = [
        {
            "Config": member(config),
            "RepoTags": [tag],
            "Layers": [member(layer) for layer in layers],
        }
    ]
    payload = json.dumps(docker_manifest).encode("utf-8")
    with tarfile.open(fileobj=stream, mode="w|") as tar:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(payload)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(payload))
        for desc in [config, *layers]:
            tar.add(
                _blob_path(layout, desc["digest"]),
                arcname=member(desc),
                recursive=False,
            )


# --------------------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_key = sub.add_parser("key")
    p_key.add_argument("--dockerfile", type=Path, required=True)
    p_key.add_argument("--arch", required=True)

    p_fetch = sub.add_parser("fetch")
    p_fetch.add_argument("--repo", action="append", required=True)
    p_fetch.add_argument("--pin", required=True)
    p_fetch.add_argument("--arch", required=True)
    p_fetch.add_argument("--out", type=Path, required=True)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--dir", type=Path, required=True)
    p_verify.add_argument("--pin", required=True)
    p_verify.add_argument("--arch", required=True)

    p_archive = sub.add_parser("docker-archive")
    p_archive.add_argument("--dir", type=Path, required=True)
    p_archive.add_argument("--pin", required=True)
    p_archive.add_argument("--arch", required=True)
    p_archive.add_argument("--tag", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "key":
            print(cache_key(args.dockerfile, args.arch))
        elif args.command == "fetch":
            print(fetch(args.repo, args.pin, args.arch, args.out))
        elif args.command == "verify":
            print(verify(args.dir, args.pin, args.arch))
        else:
            docker_archive(args.dir, args.pin, args.arch, args.tag, sys.stdout.buffer)
    except LayoutError as exc:
        print(f"oci_layout.py {args.command}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
