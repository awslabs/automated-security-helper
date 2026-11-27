# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tiny saved-image archive, built from nothing, and its OCI-layout re-pack.

No image is pulled and no engine is involved anywhere a test uses this. The
committed fixture ``tests/test_data/images/secret-image.tar`` is what
:func:`build_secret_image_archive` writes (its sha256 is recorded in the README
beside it, and a unit test holds the two equal); :func:`archive_to_layout`
turns that archive into an OCI image-layout directory, so the layout
submission shape is tested from the same committed bytes.

The image: one gzip-compressed layer holding ``app/creds.txt`` with a fake GitHub
token (assembled at build time, so this file holds no token-shaped string, and the
committed archive holds the token only as deflate output), a config naming the
uncompressed layer's diff id, and a ``docker save`` manifest. Every mtime is 0 and
every owner is root. The bytes are what one zlib writes; a different zlib may
deflate the same layer to other bytes, so the tests pin the committed file by its
recorded digest and the builder by the decompressed content, not by bytes.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Dict, List, Tuple

#: The fake token the fixture image's one file holds. trivy's secret scanner
#: reports it as ``github-pat``; secret scanning needs no vulnerability database.
FAKE_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6Q7r8"
IMAGE_TAG = "ash-fixture/secret-image:1"
IMAGE_FILE = "app/creds.txt"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tar_bytes(members: List[Tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def image_parts() -> Dict[str, object]:
    """The layer, config and manifest bytes with their digests."""
    layer = _tar_bytes([(IMAGE_FILE, f'token = "{FAKE_TOKEN}"\n'.encode("utf-8"))])
    layer_hex = _sha256(layer)
    # The layer is stored gzip-compressed, as a registry serves it, which also
    # keeps the token's text out of the committed bytes: a repository scan of the
    # archive reads deflate output, not a token-shaped string. The config's diff
    # id names the UNCOMPRESSED layer, as the image spec says.
    layer_gz = gzip.compress(layer, compresslevel=9, mtime=0)
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {"Cmd": ["/bin/true"]},
            "rootfs": {"type": "layers", "diff_ids": [f"sha256:{layer_hex}"]},
            "history": [{"created": "1970-01-01T00:00:00Z", "created_by": "fixture"}],
        },
        sort_keys=True,
    ).encode("utf-8")
    return {
        "layer": layer,
        "layer_gz": layer_gz,
        "layer_hex": layer_hex,
        "config": config,
        "config_hex": _sha256(config),
    }


def build_secret_image_archive(destination: Path, *, compress: bool = True) -> Path:
    """Write the docker-archive fixture to *destination* and return it.

    *compress* False stores the layer uncompressed, as ``docker save`` does, for a
    test that needs both shapes of one image.
    """
    parts = image_parts()
    config_name = f"{parts['config_hex']}.json"
    layer_name = f"{parts['layer_hex']}/layer.tar"
    listing = [{"Config": config_name, "RepoTags": [IMAGE_TAG], "Layers": [layer_name]}]
    members = [
        (config_name, parts["config"]),
        (layer_name, parts["layer_gz"] if compress else parts["layer"]),
        ("manifest.json", json.dumps(listing).encode("utf-8")),
    ]
    destination.write_bytes(_tar_bytes(members))
    return destination


def build_image_archive(
    destination: Path, files: Dict[str, bytes], tag: str = "ash-fixture/files-image:1"
) -> Path:
    """Write a one-layer docker-archive holding *files* (in-image path to bytes).

    For a test that needs an image with chosen content (a package manifest in
    several directories, say). The same shape as :func:`build_secret_image_archive`:
    a gzip layer, a config naming its diff id, a ``docker save`` manifest, every
    mtime 0.
    """
    layer = _tar_bytes([(name.lstrip("/"), data) for name, data in files.items()])
    layer_hex = _sha256(layer)
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": [f"sha256:{layer_hex}"]},
        },
        sort_keys=True,
    ).encode("utf-8")
    config_name = f"{_sha256(config)}.json"
    layer_name = f"{layer_hex}/layer.tar"
    listing = [{"Config": config_name, "RepoTags": [tag], "Layers": [layer_name]}]
    destination.write_bytes(
        _tar_bytes(
            [
                (config_name, config),
                (layer_name, gzip.compress(layer, compresslevel=9, mtime=0)),
                ("manifest.json", json.dumps(listing).encode("utf-8")),
            ]
        )
    )
    return destination


def archive_to_layout(archive: Path, layout: Path) -> Path:
    """Re-pack a docker-archive as an OCI image-layout directory at *layout*.

    For the one-layer fixture shape: the config and each layer become blobs
    named by their digests, an image manifest names them, and ``index.json``
    names the manifest.
    """
    layout.mkdir(parents=True, exist_ok=True)
    blobs = layout / "blobs" / "sha256"
    blobs.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as source:
        listing = json.loads(source.extractfile("manifest.json").read())[0]
        config = source.extractfile(listing["Config"]).read()
        layers = [source.extractfile(name).read() for name in listing["Layers"]]
    descriptors = []
    for data in layers:
        (blobs / _sha256(data)).write_bytes(data)
        compressed = data[:2] == b"\x1f\x8b"
        descriptors.append(
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar"
                + ("+gzip" if compressed else ""),
                "digest": f"sha256:{_sha256(data)}",
                "size": len(data),
            }
        )
    (blobs / _sha256(config)).write_bytes(config)
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": f"sha256:{_sha256(config)}",
                "size": len(config),
            },
            "layers": descriptors,
        },
        sort_keys=True,
    ).encode("utf-8")
    (blobs / _sha256(manifest)).write_bytes(manifest)
    (layout / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
    (layout / "index.json").write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": f"sha256:{_sha256(manifest)}",
                        "size": len(manifest),
                    }
                ],
            }
        )
    )
    return layout


if __name__ == "__main__":  # pragma: no cover - regenerates the committed fixture
    import sys

    target = Path(sys.argv[1])
    build_secret_image_archive(target)
    print(f"{_sha256(target.read_bytes())}  {target.name}")
