# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Build the two tiny `docker save`-format image tarballs the captures were taken from.

No Docker daemon is needed: a saved image is a tar of a config JSON, layer tars and a
manifest.json. Usage: ``python3 -I build_fixture_image.py <output-dir>``. It writes
``positive-image.tar`` (root user, an ``/etc/shadow`` with an empty password, an
``id_rsa`` file name, a ``*_PASSWORD`` environment variable) and ``negative-image.tar``
(a non-root user and one ordinary file). Every value in them is a placeholder.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path


def _add(archive: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    archive.addfile(info, io.BytesIO(data))


def _image(
    path: Path, tag: str, files: dict[str, tuple[bytes, int]], env: list[str], user: str
) -> None:
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as inner:
        for name, (data, mode) in files.items():
            _add(inner, name, data, mode)
    layer_bytes = layer.getvalue()
    config = {
        "architecture": "amd64",
        "os": "linux",
        "created": "2026-01-01T00:00:00Z",
        "config": {"Env": env, "Cmd": ["/bin/sh"], "User": user},
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:" + hashlib.sha256(layer_bytes).hexdigest()],
        },
        "history": [
            {
                "created": "2026-01-01T00:00:00Z",
                "created_by": "/bin/sh -c #(nop) ADD file in /",
            }
        ],
    }
    config_bytes = json.dumps(config).encode()
    config_name = hashlib.sha256(config_bytes).hexdigest() + ".json"
    manifest = [
        {"Config": config_name, "RepoTags": [tag], "Layers": ["layer0/layer.tar"]}
    ]
    with tarfile.open(path, "w") as outer:
        _add(outer, config_name, config_bytes)
        _add(outer, "layer0/layer.tar", layer_bytes)
        _add(outer, "manifest.json", json.dumps(manifest).encode())


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    _image(
        out / "positive-image.tar",
        "ash-fixture/dockle-positive:1",
        {
            "etc/passwd": (b"root:x:0:0:root:/root:/bin/sh\n", 0o644),
            "etc/shadow": (b"root::0:0:99999:7:::\n", 0o644),
            "app/id_rsa": (b"placeholder, not a key\n", 0o600),
        },
        ["PATH=/usr/bin", "DB_PASSWORD=placeholder"],
        "",
    )
    _image(
        out / "negative-image.tar",
        "ash-fixture/dockle-negative:1",
        {
            "etc/passwd": (
                b"root:x:0:0:root:/root:/bin/sh\napp:x:10001:10001::/app:/bin/sh\n",
                0o644,
            ),
            "app/hello.txt": (b"hello\n", 0o644),
        },
        ["PATH=/usr/bin"],
        "app",
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]))
