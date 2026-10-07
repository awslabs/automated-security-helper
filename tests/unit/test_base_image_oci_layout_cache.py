# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The base-image OCI layout cache: fetched by digest, verified before use, discarded on doubt.

Why this file exists
--------------------
``.github/actions/prepull-base-image`` keeps the Dockerfile's base image in the Actions cache as
an OCI image layout so a warm container leg makes no registry call. The cache is readable by
anyone on a public repository and is restored into a build, so the property that matters is
that nothing is used unless it is exactly the bytes ``ARG BASE_IMAGE_DIGEST`` names, and that a
restored entry which is not gets thrown away rather than half-used.

What this asserts
-----------------
* ``oci_layout.py fetch`` writes a layout from a registry by digest, refuses a registry that
  serves different bytes, and falls through to the next registry when one refuses;
* ``oci_layout.py verify`` accepts that layout and refuses every tampering this file knows how
  to make -- a flipped byte in a layer, a missing layer, a stray file, a symlink, a blob whose
  name is not its hash, a pin that names a manifest rather than an index, an index without this
  arch, an index.json that points elsewhere;
* ``oci_layout.py key`` needs no network and moves with the tag, the pin and the arch;
* ``use_cached_layout.sh`` loads the verified layout into docker, imports it into podman, hands
  nerdctl and finch the layout itself, exports ``ASH_BASE_OCI_LAYOUT`` only when it did -- and on
  a tampered layout removes it, exports nothing and reports ``used=false``, which is what sends
  the action on to its unchanged registry pull;
* the registry block that turns a warm leg into proof of zero contact is applied to the host and
  to a running buildx builder, and fails the step when it does not take effect.

No test here touches a network or a real runtime. The registry is a fake opener and the runtimes
are stubs that record their argv; what the real runtimes do with these inputs is established in
CI, where the block above makes a registry call fail the leg.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION_DIR = REPO_ROOT / ".github" / "actions" / "prepull-base-image"
ACTION = ACTION_DIR / "action.yml"
HELPER = ACTION_DIR / "oci_layout.py"
HIT_SCRIPT = ACTION_DIR / "use_cached_layout.sh"
DOCKERFILE = REPO_ROOT / "Dockerfile"

BASE = "public.ecr.aws/docker/library/python:3.12-slim-bookworm"
REPO = "public.ecr.aws/docker/library/python"
FALLBACK = "docker.io/library/python"

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"


def _load_helper():
    spec = importlib.util.spec_from_file_location("oci_layout", HELPER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ol = _load_helper()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- a fake image


class FakeImage:
    """A two-arch index with real JSON documents and gzip layers, all digest-consistent."""

    def __init__(self):
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, dict] = {}
        entries = []
        for arch, variant in (("amd64", None), ("arm64", "v8")):
            layers = [
                gzip.compress(f"{arch} layer {n}".encode() * 50) for n in range(2)
            ]
            config = json.dumps(
                {
                    "architecture": arch,
                    "os": "linux",
                    "rootfs": {"type": "layers", "diff_ids": []},
                }
            ).encode()
            manifest = json.dumps(
                {
                    "schemaVersion": 2,
                    "mediaType": OCI_MANIFEST,
                    "config": {
                        "mediaType": "application/vnd.oci.image.config.v1+json",
                        "digest": self._add(config),
                        "size": len(config),
                    },
                    "layers": [
                        {
                            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                            "digest": self._add(layer),
                            "size": len(layer),
                        }
                        for layer in layers
                    ],
                }
            ).encode()
            mdigest = self._add(manifest)
            self.manifests[arch] = json.loads(manifest)
            platform = {"architecture": arch, "os": "linux"}
            if variant:
                platform["variant"] = variant
            entries.append(
                {
                    "mediaType": OCI_MANIFEST,
                    "digest": mdigest,
                    "size": len(manifest),
                    "platform": platform,
                }
            )
        # An attestation entry, as real Docker Hub indexes carry; it must never be selected.
        entries.append(
            {
                "mediaType": OCI_MANIFEST,
                "digest": "sha256:" + "e" * 64,
                "size": 10,
                "platform": {"architecture": "unknown", "os": "unknown"},
            }
        )
        index = json.dumps(
            {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": entries}
        ).encode()
        self.pin = self._add(index)

    def _add(self, data: bytes) -> str:
        digest = _digest(data)
        self.blobs[digest] = data
        return digest

    def config_digest(self, arch: str = "amd64") -> str:
        return self.manifests[arch]["config"]["digest"]


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeRegistry:
    """Enough of the distribution API for fetch: challenge, token, manifests, blobs."""

    def __init__(self, image: FakeImage, hosts: dict[str, str]):
        # hosts maps a registry host to how it behaves: "ok", "refuse" or "substitute".
        self.image = image
        self.hosts = hosts
        self.requests: list[tuple[str, dict]] = []

    def open(self, req, timeout=None):
        url = req if isinstance(req, str) else req.full_url
        headers = {} if isinstance(req, str) else dict(req.header_items())
        self.requests.append((url, headers))
        scheme_host, _, path = url.partition("://")[2].partition("/")
        host = scheme_host
        mode = self.hosts.get(host, "absent")
        if host == "auth.example":
            return _Response(json.dumps({"token": "t0ken"}).encode())
        if mode in ("absent", "refuse"):
            raise urllib.error.URLError(f"{host} refused")
        if path == "v2/":
            msg = Message()
            msg["WWW-Authenticate"] = (
                'Bearer realm="https://auth.example/token",service="svc"'
            )
            raise urllib.error.HTTPError(url, 401, "Unauthorized", msg, None)
        assert headers.get("Authorization") == "Bearer t0ken", headers
        digest = path.rsplit("/", 1)[1]
        data = self.image.blobs.get(digest)
        if data is None:
            raise urllib.error.HTTPError(url, 404, "Not Found", Message(), None)
        if mode == "substitute":
            data = data + b" "
        return _Response(data)


@pytest.fixture
def image() -> FakeImage:
    return FakeImage()


@pytest.fixture
def layout(tmp_path, image, monkeypatch) -> Path:
    registry = FakeRegistry(image, {"public.ecr.aws": "ok"})
    monkeypatch.setattr(ol, "_OPENER", registry)
    out = tmp_path / "ash-base-image-oci"
    ol.fetch([REPO], image.pin, "X64", out)
    return out


def _mutable_copy(layout: Path, tmp_path: Path) -> Path:
    copy = tmp_path / "copy"
    shutil.copytree(layout, copy)
    for path in copy.rglob("*"):
        if path.is_file():
            path.chmod(path.stat().st_mode | stat.S_IWUSR)
    return copy


# --------------------------------------------------------------------------- key


class TestTheCacheKey:
    def test_it_is_tag_pin_and_arch_from_the_dockerfile(self):
        pin = next(
            line.split("=", 1)[1]
            for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()
            if line.startswith("ARG BASE_IMAGE_DIGEST=")
        )
        key = ol.cache_key(DOCKERFILE, "X64")
        assert key == f"ash-base-image-oci-v1-3.12-slim-bookworm-{pin}-X64"
        assert ol.cache_key(DOCKERFILE, "ARM64").endswith("-ARM64")

    def test_a_new_pin_is_a_new_key(self, tmp_path):
        a, b = tmp_path / "a", tmp_path / "b"
        a.write_text(
            f"ARG BASE_IMAGE={BASE}\nARG BASE_IMAGE_DIGEST=sha256:{'1' * 64}\n"
        )
        b.write_text(
            f"ARG BASE_IMAGE={BASE}\nARG BASE_IMAGE_DIGEST=sha256:{'2' * 64}\n"
        )
        assert ol.cache_key(a, "X64") != ol.cache_key(b, "X64")

    @pytest.mark.parametrize(
        "text",
        [
            f"ARG BASE_IMAGE={BASE}\n",
            f"ARG BASE_IMAGE={BASE}\nARG BASE_IMAGE_DIGEST=sha256:short\n",
            f"ARG BASE_IMAGE={REPO}@sha256:{'1' * 64}\nARG BASE_IMAGE_DIGEST=sha256:{'1' * 64}\n",
        ],
    )
    def test_a_malformed_dockerfile_has_no_key(self, tmp_path, text):
        path = tmp_path / "Dockerfile"
        path.write_text(text)
        with pytest.raises(ol.LayoutError):
            ol.cache_key(path, "X64")

    def test_an_unknown_arch_has_no_key(self):
        with pytest.raises(ol.LayoutError, match="RUNNER_ARCH"):
            ol.cache_key(DOCKERFILE, "sparc")


# --------------------------------------------------------------------------- fetch


class TestFetch:
    def test_it_writes_exactly_the_pinned_index_and_one_arch(self, layout, image):
        names = sorted(p.name for p in (layout / "blobs" / "sha256").iterdir())
        amd = image.manifests["amd64"]
        expected = sorted(
            d.split(":", 1)[1]
            for d in [
                image.pin,
                ol._select_manifest(json.loads(image.blobs[image.pin]), "X64")[
                    "digest"
                ],
                amd["config"]["digest"],
                *[layer["digest"] for layer in amd["layers"]],
            ]
        )
        assert names == expected
        top = json.loads((layout / "index.json").read_text())
        assert [d["mediaType"] for d in top["manifests"]] == [
            OCI_INDEX,
            OCI_MANIFEST,
        ], (
            "the arch manifest must be the LAST manifest-typed entry: nerdctl takes that one"
        )

    def test_a_registry_serving_other_bytes_is_refused(
        self, tmp_path, image, monkeypatch
    ):
        monkeypatch.setattr(
            ol, "_OPENER", FakeRegistry(image, {"public.ecr.aws": "substitute"})
        )
        out = tmp_path / "out"
        with pytest.raises(ol.LayoutError, match="no registry served"):
            ol.fetch([REPO], image.pin, "X64", out)
        assert not out.exists()
        assert list(tmp_path.glob(".oci-layout-*")) == [], (
            "no partial layout may be left"
        )

    def test_a_refusing_registry_falls_through_to_the_next(
        self, tmp_path, image, monkeypatch
    ):
        registry = FakeRegistry(
            image, {"public.ecr.aws": "refuse", "registry-1.docker.io": "ok"}
        )
        monkeypatch.setattr(ol, "_OPENER", registry)
        out = tmp_path / "out"
        digest = ol.fetch([REPO, FALLBACK], image.pin, "X64", out)
        assert ol.verify(out, image.pin, "X64") == digest
        assert any("registry-1.docker.io" in url for url, _ in registry.requests)

    def test_it_will_not_write_over_an_existing_directory(self, layout, image):
        with pytest.raises(ol.LayoutError, match="already exists"):
            ol.fetch([REPO], image.pin, "X64", layout)

    def test_the_token_is_not_forwarded_off_the_registry_host(self):
        """Blob downloads redirect to a CDN or a presigned URL, which refuses a bearer token."""
        handler = ol._StripAuthOnRedirect()
        req = urllib.request.Request("https://public.ecr.aws/v2/x/blobs/sha256:1")
        req.add_header("Authorization", "Bearer secret")
        off_host = handler.redirect_request(
            req, None, 307, "redirect", Message(), "https://cdn.example/blob?sig=1"
        )
        assert "Authorization" not in dict(off_host.header_items())
        same_host = handler.redirect_request(
            req, None, 307, "redirect", Message(), "https://public.ecr.aws/v2/other"
        )
        assert dict(same_host.header_items()).get("Authorization") == "Bearer secret"


# --------------------------------------------------------------------------- verify


def _flip_byte(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))


class TestVerify:
    def test_the_fetched_layout_verifies_and_names_the_arch_manifest(
        self, layout, image
    ):
        digest = ol.verify(layout, image.pin, "X64")
        index = json.loads(image.blobs[image.pin])
        assert digest == ol._select_manifest(index, "X64")["digest"]

    def test_another_arch_is_not_in_this_layout(self, layout, image):
        with pytest.raises(ol.LayoutError, match="not in the layout"):
            ol.verify(layout, image.pin, "ARM64")

    def test_another_pin_is_refused(self, layout):
        with pytest.raises(ol.LayoutError, match="pinned index"):
            ol.verify(layout, "sha256:" + "9" * 64, "X64")

    def test_a_flipped_byte_in_a_layer_is_refused(self, layout, image, tmp_path):
        copy = _mutable_copy(layout, tmp_path)
        layer = image.manifests["amd64"]["layers"][0]["digest"].split(":", 1)[1]
        _flip_byte(copy / "blobs" / "sha256" / layer)
        with pytest.raises(ol.LayoutError, match="hashes to"):
            ol.verify(copy, image.pin, "X64")

    def test_a_missing_layer_is_refused(self, layout, image, tmp_path):
        copy = _mutable_copy(layout, tmp_path)
        layer = image.manifests["amd64"]["layers"][1]["digest"].split(":", 1)[1]
        (copy / "blobs" / "sha256" / layer).unlink()
        with pytest.raises(ol.LayoutError, match="not in the layout"):
            ol.verify(copy, image.pin, "X64")

    def test_a_substituted_blob_renamed_to_match_is_refused(
        self, layout, image, tmp_path
    ):
        """Replacing a layer AND naming it by its new hash leaves the manifest unsatisfied."""
        copy = _mutable_copy(layout, tmp_path)
        sha_dir = copy / "blobs" / "sha256"
        old = image.manifests["amd64"]["layers"][0]["digest"].split(":", 1)[1]
        evil = gzip.compress(b"evil")
        (sha_dir / old).unlink()
        (sha_dir / hashlib.sha256(evil).hexdigest()).write_bytes(evil)
        with pytest.raises(ol.LayoutError, match="not in the layout"):
            ol.verify(copy, image.pin, "X64")

    def test_a_stray_file_is_refused(self, layout, image, tmp_path):
        copy = _mutable_copy(layout, tmp_path)
        (copy / "manifest.json").write_text("[]")
        with pytest.raises(ol.LayoutError, match="unexpected entry"):
            ol.verify(copy, image.pin, "X64")

    def test_a_blob_under_another_algorithm_is_refused(self, layout, image, tmp_path):
        copy = _mutable_copy(layout, tmp_path)
        (copy / "blobs" / "sha512").mkdir()
        with pytest.raises(ol.LayoutError, match="unexpected entry"):
            ol.verify(copy, image.pin, "X64")

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_a_symlinked_blob_is_refused(self, layout, image, tmp_path):
        copy = _mutable_copy(layout, tmp_path)
        sha_dir = copy / "blobs" / "sha256"
        layer = image.manifests["amd64"]["layers"][0]["digest"].split(":", 1)[1]
        target = tmp_path / "elsewhere"
        target.write_bytes((sha_dir / layer).read_bytes())
        (sha_dir / layer).unlink()
        (sha_dir / layer).symlink_to(target)
        with pytest.raises(ol.LayoutError, match="not a regular file"):
            ol.verify(copy, image.pin, "X64")

    def test_a_pin_that_is_a_manifest_rather_than_an_index_is_refused(
        self, layout, image, tmp_path
    ):
        mdigest = ol.verify(layout, image.pin, "X64")
        with pytest.raises(ol.LayoutError, match="not an image index"):
            ol.verify(layout, mdigest, "X64")

    def test_an_index_json_pointing_elsewhere_is_refused(self, layout, image, tmp_path):
        copy = _mutable_copy(layout, tmp_path)
        top = json.loads((copy / "index.json").read_text())
        top["manifests"] = top["manifests"][:1]
        (copy / "index.json").write_text(json.dumps(top))
        with pytest.raises(ol.LayoutError, match="index.json lists"):
            ol.verify(copy, image.pin, "X64")

    def test_a_missing_oci_layout_marker_is_refused(self, layout, image, tmp_path):
        copy = _mutable_copy(layout, tmp_path)
        (copy / "oci-layout").unlink()
        with pytest.raises(ol.LayoutError, match="oci-layout"):
            ol.verify(copy, image.pin, "X64")


# --------------------------------------------------------------------------- docker-archive


class TestDockerArchive:
    def test_it_holds_this_arch_only_tagged_under_the_from_reference(
        self, layout, image
    ):
        buf = io.BytesIO()
        ol.docker_archive(layout, image.pin, "X64", BASE, buf)
        with tarfile.open(fileobj=io.BytesIO(buf.getvalue())) as tar:
            names = tar.getnames()
            manifest = json.loads(tar.extractfile("manifest.json").read())
        amd = image.manifests["amd64"]
        assert manifest[0]["RepoTags"] == [BASE]
        assert manifest[0]["Config"] == "blobs/sha256/" + amd["config"]["digest"][7:]
        assert set(names) == {
            "manifest.json",
            manifest[0]["Config"],
            *manifest[0]["Layers"],
        }

    def test_it_refuses_a_tampered_layout(self, layout, image, tmp_path):
        copy = _mutable_copy(layout, tmp_path)
        layer = image.manifests["amd64"]["layers"][0]["digest"].split(":", 1)[1]
        _flip_byte(copy / "blobs" / "sha256" / layer)
        with pytest.raises(ol.LayoutError):
            ol.docker_archive(copy, image.pin, "X64", BASE, io.BytesIO())


# --------------------------------------------------------------------------- the hit step

RUNTIME_STUB = r"""#!/usr/bin/env python3
import json, os, sys, tarfile
log = open(os.environ["STUB_LOG"], "a")
args = sys.argv[1:]
log.write(" ".join(args) + "\n")
state_path = os.environ["STUB_STATE"]
state = json.load(open(state_path)) if os.path.exists(state_path) else {}
def save():
    json.dump(state, open(state_path, "w"))
if args[:1] == ["load"]:
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as tar:
        for member in tar:
            if member.name == "manifest.json":
                m = json.load(tar.extractfile(member))[0]
                state[m["RepoTags"][0]] = "sha256:" + m["Config"].rsplit("/", 1)[1]
    save()
    print("Loaded image")
elif args[:2] == ["pull", "-q"]:
    layout = args[2].split(":", 2)[1]
    index = json.load(open(os.path.join(layout, "index.json")))
    mdigest = index["manifests"][-1]["digest"]
    manifest = json.load(open(os.path.join(layout, "blobs", "sha256", mdigest[7:])))
    image_id = manifest["config"]["digest"][7:]
    state[image_id] = image_id
    save()
    print(image_id)
elif args[:1] == ["tag"]:
    state[args[2]] = state[args[1]]
    save()
elif args[:2] == ["image", "inspect"]:
    ref = args[-1]
    if ref not in state:
        sys.exit(1)
    print(state[ref])
elif args[:1] == ["ps"]:
    print(os.environ.get("STUB_BUILDERS", ""))
elif args[:2] == ["exec", "-i"]:
    open(os.environ["STUB_BUILDER_HOSTS"], "a").write(sys.stdin.read())
else:
    sys.exit(64)
"""

SUDO_STUB = """#!/bin/bash
[ "$1" = "tee" ] && [ "$2" = "-a" ] && [ "$3" = "/etc/hosts" ] || exit 64
cat >> "$STUB_HOSTS"
"""

GETENT_STUB = """#!/bin/bash
echo "${STUB_GETENT} $2"
"""


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class HitResult:
    def __init__(self, proc, calls, exported, outputs, work):
        self.proc = proc
        self.calls = calls
        self.exported = exported
        self.outputs = outputs
        self.work = work

    @property
    def output(self) -> str:
        return self.proc.stdout + self.proc.stderr

    def describe(self) -> str:
        return (
            f"exit={self.proc.returncode}\ncalls={self.calls}\nexported={self.exported}\n"
            f"outputs={self.outputs}\n{self.output}"
        )


def _run_hit(
    tmp_path: Path,
    layout: Path,
    pin: str,
    runtime: str,
    block: bool = False,
    # What a blocked host resolves to, as the stub getent prints it; nothing binds to it.
    getent: str = "0.0.0.0",  # nosec B104
    builders: str = "",
) -> HitResult:
    work = tmp_path / "hit"
    work.mkdir()
    bin_dir = work / "bin"
    bin_dir.mkdir()
    _write_exec(bin_dir / runtime, RUNTIME_STUB)
    if runtime != "docker":
        _write_exec(bin_dir / "docker", RUNTIME_STUB)
    _write_exec(bin_dir / "sudo", SUDO_STUB)
    _write_exec(bin_dir / "getent", GETENT_STUB)
    dockerfile = work / "Dockerfile"
    dockerfile.write_text(f"ARG BASE_IMAGE={BASE}\nARG BASE_IMAGE_DIGEST={pin}\n")
    github_env = work / "github_env"
    github_output = work / "github_output"
    github_env.write_text("")
    github_output.write_text("")
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(work),
        "RUNTIME": runtime,
        "WRAPPER": "",
        "DOCKERFILE": str(dockerfile),
        "HELPER": str(HELPER),
        "LAYOUT_DIR": str(layout),
        "RUNNER_ARCH": "X64",
        "BLOCK_REGISTRIES": "true" if block else "false",
        "GITHUB_ENV": str(github_env),
        "GITHUB_OUTPUT": str(github_output),
        "STUB_LOG": str(work / "calls.log"),
        "STUB_STATE": str(work / "state.json"),
        "STUB_HOSTS": str(work / "etc_hosts"),
        "STUB_BUILDER_HOSTS": str(work / "builder_hosts"),
        "STUB_BUILDERS": builders,
        "STUB_GETENT": getent,
    }
    proc = subprocess.run(  # nosec B603 — fixed interpreter, list args, no shell
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", str(HIT_SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    calls_file = work / "calls.log"
    calls = calls_file.read_text().splitlines() if calls_file.exists() else []

    def parse(path: Path) -> dict:
        return dict(
            line.split("=", 1) for line in path.read_text().splitlines() if line
        )

    return HitResult(proc, calls, parse(github_env), parse(github_output), work)


_REQUIRES_BASH = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="the hit step is bash, and only runs on the Linux container legs",
)


@_REQUIRES_BASH
class TestTheHitStep:
    @pytest.fixture
    def writable(self, layout, tmp_path) -> Path:
        return _mutable_copy(layout, tmp_path)

    def test_docker_loads_the_verified_image_under_the_from_reference(
        self, tmp_path, writable, image
    ):
        result = _run_hit(tmp_path, writable, image.pin, "docker")
        assert result.proc.returncode == 0, result.describe()
        assert result.outputs.get("used") == "true", result.describe()
        assert result.calls[0] == "load", result.describe()
        state = json.loads((result.work / "state.json").read_text())
        assert state[BASE] == image.config_digest(), result.describe()
        mdigest = ol.verify(writable, image.pin, "X64")
        assert result.exported == {"ASH_BASE_OCI_LAYOUT": f"{writable}@{mdigest}"}

    def test_podman_imports_through_the_oci_transport_and_tags(
        self, tmp_path, writable, image
    ):
        result = _run_hit(tmp_path, writable, image.pin, "podman")
        assert result.outputs.get("used") == "true", result.describe()
        assert result.calls[0] == f"pull -q oci:{writable}:index", result.describe()
        assert result.calls[1].startswith("tag "), result.describe()
        assert result.calls[1].endswith(f" {BASE}"), result.describe()
        assert "ASH_BASE_OCI_LAYOUT" in result.exported

    @pytest.mark.parametrize("runtime", ["nerdctl", "finch"])
    def test_nerdctl_and_finch_are_handed_the_layout_and_touch_no_store(
        self, tmp_path, writable, image, runtime
    ):
        result = _run_hit(tmp_path, writable, image.pin, runtime)
        assert result.outputs.get("used") == "true", result.describe()
        assert result.calls == [], "the build reads the layout; nothing is imported"
        assert "ASH_BASE_OCI_LAYOUT" in result.exported

    @pytest.mark.parametrize("runtime", ["docker", "podman", "nerdctl"])
    def test_a_tampered_entry_is_discarded_and_the_pull_path_runs(
        self, tmp_path, writable, image, runtime
    ):
        """The tamper case the design names: one corrupted blob in a throwaway copy."""
        layer = image.manifests["amd64"]["layers"][0]["digest"].split(":", 1)[1]
        _flip_byte(writable / "blobs" / "sha256" / layer)

        result = _run_hit(tmp_path, writable, image.pin, runtime)
        assert result.proc.returncode == 0, result.describe()
        assert result.outputs.get("used") == "false", (
            "used=false is what makes the action run its registry pull step"
        )
        assert result.exported == {}, (
            "nothing may be exported from an entry that failed"
        )
        assert result.calls == [], "nothing may be loaded from an entry that failed"
        assert not writable.exists(), (
            "a failed entry is removed, not left for later steps"
        )
        assert "discarding the cached base image" in result.output
        assert "hashes to" in result.output, "the warning must say which check failed"

    def test_an_unknown_runtime_is_not_handed_anything(self, tmp_path, writable, image):
        result = _run_hit(tmp_path, writable, image.pin, "lxc")
        assert result.outputs.get("used") == "false", result.describe()
        assert result.exported == {}
        assert writable.exists(), "a sound entry is kept; only the hand-off is refused"

    def test_the_block_covers_the_host_and_a_running_buildx_builder(
        self, tmp_path, writable, image
    ):
        result = _run_hit(
            tmp_path,
            writable,
            image.pin,
            "docker",
            block=True,
            builders="buildx_buildkit_builder-x0",
        )
        assert result.proc.returncode == 0, result.describe()
        assert result.outputs.get("blocked") == "true", result.describe()
        for target in ("etc_hosts", "builder_hosts"):
            text = (result.work / target).read_text()
            for host in ("public.ecr.aws", "registry-1.docker.io", "auth.docker.io"):
                assert f"0.0.0.0 {host}\n" in text and f":: {host}\n" in text, (
                    target,
                    text,
                )
        assert (
            "exec -i buildx_buildkit_builder-x0 sh -c cat >> /etc/hosts" in result.calls
        )

    def test_a_block_that_did_not_take_effect_fails_the_step(
        self, tmp_path, writable, image
    ):
        result = _run_hit(
            tmp_path, writable, image.pin, "podman", block=True, getent="52.1.2.3"
        )
        assert result.proc.returncode == 1, result.describe()
        assert "zero-contact assertion would prove nothing" in result.output

    def test_no_block_is_applied_when_the_entry_was_not_used(
        self, tmp_path, writable, image
    ):
        layer = image.manifests["amd64"]["layers"][0]["digest"].split(":", 1)[1]
        _flip_byte(writable / "blobs" / "sha256" / layer)
        result = _run_hit(tmp_path, writable, image.pin, "docker", block=True)
        assert not (result.work / "etc_hosts").exists(), (
            "the pull path needs the registries; the block is only for a warm leg"
        )


# --------------------------------------------------------------------------- the wiring


class TestTheActionWiring:
    @pytest.fixture
    def steps(self) -> dict:
        doc = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
        return {s.get("id"): s for s in doc["runs"]["steps"]}

    def test_the_steps_run_in_the_designed_order(self):
        doc = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
        ids = [s.get("id") for s in doc["runs"]["steps"]]
        # `report` writes the job-summary hit line every cache restore carries
        # (tests/unit/test_ci_cache_saves_from_main_only.py). It reads the restore's
        # outputs only and changes nothing the hit or pull steps see.
        assert ids == ["key", "restore", "report", "hit", "pull", "write", None], ids

    def test_the_hit_step_runs_only_on_an_exact_restore(self, steps):
        assert steps["hit"]["if"].strip() == "steps.restore.outputs.cache-hit == 'true'"
        assert "use_cached_layout.sh" in steps["hit"]["run"]

    def test_the_pull_runs_whenever_the_hit_did_not_hand_over(self, steps):
        """Miss, discarded entry and refused hand-off all leave `used` other than 'true'."""
        assert steps["pull"]["if"].strip() == "steps.hit.outputs.used != 'true'"

    def test_the_layout_is_written_only_on_main_after_a_miss(self, steps):
        condition = " ".join(steps["write"]["if"].split())
        for clause in (
            "steps.pull.outcome == 'success'",
            "steps.restore.outputs.cache-hit != 'true'",
            "github.event_name == 'push'",
            "github.ref == 'refs/heads/main'",
        ):
            assert clause in condition, condition
        assert "||" not in condition

    def test_the_action_reports_whether_the_cache_was_used(self):
        doc = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
        assert doc["outputs"]["cache-used"]["value"] == "${{ steps.hit.outputs.used }}"

    def test_the_block_is_on_by_default(self):
        doc = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
        assert doc["inputs"]["block-registries-on-hit"]["default"] == "true"
