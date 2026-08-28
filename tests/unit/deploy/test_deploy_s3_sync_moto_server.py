"""The deploy trees' recursive S3 helper, run against a real moto server.

WHAT IS UNDER TEST
------------------
Two copies of one helper, deliberately kept behaviorally identical:

  - the CDK copy, extracted from whichever committed template under
    `deploy/cdk/templates/` actually emits it, and materialized by executing that
    buildspec's own quoted heredoc
  - the Terraform copy, `deploy/terraform/.../files/ash_s3_sync.py`, on disk

The emitting template is found by content, not named. Which stack carries which
injected script is a deployment decision that has already moved once: the flavor
gating gave each stack only the scripts for the flavors it builds. A test that
names the file goes red on that change while asserting nothing wrong.

Every behavior test is parametrized across both, so "these two are the same
helper" stops being a comment and becomes a measurement. The two are separate
files because the two deployment trees are independently consumable, which is
exactly the arrangement where one gets fixed and the other silently does not.

WHY A SUBPROCESS
----------------
This is how the helper actually runs -- `python3 /tmp/ash-s3-sync.py upload ...`
from a buildspec phase. Importing `download()` and calling it would test a
function the deployment never calls that way, and would skip the argv parsing and
the exit codes, which is where two of the tests below find their evidence.

THE BUG CLASS THESE EXIST FOR
-----------------------------
The helper replaced `aws s3 cp --recursive`, which is not present in the ASH
image and exited 127. A deployed pipeline failed all four shards after a
successful scan. So the risk is not "does boto3 work" but the parts that a hand
rolled recursive copy gets wrong and a happy-path test never sees: a second
ListObjectsV2 page, a key that climbs out of the destination, and an empty
prefix. Each has a test below whose expected value differs from the buggy value,
rather than merely asserting success.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from dataclasses import dataclass

import pytest

from tests.unit.deploy.buildspec_extraction import (
    TERRAFORM_S3_SYNC,
    heredoc_body,
    helper_invocation,
    projects_containing,
    rewrite_helper_path,
    sole_command_containing,
    templates_with_plain_buildspec_marker,
)

# The buildspec commands are POSIX shell destined for a Linux build container.
# Windows runners have no `sh` on PATH by default, and the container these run in
# is Linux in every deployment. The direct-invocation tests above them are
# platform independent and do run everywhere.
posix_shell_only = pytest.mark.skipif(
    os.name == "nt",
    reason="executes a POSIX buildspec command destined for a Linux build container",
)

HELPER_MARKER = "ash-s3-sync.py"


@dataclass(frozen=True)
class Helper:
    """A materialized copy of the S3 helper, ready to invoke."""

    label: str
    path: pathlib.Path
    # The two copies log under their own file name; assertions on stderr use this
    # rather than hard-coding one spelling and quietly matching nothing.
    log_prefix: str


def _sharded_pipeline_template() -> dict:
    """The committed template that emits the S3 sync helper.

    Found by content rather than by filename. Which stack carries which injected
    script is a deployment decision that has already moved once -- the flavor gating
    gave each stack only the scripts for the flavors it builds -- and a test naming
    the file goes red on that change while asserting nothing wrong.
    """
    matching = templates_with_plain_buildspec_marker(HELPER_MARKER)
    assert len(matching) == 1, (
        f"expected exactly one template with plain-string buildspecs emitting "
        f"{HELPER_MARKER!r}; found {sorted(matching)}. If the helper is now shared "
        f"by several stacks, these tests should be parametrized over them."
    )
    return next(iter(matching.values()))


def _shard_buildspec() -> dict:
    """The buildspec of one shard project from the committed template."""
    template = _sharded_pipeline_template()
    projects = projects_containing(template, HELPER_MARKER)
    # Four shards plus the merge. Asserted so that a template which stops
    # rendering the helper fails here, rather than leaving the tests below to
    # exercise a helper this repository no longer deploys.
    assert len(projects) == 5, (
        f"expected the helper in 5 CodeBuild projects (4 shards + merge), "
        f"found {len(projects)}: {sorted(projects)}"
    )
    shard_ids = sorted(i for i in projects if "Shard" in i)
    assert len(shard_ids) == 4, f"expected 4 shard projects, found {shard_ids}"
    return projects[shard_ids[0]]


def _merge_buildspec() -> dict:
    template = _sharded_pipeline_template()
    projects = projects_containing(template, HELPER_MARKER)
    merge_ids = [i for i in projects if "Merge" in i]
    assert len(merge_ids) == 1, f"expected exactly one merge project, found {merge_ids}"
    return projects[merge_ids[0]]


@pytest.fixture(params=["cdk-template", "terraform"])
def helper(request, tmp_path: pathlib.Path) -> Helper:
    """One copy of the helper, materialized the way its deployment does it."""
    if request.param == "cdk-template":
        # Run the buildspec's own `cat > path <<'PY' ... PY`, so the quoted
        # heredoc is exercised too: an UNquoted delimiter would let the shell eat
        # the Python's f-string braces and produce a file that fails to parse.
        command = sole_command_containing(_shard_buildspec(), "pre_build", "<<'PY'")
        body = heredoc_body(command)
        path = tmp_path / "ash-s3-sync.py"
        path.write_text(body, encoding="utf-8")
        assert "def download(" in body, (
            "the extracted heredoc body does not define download(); the extraction "
            "matched something other than the helper"
        )
        return Helper(label="cdk-template", path=path, log_prefix="ash-s3-sync")

    assert TERRAFORM_S3_SYNC.is_file(), (
        f"missing Terraform helper at {TERRAFORM_S3_SYNC}"
    )
    return Helper(label="terraform", path=TERRAFORM_S3_SYNC, log_prefix="ash_s3_sync")


def run_helper(
    helper: Helper, args: list[str], child_env: dict[str, str]
) -> subprocess.CompletedProcess:
    """Invoke the helper as its buildspec does, but with this interpreter."""
    return subprocess.run(
        [sys.executable, str(helper.path), *args],
        capture_output=True,
        text=True,
        env=child_env,
        timeout=300,
    )


def keys_under(s3, bucket: str, prefix: str) -> list[str]:
    """Every key under a prefix, following pagination."""
    found: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(
        Bucket=bucket, Prefix=prefix
    ):
        found.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(found)


# ---------------------------------------------------------------------------
# The guard that makes every other test in this file meaningful.
# ---------------------------------------------------------------------------


class TestMotoEndpointIsActuallyUsed:
    """Prove the tests reach moto, and reach it BECAUSE of the endpoint variable."""

    def test_endpoint_variable_is_load_bearing(
        self,
        helper: Helper,
        child_env: dict[str, str],
        bucket: str,
        tmp_path: pathlib.Path,
    ):
        """Repointing AWS_ENDPOINT_URL away from moto must break the upload.

        Without this, every passing test below is consistent with the helper
        having reached some other endpoint entirely. The replacement endpoint is a
        closed loopback port rather than a missing variable on purpose: unsetting
        it would send a real request to s3.amazonaws.com, which these tests must
        never do.
        """
        source = tmp_path / "payload"
        source.mkdir()
        (source / "one.txt").write_text("x", encoding="utf-8")

        # Port 1 on loopback: privileged, unbound, refuses immediately.
        broken = dict(child_env)
        broken["AWS_ENDPOINT_URL"] = "http://127.0.0.1:1"
        # botocore's default retry mode would spend several seconds backing off
        # before reporting a connection it can never make.
        broken["AWS_MAX_ATTEMPTS"] = "1"

        result = run_helper(helper, ["upload", str(source), bucket, "p"], broken)

        assert result.returncode != 0, (
            "upload succeeded while pointed at a closed port, so AWS_ENDPOINT_URL "
            "is not what routes these tests to moto and the suite proves nothing "
            f"about the helper's S3 calls. stdout={result.stdout!r}"
        )

    def test_upload_is_observable_in_moto(
        self,
        helper: Helper,
        child_env: dict[str, str],
        bucket: str,
        s3,
        tmp_path: pathlib.Path,
    ):
        """The object the helper uploads is readable through the moto client.

        The positive half of the pair above: the data has to actually be in the
        moto backend, not merely reported as uploaded by the helper's own stdout.
        """
        source = tmp_path / "payload"
        source.mkdir()
        (source / "one.txt").write_text("in-moto", encoding="utf-8")

        result = run_helper(helper, ["upload", str(source), bucket, "p"], child_env)
        assert result.returncode == 0, result.stderr

        body = s3.get_object(Bucket=bucket, Key="p/one.txt")["Body"].read()
        assert body == b"in-moto"


# ---------------------------------------------------------------------------
# Behavior, across both copies of the helper.
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_upload_then_download_preserves_the_key_hierarchy(
        self,
        helper: Helper,
        child_env: dict[str, str],
        bucket: str,
        s3,
        tmp_path: pathlib.Path,
    ):
        """Nested directories survive the trip, and contents are byte-exact.

        `recreate the key hierarchy` is the part a naive implementation gets
        wrong by flattening everything into the destination directory, which
        would still exit 0 and still report the right file count.
        """
        source = tmp_path / "out"
        (source / "reports").mkdir(parents=True)
        (source / "reports" / "ash.summary.md").write_text(
            "# summary\n", encoding="utf-8"
        )
        (source / "ash_aggregated_results.json").write_text(
            '{"findings": []}', encoding="utf-8"
        )
        # A byte that is not valid UTF-8, so the helper is shown to move bytes
        # rather than decoded text.
        (source / "raw.bin").write_bytes(b"\x00\xff\xfe binary")

        upload = run_helper(helper, ["upload", str(source), bucket, "run-1"], child_env)
        assert upload.returncode == 0, upload.stderr
        assert keys_under(s3, bucket, "run-1/") == [
            "run-1/ash_aggregated_results.json",
            "run-1/raw.bin",
            "run-1/reports/ash.summary.md",
        ]

        destination = tmp_path / "back"
        download = run_helper(
            helper, ["download", bucket, "run-1", str(destination)], child_env
        )
        assert download.returncode == 0, download.stderr

        assert (destination / "reports" / "ash.summary.md").read_text(
            encoding="utf-8"
        ) == "# summary\n"
        assert (destination / "raw.bin").read_bytes() == b"\x00\xff\xfe binary"
        assert json.loads(
            (destination / "ash_aggregated_results.json").read_text(encoding="utf-8")
        ) == {"findings": []}

    def test_empty_directories_are_not_recreated(
        self,
        helper: Helper,
        child_env: dict[str, str],
        bucket: str,
        tmp_path: pathlib.Path,
    ):
        """A documented limitation, pinned so it cannot change unnoticed.

        S3 has no empty-directory object, so a directory that held no files
        upstream does not come back. Both helpers' docstrings say so; this is the
        assertion that makes the claim checkable.
        """
        source = tmp_path / "out"
        (source / "empty").mkdir(parents=True)
        (source / "full").mkdir()
        (source / "full" / "f.txt").write_text("f", encoding="utf-8")

        assert (
            run_helper(
                helper, ["upload", str(source), bucket, "run"], child_env
            ).returncode
            == 0
        )

        destination = tmp_path / "back"
        assert (
            run_helper(
                helper, ["download", bucket, "run", str(destination)], child_env
            ).returncode
            == 0
        )

        assert (destination / "full" / "f.txt").is_file()
        assert not (destination / "empty").exists()


class TestPagination:
    """ListObjectsV2 returns at most 1000 keys per page."""

    def test_download_crosses_a_page_boundary(
        self,
        helper: Helper,
        child_env: dict[str, str],
        bucket: str,
        s3,
        tmp_path: pathlib.Path,
    ):
        """1050 objects must all arrive, not the first 1000.

        The count is chosen so the correct answer (1050) and the answer a
        non-paginating implementation gives (1000) are different numbers. A test
        that used 10 objects would pass against an implementation that read only
        the first page, which is the defect this is here to catch.
        """
        total = 1050
        for i in range(total):
            s3.put_object(Bucket=bucket, Key=f"run/part-{i:05d}.json", Body=b"{}")

        destination = tmp_path / "back"
        result = run_helper(
            helper, ["download", bucket, "run", str(destination)], child_env
        )
        assert result.returncode == 0, result.stderr

        assert f"downloaded {total} file(s)" in result.stdout, result.stdout
        assert len(sorted(destination.rglob("*.json"))) == total


class TestPathContainment:
    """The guard that refuses a key which would write outside the destination."""

    def test_download_refuses_a_key_that_escapes_the_destination(
        self,
        helper: Helper,
        child_env: dict[str, str],
        bucket: str,
        s3,
        tmp_path: pathlib.Path,
    ):
        """A `..` segment must be refused, and must not land on disk.

        Written through put_object rather than the helper's own upload, because
        the upload side derives keys from local paths and cannot produce this one.
        The escaping key is what an attacker-influenced bucket supplies.
        """
        s3.put_object(Bucket=bucket, Key="run/../escaped.txt", Body=b"escaped")
        s3.put_object(Bucket=bucket, Key="run/legitimate.txt", Body=b"fine")

        destination = tmp_path / "sandbox" / "back"
        result = run_helper(
            helper, ["download", bucket, "run", str(destination)], child_env
        )

        assert result.returncode == 2, (
            f"expected exit 2 from the containment guard, got {result.returncode}. "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert "would write outside" in result.stderr, result.stderr
        assert f"{helper.log_prefix}:" in result.stderr, result.stderr

        # The point of the guard: nothing was written above the destination.
        assert not (tmp_path / "sandbox" / "escaped.txt").exists()
        assert not (tmp_path / "escaped.txt").exists()

    def test_a_key_named_dot_dot_inside_the_prefix_is_still_contained(
        self,
        helper: Helper,
        child_env: dict[str, str],
        bucket: str,
        s3,
        tmp_path: pathlib.Path,
    ):
        """A key that climbs and comes back stays inside, so it is allowed.

        Distinguishes "refuses anything containing .." from "refuses what
        actually escapes". The guard resolves the path and compares, so this one
        resolves back inside the destination and is downloaded.
        """
        s3.put_object(Bucket=bucket, Key="run/nested/../kept.txt", Body=b"kept")

        destination = tmp_path / "back"
        result = run_helper(
            helper, ["download", bucket, "run", str(destination)], child_env
        )

        assert result.returncode == 0, result.stderr
        assert (destination / "kept.txt").read_bytes() == b"kept"


class TestEmptyAndMissing:
    def test_download_of_a_missing_prefix_writes_nothing_and_succeeds(
        self,
        helper: Helper,
        child_env: dict[str, str],
        bucket: str,
        tmp_path: pathlib.Path,
    ):
        """An absent prefix is not an error, and produces no files.

        This is the branch that depends on `page.get("Contents", [])`: moto and
        AWS both omit `Contents` entirely when nothing matches, so an
        implementation reading `page["Contents"]` would raise KeyError here.
        """
        destination = tmp_path / "back"
        result = run_helper(
            helper, ["download", bucket, "no-such-prefix", str(destination)], child_env
        )

        assert result.returncode == 0, result.stderr
        assert "downloaded 0 file(s)" in result.stdout, result.stdout
        assert destination.is_dir(), "the destination should still be created"
        assert list(destination.iterdir()) == []

    def test_download_skips_a_directory_marker_key(
        self,
        helper: Helper,
        child_env: dict[str, str],
        bucket: str,
        s3,
        tmp_path: pathlib.Path,
    ):
        """A key ending in `/` is a console-created folder marker, not a file."""
        s3.put_object(Bucket=bucket, Key="run/folder/", Body=b"")
        s3.put_object(Bucket=bucket, Key="run/folder/real.txt", Body=b"real")

        destination = tmp_path / "back"
        result = run_helper(
            helper, ["download", bucket, "run", str(destination)], child_env
        )

        assert result.returncode == 0, result.stderr
        assert "downloaded 1 file(s)" in result.stdout, result.stdout
        assert (destination / "folder" / "real.txt").read_bytes() == b"real"

    def test_upload_of_an_empty_directory_uploads_nothing(
        self,
        helper: Helper,
        child_env: dict[str, str],
        bucket: str,
        s3,
        tmp_path: pathlib.Path,
    ):
        """An empty output directory is what a shard that died early leaves."""
        source = tmp_path / "out"
        source.mkdir()

        result = run_helper(helper, ["upload", str(source), bucket, "run"], child_env)

        assert result.returncode == 0, result.stderr
        assert "uploaded 0 file(s)" in result.stdout, result.stdout
        assert keys_under(s3, bucket, "run/") == []


class TestArgumentHandling:
    def test_upload_rejects_a_source_that_is_not_a_directory(
        self,
        helper: Helper,
        child_env: dict[str, str],
        bucket: str,
        tmp_path: pathlib.Path,
    ):
        missing = tmp_path / "not-there"
        result = run_helper(helper, ["upload", str(missing), bucket, "run"], child_env)

        assert result.returncode == 2
        assert "is not a directory" in result.stderr, result.stderr

    @pytest.mark.parametrize(
        "args",
        [
            pytest.param([], id="no-subcommand"),
            pytest.param(["sideways"], id="unknown-subcommand"),
            pytest.param(["upload", "only-one-arg"], id="upload-wrong-arity"),
            pytest.param(["download", "a", "b"], id="download-wrong-arity"),
        ],
    )
    def test_bad_invocation_exits_two(
        self, helper: Helper, child_env: dict[str, str], args: list[str]
    ):
        """Exit 2, not a traceback and not 0.

        A buildspec phase reads the exit status. Exiting 0 on a usage error would
        let the shard report success having uploaded nothing.
        """
        result = run_helper(helper, args, child_env)
        assert result.returncode == 2, (
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert "Traceback" not in result.stderr, result.stderr


# ---------------------------------------------------------------------------
# The committed buildspec command strings, executed verbatim.
# ---------------------------------------------------------------------------


class TestCommittedBuildspecCommands:
    """Run what the template actually says, through a shell.

    The tests above invoke the helper directly, which proves the Python is
    correct but not that the buildspec calls it correctly -- wrong argument
    order, an unquoted variable or a stale flag would all survive them. These
    execute the command string from the committed template, with only the
    hard-coded `/tmp` helper path redirected to a per-test file.
    """

    @staticmethod
    def _materialize_and_run(
        buildspec: dict,
        phase: str,
        subcommand: str,
        tmp_path: pathlib.Path,
        child_env: dict[str, str],
        cwd: pathlib.Path,
        extra_env: dict[str, str],
    ) -> subprocess.CompletedProcess:
        """Run the committed materialize command, then the committed invocation."""
        helper_path = tmp_path / "ash-s3-sync.py"

        materialize = rewrite_helper_path(
            sole_command_containing(buildspec, "pre_build", "<<'PY'"), str(helper_path)
        )
        invocation = rewrite_helper_path(
            helper_invocation(buildspec, phase, subcommand), str(helper_path)
        )

        env = dict(child_env)
        env.update(extra_env)

        setup = subprocess.run(
            ["sh", "-c", materialize],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
        assert setup.returncode == 0, setup.stderr
        assert helper_path.is_file(), "the heredoc did not write the helper"

        return subprocess.run(
            ["sh", "-c", invocation],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(cwd),
            timeout=300,
        )

    @posix_shell_only
    def test_shard_post_build_uploads_its_results(
        self, child_env: dict[str, str], bucket: str, s3, tmp_path: pathlib.Path
    ):
        """The shard's real post_build command publishes ./ash-shard-output.

        The directory name, the bucket variable and the
        `${ASH_RESULTS_PREFIX}/shard-${ASH_SHARD_INDEX}` key layout all come from
        the template, so this fails if any of them is changed without the merge
        side being changed to match.
        """
        workdir = tmp_path / "build"
        results = workdir / "ash-shard-output"
        (results / "reports").mkdir(parents=True)
        (results / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
        (results / "reports" / "ash.summary.md").write_text("# s\n", encoding="utf-8")

        result = self._materialize_and_run(
            _shard_buildspec(),
            "post_build",
            "upload",
            tmp_path,
            child_env,
            cwd=workdir,
            extra_env={
                "ASH_RESULTS_BUCKET": bucket,
                "ASH_RESULTS_PREFIX": "runs/abc123",
                "ASH_SHARD_INDEX": "2",
            },
        )

        assert result.returncode == 0, f"{result.stdout!r} {result.stderr!r}"
        assert keys_under(s3, bucket, "runs/abc123/shard-2/") == [
            "runs/abc123/shard-2/ash_aggregated_results.json",
            "runs/abc123/shard-2/reports/ash.summary.md",
        ]

    @posix_shell_only
    def test_merge_pre_build_downloads_every_shard(
        self, child_env: dict[str, str], bucket: str, s3, tmp_path: pathlib.Path
    ):
        """The merge's real pre_build command collects all four shards.

        Proves the two halves agree: the keys this reads back are the ones the
        shard command above writes, under the same prefix layout. It lands them
        in `./shard-results/shard-N`, which is exactly where the merge's own
        completeness check and `ash merge --results` look.
        """
        for shard in range(4):
            s3.put_object(
                Bucket=bucket,
                Key=f"runs/abc123/shard-{shard}/ash_aggregated_results.json",
                Body=json.dumps({"shard": shard}).encode(),
            )

        workdir = tmp_path / "build"
        workdir.mkdir()

        result = self._materialize_and_run(
            _merge_buildspec(),
            "pre_build",
            "download",
            tmp_path,
            child_env,
            cwd=workdir,
            extra_env={
                "ASH_RESULTS_BUCKET": bucket,
                "ASH_RESULTS_PREFIX": "runs/abc123",
                "ASH_SHARD_COUNT": "4",
            },
        )

        assert result.returncode == 0, f"{result.stdout!r} {result.stderr!r}"
        for shard in range(4):
            landed = (
                workdir
                / "shard-results"
                / f"shard-{shard}"
                / "ash_aggregated_results.json"
            )
            assert landed.is_file(), f"shard {shard} did not land at {landed}"
            assert json.loads(landed.read_text(encoding="utf-8")) == {"shard": shard}

    @posix_shell_only
    def test_merge_post_build_masks_a_failed_upload(
        self, child_env: dict[str, str], tmp_path: pathlib.Path
    ):
        """DOCUMENTS A GAP, does not endorse it.

        The merge's post_build upload of the merged report ends in `|| true`, so a
        failed publish exits 0 and the pipeline reports success having published
        nothing. This test pins that behavior so the gap is visible in the suite
        and so removing `|| true` shows up here as an intentional change rather
        than an unexplained red. The shard upload deliberately has no such
        suffix, which the test above depends on.

        Owned by another lane's file; reported rather than changed.
        """
        merge = _merge_buildspec()
        command = helper_invocation(merge, "post_build", "upload")
        assert command.rstrip().endswith("|| true"), (
            "the merge post_build upload no longer ends in `|| true`. If that was "
            "deliberate, delete this test -- the silent-failure gap it documents "
            "is closed."
        )

        workdir = tmp_path / "build"
        (workdir / "ash-merged-output").mkdir(parents=True)
        (workdir / "ash-merged-output" / "ash_aggregated_results.json").write_text(
            "{}", encoding="utf-8"
        )

        # A bucket that does not exist in moto, so the upload genuinely fails.
        result = self._materialize_and_run(
            merge,
            "post_build",
            "upload",
            tmp_path,
            child_env,
            cwd=workdir,
            extra_env={
                "ASH_RESULTS_BUCKET": "bucket-that-does-not-exist-in-moto",
                "ASH_RESULTS_PREFIX": "runs/abc123",
            },
        )

        assert result.returncode == 0, (
            "expected `|| true` to mask the failure; a non-zero status here means "
            "the masking is gone and this test should be deleted"
        )
        # The failure is real -- it is only the exit status that hides it. Named
        # precisely, because a looser assertion here would be vacuous: the helper
        # prints its own name on SUCCESS too, so testing for "ash" on stderr would
        # pass even if the upload had somehow worked.
        assert "NoSuchBucket" in result.stderr, result.stderr
        assert "uploaded" not in result.stdout, (
            f"the helper reported an upload against a bucket that does not exist: "
            f"{result.stdout!r}"
        )

    def test_every_shard_and_merge_project_materializes_the_helper(self):
        """All five projects write the helper before any phase uses it.

        A project that invoked the helper without materializing it first would
        fail at runtime with "No such file or directory", and only for that one
        shard. CodeBuild phases of one build share a filesystem, so pre_build
        covers a later post_build -- but only if pre_build actually has the write.
        """
        template = _sharded_pipeline_template()
        projects = projects_containing(template, HELPER_MARKER)
        assert len(projects) == 5, sorted(projects)

        for logical_id, spec in sorted(projects.items()):
            materialize = sole_command_containing(spec, "pre_build", "<<'PY'")
            assert "def download(" in heredoc_body(materialize), logical_id

    def test_no_project_shells_out_to_the_absent_aws_cli(self):
        """The regression that started this: `aws` is not in the ASH image.

        Asserts on the whole rendered template rather than the four known call
        sites, so a NEW `aws ...` command added anywhere in a shard or merge
        buildspec is caught too. Matching is on word boundaries because
        `ASH_RESULTS_BUCKET` and `aws_region` contain the letters.
        """
        template = _sharded_pipeline_template()
        offenders: list[str] = []
        for logical_id, spec in projects_containing(template, HELPER_MARKER).items():
            for phase in ("pre_build", "build", "post_build"):
                for command in (
                    spec.get("phases", {}).get(phase, {}).get("commands", [])
                ):
                    for line in command.splitlines():
                        stripped = line.strip()
                        if stripped.startswith("#"):
                            continue
                        if stripped.startswith("aws ") or " aws " in f" {stripped} ":
                            offenders.append(f"{logical_id}/{phase}: {stripped[:100]}")
        assert offenders == [], (
            "these buildspecs run in the ASH image, which ships no AWS CLI; "
            f"`aws` here exits 127 at runtime: {offenders}"
        )
