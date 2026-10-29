# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""An off-host reporter runs only as the operator configured it.

A reporter that sends findings off the host (``sends_off_host``: the four AWS
reporters, or any plugin's) does it with the host's credentials. Whether it runs,
and where it sends (a bucket, a log group, a model, a Region, a profile), must not
be read from the resolved configuration whatever had set it: a repository's own
``.ash/.ash.yaml`` naming ``ash_aws_plugins`` and setting ``s3: {enabled: true,
bucket_name: repo-chosen-bucket}`` would make a scan of it call STS and HeadBucket
and put the findings in that bucket, and a config an MCP client uploaded the same.

So when the configuration was built from a file the scanned repository could
write (or an MCP client supplied), an off-host reporter's whole section comes
from the operator: the trusted base (the defaults, ASH_CONFIG's file, or the
operator's config file outside the tree) with ``--config-overrides`` applied.

The scans here run in a child process against a loopback stand-in for AWS
(tests/utils/aws_stand_in.py), which records every request and the Region each
is signed for.

The operator loads the AWS plugin module in every case, with their own override:
a repository's file that named it would also test whether such a file may load a
module, a separate rule that hides this one where it holds. Each case where the
repository's settings must not be used has a twin where the operator's are, and
their destination receives the send.

The decoy-section cases (test_a_decoy_section_does_not_let_the_repository_choose_the_scope,
test_a_mirrored_decoy_takes_the_scope_the_operators_own_file_sets,
test_a_decoy_section_does_not_reach_ash_report_either and
test_a_mirrored_decoy_does_not_turn_on_archiving_in_ash_report) need what the Security
Hub import is built on: a reporter that imports findings (BatchImportFindings)
and archives them, and the ``scan_source`` and ``changed_files_only: false`` a
scan records in its results' metadata. Where the reporter does not import, or a
scan records neither field, they fail before any question of where a send goes.
They are expected to pass wherever those exist, a merged tree included.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import List

import pytest

from tests.utils import aws_stand_in as stand_in
from tests.utils.helpers import checkout_env
from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

AWS_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"

#: The operator's override that loads the AWS plugin module.
LOAD_AWS = f'ash_plugin_modules+=["{AWS_PLUGIN_MODULE}"]'

#: A Region of the repository's choosing. The operator's is us-east-1
#: (AWS_DEFAULT_REGION in the child); a request signed for this one used the
#: repository's.
REPO_REGION = "eu-west-3"

#: For each AWS reporter: its section name, and the options that would let it
#: send somewhere of the repository's choosing.
SECTIONS = {
    "s3": {
        "bucket_name": "repo-chosen-bucket",
        "aws_region": REPO_REGION,
        "max_retries": 0,
    },
    "cloudwatch-logs": {
        "log_group_name": "repo-chosen-group",
        "aws_region": REPO_REGION,
        "max_retries": 0,
    },
    "bedrock-summary-reporter": {
        "model_id": "repo-chosen-model",
        "aws_region": REPO_REGION,
    },
    "aws-security-hub": {
        "aws_region": REPO_REGION,
        "account_id": "123456789012",
        "findings_scope": "repo-chosen-scope",
    },
}

#: The operator's own destination for each reporter, as overrides.
OPERATOR_DESTINATIONS = {
    "s3": {
        "bucket_name": "operator-bucket",
        "aws_region": "us-east-1",
        "max_retries": "0",
    },
    "cloudwatch-logs": {
        "log_group_name": "operator-group",
        "aws_region": "us-east-1",
        "max_retries": "0",
    },
    "bedrock-summary-reporter": {
        "model_id": "operator-model",
        "aws_region": "us-east-1",
    },
}


def _operator_enables(section: str, destination: bool = True) -> List[str]:
    """The operator's overrides: load the module, turn *section* on, aim it."""
    overrides = [LOAD_AWS, f"reporters.{section}.enabled=true"]
    if destination:
        overrides += [
            f"reporters.{section}.options.{option}={value}"
            for option, value in OPERATOR_DESTINATIONS[section].items()
        ]
    return overrides


def _reached_the_operator(
    section: str, requests: List[tuple], bodies: List[tuple]
) -> bool:
    """Whether *section*'s reporter contacted the operator's destination."""
    if section == "s3":
        puts = [what for _, what in requests if what.startswith("PutObject")]
        return bool(puts) and all(
            what.startswith("PutObject /operator-bucket/") for what in puts
        )
    if section == "cloudwatch-logs":
        return any("operator-group" in body for _, body in bodies)
    # Bedrock checks the model against the models its Region lists first; the
    # stand-in refuses that, so the call it makes, signed for the operator's
    # Region, is what reaches the operator's destination.
    return any(what.startswith("/foundation-models") for _, what in requests)


@pytest.fixture
def aws():
    """The stand-in's URL, its requests, and each request's body and Region."""
    bodies: List[tuple] = []
    with stand_in.aws_stand_in(bodies=bodies) as (url, requests):
        yield url, requests, bodies


def _section_only(section: str, body: str) -> str:
    """A config with *section* under reporters and no ash_plugin_modules."""
    return f"reporters:\n  {section}:\n{body}"


def _options_block(options: dict, enabled: bool = False) -> str:
    lines = ["    enabled: true"] if enabled else []
    lines.append("    options:")
    lines += [f"      {key}: {json.dumps(value)}" for key, value in options.items()]
    return "\n".join(lines) + "\n"


def _repository_enables(section: str) -> str:
    """The repository's config: *section* on, aimed where the repository chose."""
    return _section_only(section, _options_block(SECTIONS[section], enabled=True))


def _anything_repo_chosen(requests: List[tuple], bodies: List[tuple]) -> List[tuple]:
    return [
        item
        for item in [*requests, *bodies]
        if "repo-chosen" in item[1] or item == ("region", REPO_REGION)
    ]


def _config_enabling(section: str, options: dict) -> str:
    """The operator's own config file: the module, and *section* on and aimed."""
    lines = [
        "ash_plugin_modules:",
        f"  - {AWS_PLUGIN_MODULE}",
        "reporters:",
        f"  {section}:",
        "    enabled: true",
        "    options:",
    ]
    lines += [f"      {key}: {json.dumps(value)}" for key, value in options.items()]
    return "\n".join(lines) + "\n"


def _source_tree(root: Path, in_tree_config: str = "") -> Path:
    source = root / "src"
    source.mkdir(parents=True)
    (source / "app.py").write_text("value = 1\n", encoding="utf-8")
    if in_tree_config:
        (source / ".ash").mkdir()
        (source / ".ash" / ".ash.yaml").write_text(in_tree_config, encoding="utf-8")
    return source


def _scan_in_a_child(tmp_path: Path, endpoint: str, **kwargs):
    """run_ash_scan in a fresh interpreter, with detect-secrets only."""
    arguments = {
        "output_dir": str(tmp_path / "out"),
        "scanners": ["detect-secrets"],
        "offline": True,
        "progress": False,
        "quiet": True,
        "show_summary": False,
        "fail_on_findings": False,
        "color": False,
        **kwargs,
    }
    # The child's probes are answered first: it found the uv installed with ASH
    # beside its interpreter and ran ``uv tool run --offline detect-secrets
    # --version``, which left uv's tool-directory lock in the test's HOME.
    code = CHILD_TOOL_PROBE_STUBS + (
        "import json, sys\n"
        "from automated_security_helper.interactions.run_ash_scan import run_ash_scan\n"
        "run_ash_scan(**json.loads(sys.argv[1]))\n"
    )
    return subprocess.run(
        [sys.executable, "-c", code, json.dumps(arguments)],
        capture_output=True,
        text=True,
        timeout=600,
        cwd=tmp_path,
        env=checkout_env(stand_in.child_aws_env(tmp_path, endpoint)),
        check=False,
    )


@pytest.mark.parametrize("section", sorted(SECTIONS))
@pytest.mark.integration
def test_a_config_the_repository_wrote_does_not_turn_an_off_host_reporter_on(
    tmp_path, aws, section
):
    """The operator loads the module; the repository's file turns *section* on
    and aims it. Nothing is sent: the twin below sends with the operator's."""
    endpoint, requests, bodies = aws
    source = _source_tree(tmp_path, _repository_enables(section))

    result = _scan_in_a_child(
        tmp_path, endpoint, source_dir=str(source), config_overrides=[LOAD_AWS]
    )

    assert "Traceback" not in result.stderr, result.stderr
    assert (tmp_path / "out" / "ash_aggregated_results.json").is_file(), result.stderr
    assert requests == [], (requests, result.stderr[-2000:])


@pytest.mark.parametrize("section", sorted(OPERATOR_DESTINATIONS))
@pytest.mark.integration
def test_the_operators_destination_receives_it_past_the_repositorys(
    tmp_path, aws, section
):
    """The twin: the repository's file turns *section* on and aims it, and
    the operator's overrides turn it on and aim it too. The operator's
    destination is contacted, and nothing the repository chose is."""
    endpoint, requests, bodies = aws
    source = _source_tree(tmp_path, _repository_enables(section))

    result = _scan_in_a_child(
        tmp_path,
        endpoint,
        source_dir=str(source),
        config_overrides=_operator_enables(section),
    )

    assert "Traceback" not in result.stderr, result.stderr
    assert _reached_the_operator(section, requests, bodies), (
        requests,
        result.stderr[-2000:],
    )
    assert _anything_repo_chosen(requests, bodies) == [], (requests, bodies)


@pytest.mark.unit
def test_the_default_chains_operator_files_reach_the_reporter_view(
    tmp_path, monkeypatch
):
    """No config file is selected, so the configuration is the ASH_CONFIG
    chain: an operator root outside every checkout enables the reporter and
    extends a base inside the scanned tree, so the trusted base is the plain
    defaults. The operator reporter view reads the chain the configuration
    came from, so the root's enable reaches the section the reporter runs
    with; a view that replays only the selected chain replayed nothing here,
    and the operator's own enable silently did not apply."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporter,
    )
    from tests.utils.helpers import mark_git_checkout

    ops = tmp_path / "ops"
    source = ops / "src"
    mark_git_checkout(source)
    base = source / "cfg" / "base.yaml"
    base.parent.mkdir(parents=True)
    base.write_text("project_name: repo-base\n", encoding="utf-8")
    root = ops / "ash.yaml"
    root.write_text(
        f"extends:\n  - {base.as_posix()}\n"
        "reporters:\n  aws-security-hub:\n    enabled: true\n"
        "    options:\n      aws_region: us-west-2\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))

    config = resolve_config(config_path=None, source_dir=source)

    section = reporter_section(config, SecurityHubReporter) or {}
    plain = section.model_dump() if hasattr(section, "model_dump") else dict(section)
    assert plain.get("enabled") is True, plain
    assert (plain.get("options") or {}).get("aws_region") == "us-west-2", plain


def _stored_results(output: Path) -> None:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    output.mkdir()
    (output / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
    )


def _report_s3_in_the_checkout(tmp_path: Path, endpoint: str, overrides: List[str]):
    """`ash report --format s3 --config .ash/.ash.yaml`, run in the checkout,
    where that file turns S3 on and aims it at the repository's bucket."""
    source = _source_tree(tmp_path, _repository_enables("s3"))
    output = tmp_path / "out"
    _stored_results(output)
    argv = [
        sys.executable,
        "-c",
        "from automated_security_helper.cli.main import app; app()",
        "report",
        "--format",
        "s3",
        "--output-dir",
        str(output),
        "--config",
        str(source / ".ash" / ".ash.yaml"),
        "--no-color",
    ]
    for override in overrides:
        argv += ["--config-overrides", override]
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=300,
        cwd=source,
        env=checkout_env(stand_in.child_aws_env(tmp_path, endpoint)),
        check=False,
    )


@pytest.mark.integration
def test_ash_report_in_the_repository_does_not_send_with_its_config(tmp_path, aws):
    """The operator loads the module and turns nothing on: refused, nothing sent."""
    endpoint, requests, bodies = aws

    result = _report_s3_in_the_checkout(tmp_path, endpoint, [LOAD_AWS])

    assert result.returncode == 1, (result.stdout, result.stderr)
    assert requests == [], requests


@pytest.mark.integration
def test_ash_report_sends_to_the_operators_bucket_past_the_repositorys_config(
    tmp_path, aws
):
    """The twin: the operator's overrides turn S3 on and aim it. The upload goes
    to the operator's bucket, signed for the operator's Region."""
    endpoint, requests, bodies = aws

    result = _report_s3_in_the_checkout(tmp_path, endpoint, _operator_enables("s3"))

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert _reached_the_operator("s3", requests, bodies), (requests, result.stderr)
    assert _anything_repo_chosen(requests, bodies) == [], (requests, bodies)


def _upload_from_a_client(tmp_path: Path) -> Path:
    """An MCP client's uploaded config: outside the tree, and untrusted. It turns
    S3 on and aims it at a bucket of the client's choosing."""
    upload = tmp_path / "uploads" / "client.yaml"
    upload.parent.mkdir()
    options = dict(SECTIONS["s3"], bucket_name="repo-chosen-client-bucket")
    upload.write_text(
        _section_only("s3", _options_block(options, enabled=True)), encoding="utf-8"
    )
    return upload


def _refused_the_clients_file(result) -> bool:
    """Whether the scan refused the client's file outright: exit 3, naming the
    S3 field the server's runtime-override policy denies a client. A server
    may do that instead of scanning with the file's off-host sections left
    out; either way nothing is sent."""
    said = " ".join((result.stdout + result.stderr).split())
    return (
        result.returncode == 3
        and "reporters.s3.enabled" in said
        and "denied_paths" in said
    )


@pytest.mark.integration
def test_a_config_an_mcp_client_uploaded_does_not_turn_one_on(tmp_path, aws):
    """The client's file turns S3 on: the scan either runs without its S3
    section or refuses the file, and sends nothing."""
    endpoint, requests, bodies = aws
    source = _source_tree(tmp_path)

    result = _scan_in_a_child(
        tmp_path,
        endpoint,
        source_dir=str(source),
        config=str(_upload_from_a_client(tmp_path)),
        untrusted_config=True,
        config_overrides=[LOAD_AWS],
    )

    assert "Traceback" not in result.stderr, result.stderr
    assert (
        _refused_the_clients_file(result)
        or (tmp_path / "out" / "ash_aggregated_results.json").is_file()
    ), (result.returncode, result.stdout[-2000:], result.stderr[-2000:])
    assert requests == [], (requests, result.stderr[-2000:])


@pytest.mark.integration
def test_the_operators_overrides_reach_past_an_mcp_clients_config(tmp_path, aws):
    """The twin: the operator's overrides turn S3 on and aim it. Where the
    server refuses the client's file outright, no reporter runs, so nothing is
    sent at all."""
    endpoint, requests, bodies = aws
    source = _source_tree(tmp_path)

    result = _scan_in_a_child(
        tmp_path,
        endpoint,
        source_dir=str(source),
        config=str(_upload_from_a_client(tmp_path)),
        untrusted_config=True,
        config_overrides=_operator_enables("s3"),
    )

    assert "Traceback" not in result.stderr, result.stderr
    if _refused_the_clients_file(result):
        assert requests == [], (requests, result.stderr[-2000:])
        return
    assert _reached_the_operator("s3", requests, bodies), (
        requests,
        result.stderr[-2000:],
    )
    assert _anything_repo_chosen(requests, bodies) == [], (requests, bodies)


@pytest.mark.integration
def test_the_operators_overrides_reach_past_a_clients_config_that_sets_no_reporter(
    tmp_path, aws
):
    """The client's file sets only its project's name, which no server refuses,
    and the operator's overrides turn S3 on and aim it: the operator's bucket
    receives the send, whichever way a server treats a client's off-host
    sections. The twin above can only check that where the file is scanned."""
    endpoint, requests, bodies = aws
    source = _source_tree(tmp_path)
    upload = tmp_path / "uploads" / "client.yaml"
    upload.parent.mkdir()
    upload.write_text("project_name: client-project\n", encoding="utf-8")

    result = _scan_in_a_child(
        tmp_path,
        endpoint,
        source_dir=str(source),
        config=str(upload),
        untrusted_config=True,
        config_overrides=_operator_enables("s3"),
    )

    assert "Traceback" not in result.stderr, result.stderr
    assert _reached_the_operator("s3", requests, bodies), (
        result.returncode,
        requests,
        result.stdout[-2000:],
        result.stderr[-2000:],
    )
    assert _anything_repo_chosen(requests, bodies) == [], (requests, bodies)


@pytest.mark.integration
def test_the_operators_config_file_outside_the_tree_turns_it_on(tmp_path, aws):
    """Control: an operator --config outside the tree enables S3 to its bucket."""
    endpoint, requests, bodies = aws
    source = _source_tree(tmp_path)
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    options = dict(
        SECTIONS["s3"], bucket_name="operator-bucket", aws_region="us-east-1"
    )
    operator.write_text(_config_enabling("s3", options), encoding="utf-8")

    result = _scan_in_a_child(
        tmp_path, endpoint, source_dir=str(source), config=str(operator)
    )

    assert "Traceback" not in result.stderr, result.stderr
    puts = [what for service, what in requests if what.startswith("PutObject")]
    assert puts and all(
        what.startswith("PutObject /operator-bucket/") for what in puts
    ), (
        requests,
        result.stderr[-2000:],
    )


# --------------------------------------------------------------------------- #
# A decoy section under another spelling of the reporter's name
# --------------------------------------------------------------------------- #
#
# get_plugin_config finds a reporter's section under several spellings
# (aws-security-hub, aws_security_hub, AwsSecurityHub). The repository sets the
# options under one spelling and an empty decoy under another, and the operator's
# overrides use the decoy's spelling. A check that asked whether "an override
# writes this option" by comparing spellings loosely took the overrides as having
# set the repository's options, kept findings_scope: victim and
# archive_resolved_findings: true, and the scan archived the victim scope's
# findings. The operator's record is built from the trusted base and the overrides
# alone, so the repository's sections never reach it under any spelling.
#
# The operator loads the AWS plugin module, with their own override. A decoy file
# that named it would also test whether a repository's file may load a module,
# which is a different rule; here the reporter loads either way, and only the
# section it reads is in question.

DECOY = """
reporters:
  aws-security-hub:
    enabled: true
    options:
      aws_region: us-east-1
      findings_scope: victim
      archive_resolved_findings: true
  aws_security_hub:
    options: {}
"""

#: The same decoy mirrored: the empty section first, under the reporter's
#: CamelCase spelling, and the repository's payload last, under the underscore
#: spelling. No section has the reporter's own name, so the lookup by that name
#: reaches the payload, as the lookup by any --format spelling does: each
#: resolves a stripped spelling to the last-listed section. A confinement that
#: looked at the reporter's own key alone would leave the payload in place, and
#: the reporter would import, and archive, under the repository's scope.
DECOY_MIRRORED = """
reporters:
  AwsSecurityHub:
    options: {}
  aws_security_hub:
    enabled: true
    options:
      aws_region: us-east-1
      findings_scope: victim
      archive_resolved_findings: true
"""


def _operator_overrides(key: str, archives: bool = False) -> List[str]:
    """The operator's overrides, under section spelling *key*."""
    overrides = [
        f'ash_plugin_modules+=["{AWS_PLUGIN_MODULE}"]',
        f"reporters.{key}.enabled=true",
        f"reporters.{key}.options.aws_region=us-east-1",
        f"reporters.{key}.options.findings_scope=operator-scope",
    ]
    if archives:
        overrides.append(f"reporters.{key}.options.archive_resolved_findings=true")
    return overrides


OPERATOR_OVERRIDES = _operator_overrides("aws_security_hub")


@pytest.fixture
def security_hub():
    bodies: List[tuple] = []
    with stand_in.aws_stand_in(security_hub=True, bodies=bodies) as (url, requests):
        yield url, requests, bodies


@pytest.fixture
def security_hub_with_stored_findings():
    """The stand-in, with the list GetFindings answers from, empty at first."""
    bodies: List[tuple] = []
    stored: List[dict] = []
    with stand_in.aws_stand_in(
        security_hub=True, bodies=bodies, stored_findings=stored
    ) as (url, requests):
        yield url, requests, bodies, stored


def _with_a_finding(source: Path) -> None:
    """A line detect-secrets reports, built here so this file holds no secret."""
    keyword = "pass" + "word"
    value = "".join(chr(ord("a") + (index * 7) % 26) for index in range(24))
    (source / "creds.py").write_text(f'{keyword} = "{value}"\n', encoding="utf-8")


def _archived_or_victim(requests: List[tuple], bodies: List[tuple]) -> List[tuple]:
    return [
        request
        for request in requests
        if request[1].startswith(("POST /findings?", "PATCH /findings/batchupdate"))
        or request[1] == "POST /findings"
    ] + [body for body in bodies if "victim" in body[1]]


@pytest.mark.integration
def test_a_decoy_section_does_not_let_the_repository_choose_the_scope(
    tmp_path, security_hub
):
    # Needs the Security Hub import and a scan's scan_source and
    # changed_files_only metadata (see the module docstring).
    endpoint, requests, bodies = security_hub
    source = _source_tree(tmp_path, DECOY)
    _with_a_finding(source)

    result = _scan_in_a_child(
        tmp_path, endpoint, source_dir=str(source), config_overrides=OPERATOR_OVERRIDES
    )

    assert "Traceback" not in result.stderr, result.stderr
    # The reporter ran, with the operator's scope: it checked the hub and imported.
    assert ("securityhub", "GET /accounts") in requests, (requests, result.stderr)
    imported = _findings_imported(bodies)
    assert imported, (requests, result.stderr[-2000:])
    assert {finding["ProductFields"]["ash/target"] for finding in imported} == {
        "operator-scope"
    }, imported
    # And nothing was read or archived under the repository's scope.
    assert _archived_or_victim(requests, bodies) == [], (requests, bodies)


@pytest.mark.integration
def test_a_mirrored_decoy_takes_the_scope_the_operators_own_file_sets(
    tmp_path, security_hub, monkeypatch
):
    """The operator's findings_scope is in the ASH_CONFIG file, outside the
    scanned tree, and the repository's mirrored decoy is in the tree.

    In the other decoy cases the operator sets the scope in an override, which
    reaches the reporter only through the operator's section, put in place of
    the repository's. Here the trusted base holds it, so confining the
    repository's options to the operator's values hands the reporter the
    operator's scope by itself, under whichever spelling it reads.

    Needs the Security Hub import and a scan's scan_source and
    changed_files_only metadata (see the module docstring).
    """
    endpoint, requests, bodies = security_hub
    source = _source_tree(tmp_path, DECOY_MIRRORED)
    _with_a_finding(source)
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        _config_enabling(
            "aws-security-hub",
            {"aws_region": "us-east-1", "findings_scope": "operator-scope"},
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    result = _scan_in_a_child(
        tmp_path, endpoint, source_dir=str(source), config_overrides=[LOAD_AWS]
    )

    assert "Traceback" not in result.stderr, result.stderr
    assert ("securityhub", "GET /accounts") in requests, (requests, result.stderr)
    imported = _findings_imported(bodies)
    assert imported, (requests, result.stderr[-2000:])
    assert {finding["ProductFields"]["ash/target"] for finding in imported} == {
        "operator-scope"
    }, imported
    assert _archived_or_victim(requests, bodies) == [], (requests, bodies)


def _results_the_reporter_imports_and_archives(
    tmp_path: Path, endpoint: str, decoy: str = DECOY
) -> Path:
    """The source tree, after a real scan of it wrote results Security Hub acts on.

    Results with no findings, or that do not say they are unfiltered and where
    they were scanned, take the reporter's "no findings to import" return before
    it reads its scope, so a test fed them passes whatever scope the reporter
    holds. These come from a scan of a tree with a finding in it, and are
    checked for what the reporter needs: a finding to import, and, for
    archiving, ``changed_files_only: false``, a ``scan_source`` and a scanner
    that finished without losing a target.
    """
    source = _source_tree(tmp_path)
    _with_a_finding(source)
    scanned = _scan_in_a_child(tmp_path, endpoint, source_dir=str(source))
    assert "Traceback" not in scanned.stderr, scanned.stderr
    results = json.loads(
        (tmp_path / "out" / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    metadata = results["metadata"]
    assert metadata.get("changed_files_only") is False, metadata
    assert metadata.get("scan_source"), metadata
    sarif_results = [
        result
        for run in (results.get("sarif") or {}).get("runs") or []
        for result in run.get("results") or []
    ]
    assert sarif_results, "the scan reported no finding to import"
    detect_secrets = results["scanner_results"]["detect-secrets"]
    assert detect_secrets["status"] in ("PASSED", "FAILED"), detect_secrets
    # The decoy goes in after the scan, so the scan itself had nothing to send.
    (source / ".ash").mkdir()
    (source / ".ash" / ".ash.yaml").write_text(decoy, encoding="utf-8")
    return source


def _findings_imported(bodies: List[tuple]) -> List[dict]:
    return [
        finding
        for what, body in bodies
        if what.startswith("POST /findings/import")
        for finding in json.loads(body)["Findings"]
    ]


def _get_findings_targets(bodies: List[tuple]) -> List[str]:
    """The ash/target value of every GetFindings filter."""
    return [
        product_field["Value"]
        for what, body in bodies
        if what.split("?")[0] == "POST /findings"
        for product_field in json.loads(body)["Filters"]["ProductFields"]
        if product_field["Key"] == "ash/target"
    ]


#: (the decoy file, the spelling the operator's overrides use, the --format
#: spelling). In the first, the repository's payload is under the reporter's own
#: name and --format names it, the spelling ``ash report`` looks the section up
#: by: ``--format AWS-Security-Hub`` would find the decoy's spelling, where the
#: operator's overrides are, whatever the confinement does. The second mirrors
#: it: the payload is under another spelling, last, the overrides are under the
#: empty section's spelling, and no section has the reporter's own name, so the
#: section the reporter reads, by its own name or by the --format spelling, is
#: the payload wherever the confinement misses it, and the import goes to the
#: repository's scope.
DECOY_SHAPES = {
    "payload-under-the-reporters-name": (DECOY, "aws_security_hub", "aws-security-hub"),
    "payload-under-another-spelling": (
        DECOY_MIRRORED,
        "AwsSecurityHub",
        "AWS-Security-Hub",
    ),
}

#: Ids of the two stored findings GetFindings returns.
STALE_OPERATOR = "ash/stale-operator-scope-finding"
STALE_VICTIM = "ash/stale-victim-scope-finding"


def _stale(template: dict, finding_id: str, target: str) -> dict:
    """A stored, still ACTIVE finding of *target*, last updated long before the
    scan: one a scan of that scope that no longer reports it would archive."""
    stale = json.loads(json.dumps(template))
    stale.update(
        Id=finding_id,
        RecordState="ACTIVE",
        CreatedAt="2000-01-01T00:00:00.000Z",
        UpdatedAt="2000-01-01T00:00:00.000Z",
    )
    stale["ProductFields"]["ash/target"] = target
    return stale


def _report_security_hub(tmp_path, endpoint, source, format_spelling, overrides):
    argv = [
        sys.executable,
        "-c",
        "from automated_security_helper.cli.main import app; app()",
        "report",
        "--format",
        format_spelling,
        "--output-dir",
        str(tmp_path / "out"),
        "--config",
        str(source / ".ash" / ".ash.yaml"),
        "--no-color",
    ]
    for override in overrides:
        argv += ["--config-overrides", override]
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=300,
        cwd=source,
        env=checkout_env(stand_in.child_aws_env(tmp_path, endpoint)),
        check=False,
    )


@pytest.mark.parametrize(
    "operator_archives", [False, True], ids=["operator-imports", "operator-archives"]
)
@pytest.mark.parametrize("shape", sorted(DECOY_SHAPES))
@pytest.mark.integration
def test_a_decoy_section_does_not_reach_ash_report_either(
    tmp_path, security_hub_with_stored_findings, shape, operator_archives
):
    """`ash report` in the checkout, with a decoy file as its --config, on results
    the reporter imports and, when the operator turns it on, archives.

    The first run gives a finding as the reporter writes it. The second runs
    with two stored ACTIVE findings built from it, one of the operator's scope
    and one of the repository's (victim), both older than the scan and neither
    reported by it. Only the operator's may be archived, and only when the
    operator turned archiving on.

    Needs the Security Hub import and a scan's scan_source and
    changed_files_only metadata (see the module docstring).
    """
    endpoint, requests, bodies, stored = security_hub_with_stored_findings
    decoy, override_key, format_spelling = DECOY_SHAPES[shape]
    source = _results_the_reporter_imports_and_archives(tmp_path, endpoint, decoy)
    assert requests == [], requests
    overrides = _operator_overrides(override_key, archives=operator_archives)

    first = _report_security_hub(tmp_path, endpoint, source, format_spelling, overrides)
    assert first.returncode == 0, (first.stdout, first.stderr)
    template = _findings_imported(bodies)[0]
    stored.extend(
        [
            _stale(template, STALE_OPERATOR, "operator-scope"),
            _stale(template, STALE_VICTIM, "victim"),
        ]
    )
    del requests[:]
    del bodies[:]

    result = _report_security_hub(
        tmp_path, endpoint, source, format_spelling, overrides
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    # The reporter ran and imported, every finding under the operator's scope.
    # `ash report` skips the dependency check (DescribeHub), so the first call
    # is report()'s own account lookup.
    assert ("sts", "GetCallerIdentity") in requests, (requests, result.stderr)
    imported = _findings_imported(bodies)
    assert imported, (requests, result.stderr[-2000:])
    assert {finding["ProductFields"]["ash/target"] for finding in imported} == {
        "operator-scope"
    }, imported
    archived = [f["Id"] for f in imported if f["RecordState"] == "ARCHIVED"]
    receipt = json.loads(result.stdout)
    assert not [body for body in bodies if "victim" in body[1]], bodies
    if operator_archives:
        # It read the stored findings of the operator's scope, and archived the
        # operator's stale one: never the repository's.
        assert _get_findings_targets(bodies) == ["operator-scope"], bodies
        assert archived == [STALE_OPERATOR], imported
        assert receipt["archived_ids"] == [STALE_OPERATOR], receipt
        assert receipt["archive_skipped"] is None, receipt
    else:
        # Nothing was read or archived: archiving is the operator's to turn on.
        assert _archived_or_victim(requests, bodies) == [], (requests, bodies)
        assert archived == [], imported
        assert receipt["archive_skipped"] == "archive_resolved_findings is false"


@pytest.mark.integration
def test_a_mirrored_decoy_does_not_turn_on_archiving_in_ash_report(
    tmp_path, security_hub_with_stored_findings
):
    """`ash report` with the mirrored decoy as its --config, and the operator's
    overrides under the payload's own spelling, setting the scope and not archiving.

    The overrides put the operator's scope in the payload's section, so the
    reporter imports under operator-scope whichever section it reads. What the
    operator left unset, archive_resolved_findings, stays the repository's in that
    section: only confining the repository's options to the operator's values
    keeps it from the reporter, even where the operator's section is not put in
    place of the repository's.

    An ASH_CONFIG cell, like the scan's, would not reach this: with ASH_CONFIG set
    and no --config, `ash report` reads the operator's file and never the decoy.

    Needs the Security Hub import and a scan's scan_source and
    changed_files_only metadata (see the module docstring).
    """
    endpoint, requests, bodies, _stored = security_hub_with_stored_findings
    source = _results_the_reporter_imports_and_archives(
        tmp_path, endpoint, DECOY_MIRRORED
    )
    assert requests == [], requests

    result = _report_security_hub(
        tmp_path,
        endpoint,
        source,
        "AWS-Security-Hub",
        _operator_overrides("aws_security_hub"),
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    imported = _findings_imported(bodies)
    assert imported, (requests, result.stderr[-2000:])
    assert {finding["ProductFields"]["ash/target"] for finding in imported} == {
        "operator-scope"
    }, imported
    # The repository's archive_resolved_findings did not reach the reporter: it
    # read and archived nothing.
    assert _archived_or_victim(requests, bodies) == [], (requests, bodies)
    receipt = json.loads(result.stdout)
    assert receipt["archive_skipped"] == "archive_resolved_findings is false"


# --------------------------------------------------------------------------- #
# The operator loads or enables the reporter; the repository only aims it
# --------------------------------------------------------------------------- #
#
# The operator turns the reporter on and names no destination; the repository's
# file supplies only what it would need to send somewhere of its choosing (a
# bucket, a log group, a model, a Region). Nothing it chose is used. Where the
# operator names a destination too, it receives the send
# (test_the_operators_destination_receives_it_past_the_repositorys).

#: Each reporter's destination options, all of the repository's choosing.
AIMING = {
    "s3": {"bucket_name": "repo-chosen-bucket", "aws_region": REPO_REGION},
    "cloudwatch-logs": {
        "log_group_name": "repo-chosen-group",
        "aws_region": REPO_REGION,
    },
    "bedrock-summary-reporter": {
        "model_id": "repo-chosen-model",
        "aws_region": REPO_REGION,
    },
}


@pytest.mark.parametrize("section", sorted(AIMING))
@pytest.mark.integration
def test_the_operator_enabling_a_reporter_lets_the_repository_aim_it_nowhere(
    tmp_path, aws, section
):
    """The operator loads the module and enables the reporter; the repository's
    file supplies only where it sends. Nothing it chose is contacted or used."""
    endpoint, requests, bodies = aws
    source = _source_tree(
        tmp_path, _section_only(section, _options_block(AIMING[section]))
    )

    result = _scan_in_a_child(
        tmp_path,
        endpoint,
        source_dir=str(source),
        config_overrides=[LOAD_AWS, f"reporters.{section}.enabled=true"],
    )

    assert "Traceback" not in result.stderr, result.stderr
    # The scan ran to its results, so the check below is not about a refused config.
    assert result.returncode == 0, (result.stdout[-2000:], result.stderr[-2000:])
    assert (tmp_path / "out" / "ash_aggregated_results.json").is_file()
    assert _anything_repo_chosen(requests, bodies) == [], (requests, bodies)
