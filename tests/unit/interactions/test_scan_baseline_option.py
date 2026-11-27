import json

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit


def test_bad_baseline_with_nothing_staged_is_refused(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    baseline = tmp_path / "missing.json"
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "fs",
            str(source),
            "--mode",
            "precommit",
            "--staged",
            "--baseline",
            str(baseline),
        ],
    )
    assert response.exit_code == 5
    assert "Error reading --baseline" in response.output


def test_baseline_inside_the_checkout_is_refused(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    baseline = source / "baseline.json"
    baseline.write_text(json.dumps({"metadata": {}, "sarif": {"runs": []}}))
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "fs",
            str(source),
            "--mode",
            "local",
            "--baseline",
            str(baseline),
        ],
    )
    assert response.exit_code == 5
    assert "inside the scanned tree" in response.output


def test_baseline_hard_linked_into_the_scanned_tree_is_refused(tmp_path):
    import os

    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.scan_baseline import (
        BaselineRefused,
        read_baseline,
    )

    source = tmp_path / "source"
    source.mkdir()
    inside = source / "baseline.json"
    inside.write_text(AshAggregatedResults().model_dump_json(by_alias=True))
    outside = tmp_path / "baseline.json"
    try:
        os.link(inside, outside)
    except OSError:
        pytest.skip("hard links are unavailable")
    with pytest.raises(BaselineRefused, match="hard link"):
        read_baseline(outside, source_dir=source, output_dir=tmp_path / "out")


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(["--mode", "container"], id="container"),
        pytest.param(["--mode", "nix"], id="nix"),
        pytest.param(["--shard-index", "0", "--shard-count", "2"], id="shards"),
        pytest.param(["--phases", "convert"], id="phases"),
    ],
)
def test_baseline_refuses_unsupported_scan_scopes(tmp_path, arguments):
    source = tmp_path / "source"
    source.mkdir()
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "fs",
            str(source),
            "--baseline",
            str(tmp_path / "baseline.json"),
            *arguments,
        ],
    )
    assert response.exit_code == 5
    assert "--baseline" in response.output
    assert "not supported" in response.output


def test_baseline_refuses_a_workspace_given_through_the_legacy_option(tmp_path):
    """``--baseline`` with the deprecated ``--workspace`` option is still refused.

    The subject is the legacy spelling. ``ash scan --workspace FILE`` is deprecated and
    removed in ASH v4.0, and until then it keeps the refusal it always gave a baseline.
    ``ash scan workspace FILE`` is the command that replaces it, and ``--baseline``
    belongs to ``ash scan fs``, so this case drives the older form on purpose.
    """
    source = tmp_path / "source"
    source.mkdir()
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(source),
            "--baseline",
            str(tmp_path / "baseline.json"),
            "--workspace",
            "workspace.yaml",
        ],
    )
    assert response.exit_code == 5
    assert "--baseline" in response.output
    assert "not supported" in response.output


def test_baseline_from_another_project_is_refused(tmp_path):
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.scan_baseline import (
        BaselineRefused,
        check_baseline_scope,
        read_baseline,
    )

    source = tmp_path / "source"
    source.mkdir()
    saved = tmp_path / "baseline.json"
    saved.write_text(AshAggregatedResults().model_dump_json(by_alias=True))
    baseline = read_baseline(saved, source_dir=source, output_dir=tmp_path / "out")
    with pytest.raises(BaselineRefused, match="different project"):
        check_baseline_scope(baseline, project_name="different", scan_source=".")


def test_baseline_from_another_directory_is_refused(tmp_path):
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.scan_baseline import (
        BaselineRefused,
        check_baseline_scope,
        read_baseline,
    )

    source = tmp_path / "source"
    source.mkdir()
    results = AshAggregatedResults()
    results.metadata.scan_source = "one"
    saved = tmp_path / "baseline.json"
    saved.write_text(results.model_dump_json(by_alias=True))
    baseline = read_baseline(saved, source_dir=source, output_dir=tmp_path / "out")
    with pytest.raises(BaselineRefused, match="different directory"):
        check_baseline_scope(
            baseline, project_name=results.metadata.project_name, scan_source="two"
        )


def test_use_existing_over_baseline_results_is_refused(tmp_path):
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    baseline = tmp_path / "baseline.json"
    original = AshAggregatedResults()
    baseline.write_text(original.model_dump_json(by_alias=True))
    original.metadata.baseline = {
        "sha256": "x",
        "matched": 1,
        "matched_without_lines": 0,
    }
    (output / "ash_aggregated_results.json").write_text(
        original.model_dump_json(by_alias=True)
    )
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "fs",
            str(source),
            "--mode",
            "local",
            "--output-dir",
            str(output),
            "--use-existing",
            "--baseline",
            str(baseline),
        ],
    )
    assert response.exit_code == 5
    assert "baseline" in response.output


def test_wrong_project_with_nothing_staged_is_refused(tmp_path, monkeypatch):
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    source = tmp_path / "source"
    source.mkdir()
    baseline = tmp_path / "baseline.json"
    results = AshAggregatedResults()
    results.metadata.project_name = "not-the-project"
    baseline.write_text(results.model_dump_json(by_alias=True))
    monkeypatch.setattr(
        "automated_security_helper.utils.staged_files.staged_files_for_source",
        lambda _: [],
    )
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "fs",
            str(source),
            "--mode",
            "precommit",
            "--staged",
            "--baseline",
            str(baseline),
        ],
    )
    assert response.exit_code == 5
    assert "Error reading --baseline" in response.stderr
    assert "different project" in response.stderr


def test_library_refuses_baseline_in_container_mode(tmp_path):
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    with pytest.raises(ValueError, match="baseline"):
        run_ash_scan(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            mode=RunMode.container,
            baseline=str(tmp_path / "missing"),
        )


def test_baseline_inside_the_output_dir_is_refused(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    baseline = output / "baseline.json"
    baseline.write_text("{}")
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "fs",
            str(source),
            "--mode",
            "local",
            "--output-dir",
            str(output),
            "--baseline",
            str(baseline),
        ],
    )
    assert response.exit_code == 5
    assert "inside the output directory" in response.output


def test_baseline_reached_through_a_link_in_the_checkout_is_refused(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    target = tmp_path / "baseline.json"
    target.write_text("{}")
    link = source / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable")
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "fs",
            str(source),
            "--mode",
            "local",
            "--baseline",
            str(link),
        ],
    )
    assert response.exit_code == 5
    assert "scanned tree" in response.output


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {"shard": {"index": 0, "count": 2}},
        {"changed_files_only": True},
        {"baseline": {}},
    ],
)
def test_invalid_or_filtered_baseline_is_refused(tmp_path, metadata):
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    source = tmp_path / "source"
    source.mkdir()
    baseline = tmp_path / "baseline.json"
    data = json.loads(AshAggregatedResults().model_dump_json(by_alias=True))
    if metadata is not None:
        data["metadata"].update(metadata)
    baseline.write_text("not json" if metadata is None else json.dumps(data))
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "fs",
            str(source),
            "--mode",
            "local",
            "--baseline",
            str(baseline),
        ],
    )
    assert response.exit_code == 5
    assert "Error reading --baseline" in response.output


def test_library_refuses_output_baseline_before_output_cleanup(tmp_path):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    baseline = output / "ash_aggregated_results.json"
    baseline.write_text("do not delete")
    with pytest.raises(SystemExit) as error:
        run_ash_scan(
            source_dir=source,
            output_dir=output,
            baseline=str(baseline),
            show_summary=False,
            progress=False,
        )
    assert error.value.code == 5
    assert baseline.read_text() == "do not delete"


def test_library_refuses_baseline_with_saved_results(tmp_path, monkeypatch, capsys):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils import scan_baseline

    def unread(*args, **kwargs):
        pytest.fail("baseline read")

    monkeypatch.setattr(scan_baseline, "read_baseline", unread)
    source = tmp_path / "source"
    source.mkdir()
    saved = tmp_path / "saved.json"
    saved.write_text(AshAggregatedResults().model_dump_json(by_alias=True))
    before = saved.read_text()
    baseline = tmp_path / "baseline.json"
    baseline.write_text(AshAggregatedResults().model_dump_json(by_alias=True))
    with pytest.raises(SystemExit) as error:
        run_ash_scan(
            source_dir=source,
            output_dir=tmp_path / "output",
            existing_results=str(saved),
            baseline=str(baseline),
            show_summary=False,
            progress=False,
        )
    assert error.value.code == 5
    assert "needs a fresh scan" in capsys.readouterr().err
    assert saved.read_text() == before


def test_library_refuses_baseline_data_without_a_baseline_path(tmp_path):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.scan_baseline import read_baseline

    source = tmp_path / "source"
    source.mkdir()
    path = tmp_path / "baseline.json"
    path.write_text(AshAggregatedResults().model_dump_json(by_alias=True))
    data = read_baseline(path, source_dir=source, output_dir=tmp_path / "output")
    with pytest.raises(ValueError, match="baseline_data"):
        run_ash_scan(
            source_dir=source,
            output_dir=tmp_path / "output",
            baseline_data=data,
            show_summary=False,
            progress=False,
        )


def test_explicit_express_with_baseline_is_refused(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "fs",
            str(source),
            "--express",
            "--baseline",
            str(tmp_path / "baseline"),
        ],
    )
    assert response.exit_code == 5
    assert "Error reading --baseline" in response.stderr
    assert "--express" in response.stderr


def test_explicit_express_with_json_baseline_is_refused(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    document = tmp_path / "args.json"
    document.write_text(
        json.dumps({"baseline": str(tmp_path / "missing"), "path": str(source)})
    )
    response = CliRunner().invoke(
        app, ["scan", "fs", "--express", "--cli-json-input", str(document)]
    )
    assert response.exit_code == 5
    assert "Error reading --baseline" in response.stderr
    assert "--express" in response.stderr


def test_scope_refusal_does_not_delete_previous_results(tmp_path, monkeypatch):
    from automated_security_helper.core.enums import ExecutionPhase
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _run_local_mode,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    class Logger:
        def __getattr__(self, name):
            return lambda *args, **kwargs: None

    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    prior = output / "ash_aggregated_results.json"
    prior.write_text("previous results")
    old = AshAggregatedResults()
    old.metadata.project_name = "different-project"
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(old.model_dump_json(by_alias=True))
    opts = ScanOptions(
        source_dir=source,
        output_dir=output,
        baseline=str(baseline_path),
        phases=[ExecutionPhase.SCAN],
        show_summary=False,
        progress=False,
    )
    with pytest.raises(SystemExit) as error:
        _run_local_mode(opts, Logger())
    assert error.value.code == 5
    assert prior.read_text() == "previous results"


def test_empty_staged_baseline_scan_preserves_previous_results(tmp_path, monkeypatch):
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setattr(
        "automated_security_helper.utils.staged_files.staged_files_for_source",
        lambda _: [],
    )
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    prior = output / "ash_aggregated_results.json"
    prior.write_text("previous results")
    old = AshAggregatedResults()
    old.metadata.project_name = "ash-scan"
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(old.model_dump_json(by_alias=True))
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "fs",
            str(source),
            "--mode",
            "precommit",
            "--staged",
            "--output-dir",
            str(output),
            "--baseline",
            str(baseline_path),
        ],
    )
    assert response.exit_code == 0, response.output
    assert "nothing is staged" in response.output
    assert prior.read_text() == "previous results"


def test_baseline_path_with_nul_is_usage_error(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    response = CliRunner().invoke(
        app,
        [
            "scan",
            "fs",
            str(source),
            "--mode",
            "local",
            "--baseline",
            "bad\x00path",
        ],
    )
    assert response.exit_code == 5
    assert "Error reading --baseline" in response.output


def test_baseline_in_case_aliased_output_directory_is_not_touched(tmp_path):
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.scan_baseline import (
        BaselineRefused,
        read_baseline,
    )

    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "OutputDirectory"
    output.mkdir()
    saved = output / "baseline.json"
    data = AshAggregatedResults().model_dump_json(by_alias=True)
    saved.write_text(data)
    alias = tmp_path / "outputdirectory" / saved.name
    if not alias.exists():
        pytest.skip("the test volume is case-sensitive")
    with pytest.raises(BaselineRefused, match="output directory"):
        read_baseline(alias, source_dir=source, output_dir=output)
    assert saved.read_text() == data


def test_baseline_swapped_to_output_after_path_check_is_refused(tmp_path, monkeypatch):
    import os
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.scan_baseline import (
        BaselineRefused,
        read_baseline,
    )

    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    data = AshAggregatedResults().model_dump_json(by_alias=True)
    protected = output / "protected.json"
    protected.write_text(data)
    saved = tmp_path / "baseline.json"
    saved.write_text(data)
    original_open = os.open
    swapped = False

    def swap_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if str(path) == str(saved) and not swapped:
            saved.unlink()
            saved.symlink_to(protected)
            swapped = True
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_open)
    with pytest.raises(BaselineRefused):
        read_baseline(saved, source_dir=source, output_dir=output)
    assert swapped and protected.read_text() == data


def test_python_api_refuses_baseline_log_before_truncating_it(tmp_path):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    log = output / "ash.log"
    original = "log contents must survive\n"
    log.write_text(original)
    with pytest.raises(SystemExit) as exc:
        run_ash_scan(
            source_dir=source, output_dir=output, baseline=str(log), progress=False
        )
    assert exc.value.code == 5
    assert log.read_text() == original


def test_baseline_options_do_not_shift_existing_positional_arguments():
    import inspect
    from automated_security_helper.cli.scan import run_ash_scan_cli_command
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    for function, previous in (
        (run_ash_scan, "min_severity"),
        # The two duplicate switches (--annotate-duplicates, --fold-duplicates) landed
        # between compact_report and changed_files_only, so the last argument that
        # existed before the baseline options is now fold_duplicates.
        (run_ash_scan_cli_command, "fold_duplicates"),
    ):
        names = list(inspect.signature(function).parameters)
        assert names.index("changed_files_only") == names.index(previous) + 1
        assert names.index("baseline") > names.index("changed_files_only")


@pytest.mark.parametrize("form", ["flag", "environment", "json", "json_flag"])
def test_baseline_and_existing_results_are_refused_before_read(
    tmp_path, monkeypatch, form
):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    saved = output / "ash_aggregated_results.json"
    saved.write_text("sentinel")
    baseline = tmp_path / "baseline.json"
    args = [
        "scan",
        "fs",
        str(source),
        "--mode",
        "local",
        "--output-dir",
        str(output),
        "--use-existing",
    ]
    if form == "flag":
        args += ["--baseline", str(baseline)]
    elif form == "environment":
        monkeypatch.setenv("ASH_BASELINE", str(baseline))
    else:
        document = tmp_path / "input.json"
        document.write_text(
            json.dumps(
                {"--baseline" if form == "json_flag" else "baseline": str(baseline)}
            )
        )
        args += ["--cli-json-input", str(document)]
    original_open = __import__("pathlib").Path.open

    def guarded_open(path, *args, **kwargs):
        if path == saved:
            pytest.fail("saved results opened")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("pathlib.Path.open", guarded_open)
    response = CliRunner().invoke(app, args)
    assert response.exit_code == 5
    assert "--baseline needs a fresh scan" in response.output
    with original_open(saved) as stream:
        assert stream.read() == "sentinel"


@pytest.mark.parametrize("key", ["baseline", "--baseline"])
def test_baseline_reaching_an_express_child_is_refused(tmp_path, monkeypatch, key):
    from automated_security_helper.express.runtime import CHILD_ENV

    source = tmp_path / "source"
    source.mkdir()
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}")
    document = tmp_path / "input.json"
    document.write_text(json.dumps({key: str(baseline)}))
    monkeypatch.setenv(CHILD_ENV, "1")
    response = CliRunner().invoke(
        app,
        ["scan", "fs", str(source), "--cli-json-input", str(document)],
    )
    assert response.exit_code == 5
    assert "not supported by the express daemon" in response.output
    assert "--no-express" in response.output
