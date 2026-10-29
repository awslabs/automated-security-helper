# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan judges paths against the output and work directories of the scans running.

A caller can hand one resolved configuration to several orchestrators. Each
orchestrator records its plugin context's directories on that configuration as
its own scan's, and removes them when its scan ends. During a scan its plugins
judge paths against every recorded scan's directories: a path under its own
output directory is refused, and so is one under the output directory of a scan
running at the same time. A scan that has ended no longer refuses paths under
its directories.
"""

import threading

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.path_trust import (
    honored_path,
    reset_path_refusal_warnings,
)
from automated_security_helper.core.orchestrator import ASHScanOrchestrator

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


def _refused(path, source, config):
    return (
        honored_path(path, source_dir=source, key="config_file", config=config) is None
    )


def _scan(tmp_path, name, config):
    """An initialized orchestrator on *config* and a file in its output dir."""
    source = tmp_path / name / "src"
    source.mkdir(parents=True)
    orchestrator = ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=tmp_path / name / "out",
        resolved_config=config,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
    )
    product = tmp_path / name / "out" / "derived.yaml"
    product.parent.mkdir(parents=True, exist_ok=True)
    product.write_text("")
    return orchestrator, product


@pytest.fixture
def judged_during_scan(monkeypatch):
    """Replace the phases with a step that judges the given products, in the
    scan's own thread, and returns what it judged."""
    judgments = {}
    gates = {}

    def judge(self, phases=None):
        name = self.source_dir.parent.name
        gate = gates.get(name)
        if gate is not None:
            gate.wait(30)
        judgments[name] = {
            label: _refused(product, self.source_dir, self.config)
            for label, product in products.items()
        }
        if gate is not None:
            gate.wait(30)
        return object()

    products = {}
    monkeypatch.setattr(ASHScanOrchestrator, "_execute_scan", judge)
    return products, judgments, gates


def test_a_second_scan_on_one_config_is_not_refused_under_the_first_scans_output(
    tmp_path, judged_during_scan
):
    products, judgments, _ = judged_during_scan
    config = AshConfig()
    first, products["first"] = _scan(tmp_path, "first", config)
    first.execute_scan()
    second, products["second"] = _scan(tmp_path, "second", config)
    second.execute_scan()

    assert judgments["first"]["first"] is True
    assert judgments["second"] == {"first": False, "second": True}
    # Each scan's roots left the record when the scan ended.
    assert not _refused(products["first"], first.source_dir, config)
    assert not _refused(products["second"], second.source_dir, config)
    assert config._run_derived_roots == {}


def test_a_scan_that_fails_still_removes_its_roots_from_the_record(
    tmp_path, monkeypatch
):
    config = AshConfig()
    orchestrator, product = _scan(tmp_path, "first", config)

    def fail(self, phases=None):
        assert _refused(product, self.source_dir, self.config)
        raise RuntimeError("the scan failed")

    monkeypatch.setattr(ASHScanOrchestrator, "_execute_scan", fail)
    with pytest.raises(RuntimeError, match="the scan failed"):
        orchestrator.execute_scan()

    assert config._run_derived_roots == {}
    assert not _refused(product, orchestrator.source_dir, config)


def test_two_scans_at_once_on_one_config_each_refuse_both_scans_paths(
    tmp_path, judged_during_scan
):
    products, judgments, gates = judged_during_scan
    config = AshConfig()
    first, products["first"] = _scan(tmp_path, "first", config)
    second, products["second"] = _scan(tmp_path, "second", config)
    both_running = threading.Barrier(2)
    gates["first"] = both_running
    gates["second"] = both_running

    threads = [
        threading.Thread(target=first.execute_scan),
        threading.Thread(target=second.execute_scan),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert not any(thread.is_alive() for thread in threads)

    assert judgments["first"] == {"first": True, "second": True}
    assert judgments["second"] == {"first": True, "second": True}
