# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The results' JSON dumps take every name a record can hold, and only those.

A result records a file name that is not valid UTF-8 in its record form, each lone
surrogate written as its escape (``\\udcNN``). The dumps around that:

- take every keyword ``model_dump_json`` takes, a name set after the results were
  built included;
- raise a serialization failure that has nothing to do with such a name, even when
  its message says "surrogates not allowed": whether a model holds a lone surrogate
  is a fact about the model, not about an exception's text;
- serialize each large model at most once per report, whatever names the results
  hold;
- hold the other lone surrogates a str can carry, from Windows names: a lone high
  surrogate and a pair stored as two code points, escaped each, and read back as
  they were given.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict

import pytest
from pydantic import field_serializer

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.undecodable_text import RecordModel

# The constant below is a file name that is not UTF-8.
if os.name == "nt":
    pytest.skip(
        "a file name that is not UTF-8 cannot exist on NTFS (names are UTF-16)",
        allow_module_level=True,
    )

ODD = os.fsdecode(b"secr\xe9t.py")
RECORDED = "secr\\udce9t.py"


def _result(uri: str, rule: str = "R1") -> Result:
    return Result(
        ruleId=rule,
        message=Message(text="finding"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri)
                )
            )
        ],
        properties=PropertyBag(scanner_name="detect-secrets", tags=["secret"]),
    )


def _report(*results: Result) -> SarifReport:
    return SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="detect-secrets")),
                results=list(results),
            )
        ]
    )


def _set_after(report: SarifReport) -> SarifReport:
    """*report* with its first result's URI given the raw name after it was built."""
    location = report.runs[0].results[0].locations[0]
    location.physicalLocation.root.artifactLocation.uri = ODD
    return report


def _first_uri(document: dict) -> str:
    location = document["runs"][0]["results"][0]["locations"][0]
    return location["physicalLocation"]["artifactLocation"]["uri"]


@pytest.mark.parametrize(
    "keywords",
    [
        {"ensure_ascii": True},
        {"indent": 2},
        {"indent": 2, "ensure_ascii": True, "exclude_none": True, "by_alias": True},
    ],
    ids=["ensure-ascii", "indent", "every-json-keyword"],
)
def test_a_json_dump_takes_its_own_keywords_with_a_name_set_after(keywords):
    report = _set_after(_report(_result("app.py"), _result("b.py")))

    written = report.model_dump_json(**keywords)

    if keywords.get("ensure_ascii"):
        assert written.isascii()
    if keywords.get("indent"):
        assert "\n  " in written
    # ascii() on both sides: pytest's diff of two str holding a lone surrogate
    # cannot be sent between workers.
    assert ascii(_first_uri(json.loads(written))) == ascii(RECORDED)


def test_the_aggregated_results_dump_takes_them_too(tmp_path: Path):
    model = AshAggregatedResults(sarif=_set_after(_report(_result("app.py"))))

    written = model.model_dump_json(indent=2, ensure_ascii=True, by_alias=True)

    assert written.isascii()
    assert ascii(_first_uri(json.loads(written)["sarif"])) == ascii(RECORDED)


class _FailingOnce(RecordModel):
    """A record whose one field fails to serialize the first time, with the words a
    lone surrogate's failure has, though it holds no such name."""

    name: str = "app.py"
    calls: int = 0

    @field_serializer("name")
    def _name(self, value: str) -> str:
        object.__setattr__(self, "calls", self.calls + 1)
        if self.calls == 1:
            raise ValueError(
                "first serialization fails: 'utf-8' codec can't encode character "
                "'\\udce9' in position 0: surrogates not allowed"
            )
        return value


def test_a_failure_that_names_surrogates_without_one_is_raised():
    model = _FailingOnce()

    with pytest.raises(Exception) as raised:
        model.model_dump_json()

    assert "first serialization fails" in str(raised.value)


class _CountingSerializer:
    """A model class's serializer that counts its calls and passes them on."""

    def __init__(self, inner, counts: Dict[str, int], key: str):
        self._inner = inner
        self._counts = counts
        self._key = key

    def to_python(self, *args, **kwargs):
        self._counts[self._key] = self._counts.get(self._key, 0) + 1
        return self._inner.to_python(*args, **kwargs)

    def to_json(self, *args, **kwargs):
        self._counts[self._key] = self._counts.get(self._key, 0) + 1
        return self._inner.to_json(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _reporters():
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_builtin import ASH_REPORTERS

    probe = PluginContext(source_dir=Path.cwd(), output_dir=Path.cwd())
    return [
        (reporter, reporter(context=probe).config.name) for reporter in ASH_REPORTERS
    ]


@pytest.mark.parametrize("uri", ["app.py", ODD], ids=["plain", "not-utf8"])
def test_each_report_serializes_each_large_model_at_most_once(
    tmp_path: Path, monkeypatch, uri
):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.core.phases.report_phase import ReportPhase
    from automated_security_helper.core.progress import LiveProgressDisplay

    reporters = _reporters()
    every = AshConfig(reporters={name: {"enabled": True} for _, name in reporters})
    counts: Dict[str, int] = {}
    for cls, key in (
        (SarifReport, "SarifReport"),
        (AshAggregatedResults, "AshAggregatedResults"),
    ):
        monkeypatch.setattr(
            cls,
            "__pydantic_serializer__",
            _CountingSerializer(cls.__pydantic_serializer__, counts, key),
        )
    per_report = {}
    for reporter, name in reporters:
        model = AshAggregatedResults(
            sarif=_report(*[_result(uri, rule=f"R{i}") for i in range(20)])
        )
        out = tmp_path / name
        context = PluginContext(source_dir=out, output_dir=out, config=every)
        phase = ReportPhase(
            plugins=[reporter],
            plugin_context=context,
            progress_display=LiveProgressDisplay(show_progress=False),
            asharp_model=model,
        )
        counts.clear()
        phase.execute(
            report_dir=out / "reports",
            cli_output_formats=[name],
            aggregated_results=model,
            python_based_plugins_only=False,
        )
        per_report[name] = dict(counts)

    more = {
        name: count
        for name, count in per_report.items()
        if any(times > 1 for times in count.values())
    }
    assert more == {}, more
    # The sarif report dumps the SARIF, so the count reaches the dumps at all.
    assert per_report["sarif"].get("SarifReport", 0) == 1, per_report


#: Lone surrogates a Windows name can hold, beside the low ones a POSIX byte gives.
WINDOWS_NAMES = {
    "lone-high": ("x\ud800.py", "x\\ud800.py"),
    # Built with chr(): the two halves stay two code points, not one character.
    "pair-as-two-code-points": (
        "x" + chr(0xD83D) + chr(0xDE00) + ".py",
        "x\\ud83d\\ude00.py",
    ),
    "lone-low-outside-the-byte-range": ("x\udc00.py", "x\\udc00.py"),
}


@pytest.mark.parametrize("label", sorted(WINDOWS_NAMES))
def test_another_lone_surrogate_is_recorded_and_reads_back(label):
    given, recorded = WINDOWS_NAMES[label]

    report = _report(_result(given))
    back = SarifReport.model_validate_json(report.model_dump_json())

    assert ascii(_first_uri(json.loads(report.model_dump_json()))) == ascii(recorded)
    uri = back.runs[0].results[0].locations[0].physicalLocation.root.artifactLocation
    assert ascii(uri.uri) == ascii(recorded)


@pytest.mark.parametrize("label", sorted(WINDOWS_NAMES))
def test_a_config_naming_it_reads_back_as_given(label):
    given, recorded = WINDOWS_NAMES[label]
    config = AshConfig(
        global_settings={"ignore_paths": [{"path": given, "reason": "not scanned"}]}
    )

    written = AshAggregatedResults(ash_config=config).model_dump_json()
    back = AshAggregatedResults.model_validate_json(written)

    stored = json.loads(written)["ash_config"]["global_settings"]["ignore_paths"]
    assert ascii(stored[0]["path"]) == ascii(recorded)
    assert back.ash_config is not None
    path = back.ash_config.global_settings.ignore_paths[0].path
    assert ascii(path) == ascii(given)
