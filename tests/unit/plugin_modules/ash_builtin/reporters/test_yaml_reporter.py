# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash.yaml`` has to be loadable by a parser that will not execute the file.

Why a behavioural test and not a call assertion
-----------------------------------------------
The fix is one kwarg -- ``model_dump(by_alias=True, mode="json")`` -- and the
obvious guard is to assert that kwarg was passed. ``test_spdx_reporter.py`` has
such an assertion and it is worth keeping there for other reasons, but on its own
it is the wrong shape of guard for *this* defect: it passes whenever the kwargs
are present, including if the output becomes unloadable again by some other route.
Which is how the defect arrived in the first place -- nobody was checking the
output, only the code.

So these tests load the output. ``yaml.safe_load`` succeeding is the property an
operator actually depends on.

What the defect was
-------------------
``yaml.dump(model.model_dump(by_alias=True))`` -- Python mode, not JSON mode --
leaves rich objects in the tree, and ``yaml.dump`` serialises those as
``!!python/object`` tags. ``yaml.safe_load`` refuses them outright with
``ConstructorError``; the only loaders that accept them are the ones that will
construct arbitrary Python objects out of the file. Requiring that of anyone
consuming a *security tool's* output is the part that makes this more than a
formatting bug.

It is not limited to scans that found something. A **default**
``AshAggregatedResults`` with no findings at all emits four such tags, from the
``AnyUrl`` values in the SARIF tool metadata's ``informationUri`` and
``downloadUri``. So it was every document ASH has ever written, empty ones
included. Enum fields such as ``ScannerStatus`` add more tags on any real scan,
but they are the second source, not the first.

Both sources are asserted below, and separately, because they come from different
pydantic types and a partial fix would leave one of them behind.
"""

import re

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.yaml_reporter import (
    YamlReporter,
)

#: Any tag that makes a document constructible only by an unsafe loader. Matched
#: as a prefix because pydantic emits at least two spellings --
#: ``!!python/object:pydantic.networks.AnyUrl`` and
#: ``!!python/object/new:pydantic_core._pydantic_core.Url`` -- and a fix that
#: eliminated one but not the other must still fail.
UNSAFE_TAG = re.compile(r"!!python/object\S*")


@pytest.fixture
def context(tmp_path) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config=AshConfig(),
    )


def _report(model: AshAggregatedResults, context: PluginContext) -> str:
    return YamlReporter(context=context).report(model)


class TestTheOutputIsSafeLoadable:
    def test_an_empty_scan_produces_a_safe_loadable_document(self, context):
        """The broadest case, and the one that makes this every document.

        A default model has no findings and no scanner results, and still emitted
        four ``!!python/object`` tags before the fix -- from the ``AnyUrl`` values
        in the SARIF tool metadata. So "every real scan" understated it: an empty
        scan was affected too.
        """
        result = _report(AshAggregatedResults(), context)

        loaded = yaml.safe_load(result)
        assert isinstance(loaded, dict)
        assert not UNSAFE_TAG.search(result), UNSAFE_TAG.findall(result)

    def test_a_scan_with_a_scanner_status_enum_is_safe_loadable(self, context):
        """The second source of tags, asserted separately.

        ``ScannerStatus`` is an enum, and it reaches the dump through
        ``scanner_results`` on every scan that ran a scanner. It comes from a
        different pydantic type than the ``AnyUrl`` case above, so a partial fix
        could close one and leave the other; asserting them separately is what
        makes that visible.
        """
        model = AshAggregatedResults()
        model.scanner_results = {
            "bandit": ScannerStatusInfo(status=ScannerStatus.FAILED)
        }
        result = _report(model, context)

        loaded = yaml.safe_load(result)
        assert not UNSAFE_TAG.search(result), UNSAFE_TAG.findall(result)
        # The load is not vacuous: the enum survived as a plain string, and the
        # value is the one that was set. Without this, a fix that dropped
        # scanner_results entirely would satisfy safe_load and this test.
        assert loaded["scanner_results"]["bandit"]["status"] == "FAILED"

    def test_the_document_still_carries_the_model_it_was_given(self, context):
        """Guards against making the output loadable by making it empty.

        ``yaml.safe_load("{}")`` succeeds, so "safe_load did not raise" is
        satisfiable by a reporter that emits nothing useful. This pins that the
        loaded document is the model.
        """
        model = AshAggregatedResults()
        model.name = "fixture-scan"
        loaded = yaml.safe_load(_report(model, context))

        assert loaded["name"] == "fixture-scan"
        assert "metadata" in loaded
        assert "sarif" in loaded


class TestTheUnsafeTagMatcherWorks:
    """A negative control for the matcher itself.

    Every assertion above is of the form "no unsafe tag was found". If the regex
    were wrong, all of them would pass against output full of tags. So the matcher
    is checked against a document known to contain them, produced the way the
    pre-fix reporter produced it.
    """

    def test_the_matcher_finds_tags_in_a_python_mode_dump(self):
        model = AshAggregatedResults()
        model.scanner_results = {
            "bandit": ScannerStatusInfo(status=ScannerStatus.FAILED)
        }
        # Exactly what yaml_reporter did before the fix: no mode="json".
        pre_fix = yaml.dump(model.model_dump(by_alias=True), indent=2)

        assert UNSAFE_TAG.search(pre_fix), (
            "the pre-fix dump contains no !!python/object tag, so the matcher "
            "above proves nothing"
        )
        with pytest.raises(yaml.constructor.ConstructorError):
            yaml.safe_load(pre_fix)
