"""The code of a timeout says whether the timed-out run's tool was stopped.

``timed_out`` has the default sentence "it timed out and was killed", and
``could_not_stop`` "it timed out and its tool could not be stopped". A timeout whose
later run's tool could not be stopped (the record names a run other than the
timeout's) was coded ``timed_out``, so anything keyed on the code, and the default
sentence a report falls back to, said "killed" of a scan whose tool may still be
running. Every ending but the was-killed one is now ``could_not_stop``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.core.exceptions import DEFAULT_SENTENCES, ReasonCode
from automated_security_helper.core.phases import scanner_executor
from automated_security_helper.core.phases.scanner_executor import (
    UNSTOPPED_LATER_RUN_ENDING,
    _timeout_ending,
    _timeout_reason,
)
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    WAS_KILLED_ENDING,
)

pytestmark = pytest.mark.unit

#: The plugin's record of which runs' stops failed, as ``_timeout_ending`` reads it:
#: nothing (every stop worked), the timeout's own, and a run other than the timeout.
KILLED = SimpleNamespace(scan_could_not_stop_runs={})
UNSTOPPED = SimpleNamespace(scan_could_not_stop_runs={"timed_out": "the tool"})
UNSTOPPED_LATER = SimpleNamespace(scan_could_not_stop_runs={"cancelled": "the tool"})


class TestEachEndingHasItsCode:
    @pytest.mark.parametrize(
        "plugin, ending, code",
        [
            pytest.param(
                KILLED, WAS_KILLED_ENDING, ReasonCode.TIMED_OUT, id="was-killed"
            ),
            pytest.param(
                UNSTOPPED,
                COULD_NOT_STOP_ENDING,
                ReasonCode.COULD_NOT_STOP,
                id="could-not-stop",
            ),
            pytest.param(
                UNSTOPPED_LATER,
                UNSTOPPED_LATER_RUN_ENDING,
                ReasonCode.COULD_NOT_STOP,
                id="a-later-run-could-not-be-stopped",
            ),
        ],
    )
    def test_the_ending_and_its_code(self, plugin, ending, code):
        assert _timeout_ending(plugin) == ending

        reason = _timeout_reason(plugin, 30.0, ())

        assert reason.code == code
        assert reason.sentence == f"it timed out after '30' s{ending}"

    def test_the_three_endings_are_the_three_the_code_is_chosen_from(self):
        assert {
            WAS_KILLED_ENDING,
            COULD_NOT_STOP_ENDING,
            UNSTOPPED_LATER_RUN_ENDING,
        } == {
            _timeout_ending(plugin) for plugin in (KILLED, UNSTOPPED, UNSTOPPED_LATER)
        }


class TestTheFallbackSentenceNeverSaysKilledForATimeoutThatWasNotKilled:
    """When the sentence made from the ending is not fit to show, the code's default
    sentence stands in its place."""

    @pytest.fixture(autouse=True)
    def _an_unfit_sentence(self, monkeypatch):
        monkeypatch.setattr(
            scanner_executor, "text_without_values", lambda text, values: "x" * 300
        )

    @pytest.mark.parametrize("plugin", [UNSTOPPED, UNSTOPPED_LATER])
    def test_a_tool_that_may_still_be_running_is_not_called_killed(self, plugin):
        reason = _timeout_reason(plugin, 30.0, ())

        assert reason.sentence == DEFAULT_SENTENCES[ReasonCode.COULD_NOT_STOP]
        assert "killed" not in reason.sentence

    def test_control_a_tool_that_was_killed_says_so(self):
        reason = _timeout_reason(KILLED, 30.0, ())

        assert reason.sentence == DEFAULT_SENTENCES[ReasonCode.TIMED_OUT]
        assert "killed" in reason.sentence
