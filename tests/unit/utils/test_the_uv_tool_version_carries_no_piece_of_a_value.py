# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv tool version probe's cut leaves no piece of an env-read value.

``UVToolRunner.get_tool_version`` reads the probe's first line as the
version. A value with a line break printed into that answer would leave its
first half in the carried version (the SARIF's scanner_version and the
DEBUG line) -- a piece the downstream whole-value redaction cannot match --
so the answer is redacted whole before the cut. The same ordering holds
against the strip: a value ending in a whitespace-class character loses its
edge to a whole-text strip, and the whole-value match then misses it, so
the redaction runs on the unstripped text and the strip comes after. The
one-line control shows a value with no break and no whitespace edge
survives the cut whole, where a downstream redaction can still match it;
redaction here hides it already.
"""

from __future__ import annotations

import contextlib
import os
import stat
import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

from automated_security_helper.utils import uv_tool_runner
from tests.unit.base.test_failure_lines_carry_no_environment_value import _context
from tests.unit.base.test_scanner_plugin_coverage import _scanner
from tests.unit.base.test_uv_tool_mixin import FakePlugin

HEAD = "ASH_CANARY_Zq7Kx9LmHead"
TAIL = "ASH_CANARY_Pw4Nv2RtTail"


def _fake_uv(path, stdout_text):
    """An executable that writes *stdout_text* and exits 0, whatever its argv."""
    data = stdout_text.encode("utf-8").hex()
    path.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        f"sys.stdout.buffer.write(bytes.fromhex('{data}'))\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


@pytest.mark.parametrize(
    "printed, value, case",
    [
        pytest.param(
            f"1.2.3 {HEAD}{TAIL}\n", f"{HEAD}{TAIL}", "c1", id="one-line-control"
        ),
        pytest.param(f"1.2.3 {HEAD}\n{TAIL}\n", f"{HEAD}\n{TAIL}", "c2", id="spanning"),
        # The value's own last character is whitespace-class and sits at the
        # very end of the probe's stdout: a whole-text strip ahead of the
        # redaction shaves that edge off, the whole-value match misses, and
        # the piece prints.
        pytest.param(
            f"1.2.3 {HEAD}{TAIL}\x0c",
            f"{HEAD}{TAIL}\x0c",
            "c3",
            id="whitespace-edge",
        ),
    ],
)
def test_the_version_holds_no_piece_of_a_value(tmp_path, printed, value, case):
    fake = _fake_uv(tmp_path / "fake-uv", printed)
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(fake))
    runner._uv_available_cache = True

    version = (
        runner.get_tool_version(
            f"vcut{os.getpid()}{case}", None, refresh=True, values=(value,)
        )
        or ""
    )

    assert version.startswith("1.2.3"), repr(version)
    assert HEAD not in version and TAIL not in version, repr(version)


@pytest.mark.parametrize(
    "printed, hidden, case",
    [
        # uv respells a version: an env-read "9.9.9-RC777" prints as
        # "9.9.9rc777", which a match on the value as written never sees.
        pytest.param("1.2.3 9.9.9rc777\n", "rc777", "r1", id="respelled"),
        # The same value printed as written: the respelling-aware layer
        # still hides it in its original spelling. The over-masking control
        # is test_a_version_that_is_not_the_value_is_carried_whole below.
        pytest.param("1.2.3 9.9.9-RC777\n", "RC777", "r2", id="literal-twin"),
    ],
)
def test_the_version_hides_a_value_in_the_spelling_uv_prints(
    tmp_path, printed, hidden, case
):
    fake = _fake_uv(tmp_path / "fake-uv", printed)
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(fake))
    runner._uv_available_cache = True

    version = (
        runner.get_tool_version(
            f"vspell{os.getpid()}{case}",
            None,
            refresh=True,
            values=("9.9.9-RC777",),
        )
        or ""
    )

    assert version.startswith("1.2.3"), repr(version)
    assert hidden not in version, repr(version)


def test_the_tool_name_and_the_from_spec_play_their_own_roles(tmp_path):
    """The spec is the plugin-built input and the tool name is the anchor.

    The probe prints the tool's name, a respelling of the value and a spelling
    of the spec. The value layer hides the respelling whichever role the
    arguments play; only the input layer hides the spec's spelling, and it can
    do that only when the spec is the one passed as the input. The name must
    stay readable at both arms. With the two arguments swapped at a call site
    the spec's spelling survives, which is what the last assertion catches.
    """
    fake = _fake_uv(tmp_path / "fake-uv", "vtool 9.9.9rc777 vtool[sarif]\n")
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(fake))
    runner._uv_available_cache = True

    version = (
        runner.get_tool_version(
            "vtool", "vtool[sarif]==9.9.9-RC777", refresh=True, values=("9.9.9-RC777",)
        )
        or ""
    )

    assert version.startswith("vtool "), repr(version)
    assert "rc777" not in version and "RC777" not in version, repr(version)
    assert "vtool[sarif]" not in version, repr(version)


def test_a_version_that_is_not_the_value_is_carried_whole(tmp_path):
    """The respelling-aware layer hides the value, not the version around it."""
    fake = _fake_uv(tmp_path / "fake-uv", "1.2.3\n")
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(fake))
    runner._uv_available_cache = True

    version = runner.get_tool_version(
        f"vkeep{os.getpid()}", None, refresh=True, values=("9.9.9-RC777",)
    )

    assert version == "1.2.3", repr(version)


def test_the_first_probes_redaction_does_not_decide_for_later_callers(tmp_path):
    """The memo must not freeze one caller's redaction into every answer.

    Callers share the ``tool::spec`` memo key but not their values: each
    passes its own plugin's environment-read values. Whoever probes first
    must therefore not decide the redaction for everyone. A caller with no
    values rightly sees the probe's text; a caller whose configuration read
    that text's value from the environment must get it hidden even when the
    values-free caller filled the memo first; and a values-free caller after
    a redacting one must not inherit the mangled form. The memoized answer
    has to be the raw text, redacted again on every return.
    """
    value = f"{HEAD}{TAIL}"
    fake = _fake_uv(tmp_path / "fake-uv", f"1.2.3 {value}\n")
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(fake))
    runner._uv_available_cache = True
    tool = f"vmemo{os.getpid()}"

    first = runner.get_tool_version(tool, None, refresh=True, values=())
    second = runner.get_tool_version(tool, None, values=(value,))
    third = runner.get_tool_version(tool, None, values=())
    # Every call after the first is a cache hit, which redacts after the cache
    # lock is released. This pins what a hit returns; the lock scope itself is
    # not observable from a single thread.
    fourth = runner.get_tool_version(tool, None, values=(value,))

    assert first == f"1.2.3 {value}", repr(first)
    assert second is not None and value not in second, repr(second)
    assert third == f"1.2.3 {value}", repr(third)
    assert fourth == second, repr(fourth)


def test_a_reader_that_waited_on_the_probe_lock_gets_the_answer_redacted(
    tmp_path, monkeypatch
):
    """The second cache read, under the probe lock, redacts like the first.

    Two readers of one tool's version race: the second finds the memo empty,
    waits on the probe lock, and by the time it holds it the first has stored
    the answer, so it returns that remembered text instead of probing. The
    memo holds the raw text, so this return has to redact it too; every
    other cell here reaches the first read or the probe's own return. The
    first reader's store is stood in for by the lock the second one takes:
    on entering it, the memo is filled as the first reader's store leaves it.
    """
    value = f"{HEAD}{TAIL}"
    ran = tmp_path / "ran"
    data = f"1.2.3 {value}\n".encode("utf-8").hex()
    fake = tmp_path / "fake-uv"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        f"open({str(ran)!r}, 'a').write('x')\n"
        f"sys.stdout.buffer.write(bytes.fromhex('{data}'))\n",
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(fake))
    runner._uv_available_cache = True
    tool = f"vwait{os.getpid()}"
    key = f"{tool}::"

    # The first reader's probe, which stores the raw text; then the memo is
    # emptied, so the second reader's first look misses.
    first = runner.get_tool_version(tool, None, refresh=True, values=())
    stored = uv_tool_runner._uv_tool_version_cache.pop(key)
    assert first == f"1.2.3 {value}", repr(first)
    assert ran.read_text() == "x"
    assert any(value in (text or "") for text in stored.values()), stored

    @contextlib.contextmanager
    def _first_reader_stores_while_this_one_waits(_probe_lock):
        with uv_tool_runner._uv_tool_runner_cache_lock:
            uv_tool_runner._uv_tool_version_cache[key] = stored
        yield

    monkeypatch.setattr(
        uv_tool_runner, "_probe_lock_held", _first_reader_stores_while_this_one_waits
    )

    second = runner.get_tool_version(tool, None, values=(value,))

    assert second is not None and second.startswith("1.2.3"), repr(second)
    assert HEAD not in second and TAIL not in second, repr(second)
    # It answered from the memo: no second probe ran.
    assert ran.read_text() == "x"


def test_the_mixin_threads_the_plugins_values_to_the_probe(tmp_path):
    """The redaction can only hide what it is given: the mixin's version read
    passes the plugin's own values through to the runner's cut."""
    context = _context(tmp_path, [f"{HEAD}\n{TAIL}"])
    scanner = _scanner(context)
    scanner.use_uv_tool = True
    runner = Mock()
    runner.is_uv_available.return_value = True
    runner.get_tool_version.return_value = "1.2.3"

    with (
        patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=runner,
        ),
        patch.object(
            type(scanner), "_values_to_redact", return_value=(f"{HEAD}\n{TAIL}",)
        ),
    ):
        assert scanner._get_uv_tool_version("stub-tool") == "1.2.3"

    kwargs = runner.get_tool_version.call_args.kwargs
    assert kwargs.get("values") == (f"{HEAD}\n{TAIL}",), kwargs


def test_a_caller_that_checked_nothing_has_the_spec_hidden_from_the_version(tmp_path):
    """No ``values`` means no caller checked where the spec came from, and the
    carried version hides every plugin-built argument: a tool whose
    ``--version`` line echoes its own ``--from`` spec does not print it."""
    spec = f"vtool[x{os.getpid()}]==1.0"
    fake = _fake_uv(tmp_path / "fake-uv", f"vtool 1.0 {spec}\n")
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(fake))
    runner._uv_available_cache = True

    version = runner.get_tool_version("vtool", spec, refresh=True) or ""

    assert version.startswith("vtool 1.0"), repr(version)
    assert "==1.0" not in version, repr(version)


def test_an_explicit_empty_value_set_still_carries_the_spec(tmp_path):
    """The other side of the same contract: a caller that checked, and found
    no environment-read value, has nothing hidden."""
    spec = f"vtool[y{os.getpid()}]==1.0"
    fake = _fake_uv(tmp_path / "fake-uv", f"vtool 1.0 {spec}\n")
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(fake))
    runner._uv_available_cache = True

    version = runner.get_tool_version("vtool", spec, refresh=True, values=())

    assert version == f"vtool 1.0 {spec}", repr(version)


def test_the_post_install_version_read_passes_the_installs_values():
    """The install's own version read has the same values the install and the
    record lines use, so the INFO line it feeds hides what they hide."""
    plugin = FakePlugin(command="bandit", use_uv_tool=True)
    held = ("ASH_CANARY_Zq7Kx9LmValue",)
    with (
        patch.object(plugin, "_is_offline_mode", return_value=False),
        patch.object(type(plugin), "_values_to_redact", return_value=held),
        patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner,
        patch(
            "automated_security_helper.utils.subprocess_utils.clear_find_executable_cache"
        ),
    ):
        runner = MagicMock()
        runner.is_uv_available.return_value = True
        runner.get_cache_info.return_value = {"cache_available": False}
        runner.is_tool_installed.return_value = False
        runner.install_tool_with_version.return_value = True
        runner.get_installed_tool_version.return_value = "1.7.0"
        mock_get_runner.return_value = runner

        assert plugin._install_uv_tool() is True

    kwargs = runner.get_installed_tool_version.call_args.kwargs
    assert tuple(kwargs.get("values", ())) == held, kwargs
    assert (
        kwargs["values"] == runner.install_tool_with_version.call_args.kwargs["values"]
    ), kwargs


SGR_ON = "\x1b[1m"
SGR_OFF = "\x1b[0m"


@pytest.mark.parametrize(
    "printed, case",
    [
        # The value holds a complete color code, and its visible text is a
        # short word. Printed glued to word characters, the visible text
        # matches as a whole word nowhere once the codes are stripped, so
        # only a match on the text as written, before the strip, hides it.
        pytest.param(f"1.2.3 zz{SGR_ON}dovrek{SGR_OFF}zz\n", "g1", id="glued"),
        # The control: at word boundaries the stripped spelling matches on
        # its own, with or without the match on the text as written.
        pytest.param(f"1.2.3 {SGR_ON}dovrek{SGR_OFF}\n", "g2", id="space-bounded"),
    ],
)
def test_a_code_holding_value_is_hidden_where_glued_to_word_characters(
    tmp_path, printed, case
):
    fake = _fake_uv(tmp_path / "fake-uv", printed)
    runner = uv_tool_runner.UVToolRunner(uv_executable=str(fake))
    runner._uv_available_cache = True

    version = (
        runner.get_tool_version(
            f"vglue{os.getpid()}{case}",
            None,
            refresh=True,
            values=(f"{SGR_ON}dovrek{SGR_OFF}",),
        )
        or ""
    )

    assert version.startswith("1.2.3"), repr(version)
    assert "dovrek" not in version, repr(version)
