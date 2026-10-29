# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sentence that says ASH could not stop a tool is written once.

Five places in utils/subprocess_utils.py spelled "which may still be running" for
themselves: the default reason, the generic reason, the spawn record's reason, and
the two cancels the spawn layer raises (the kernel refused the kill at the
server's stop, and a cancel whose stop did not end the child). The words were the
same, so nothing read differently, but a change to the ending had to find all five.
They now share ``COULD_NOT_STOP_SUFFIX``, and the two cancels compose through
``could_not_stop_sentence``. What is checked:

* the composer composes the sentence, and the reasons end as it does;
* the words of every reason are as they were, so nothing a reader sees moved;
* the spawn record's reason is the default reason for the same pid;
* no code in subprocess_utils spells the ending or the opening of the sentence
  outside the constant and the composer. The scan has a planted-positive control
  and a negative one, and skips docstrings and comments, which only describe it.

All cells are DISARMED: stand-in values and a source read; nothing is spawned or
signaled.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import List

from automated_security_helper.utils import subprocess_utils

_SUFFIX = "which may still be running"


class _Running:
    """A stand-in for a child that a stop did not end."""

    pid = 2**30 + 61
    returncode = None

    def poll(self):
        return None


class TestTheComposer:
    def test_it_composes_the_sentence(self):
        assert (
            subprocess_utils.could_not_stop_sentence("a process it started")
            == f"ASH could not stop a process it started, {_SUFFIX}"
        )

    def test_it_names_what_it_is_given_as_it_is_given(self):
        assert subprocess_utils.could_not_stop_sentence("python3 (pid 5)") == (
            f"ASH could not stop python3 (pid 5), {_SUFFIX}"
        )

    def test_the_reasons_end_as_the_composer_does(self):
        suffix = subprocess_utils.COULD_NOT_STOP_SUFFIX
        assert suffix == _SUFFIX
        assert subprocess_utils.could_not_stop_sentence("x").endswith(suffix)
        assert subprocess_utils.COULD_NOT_STOP_REASON.endswith(suffix)
        assert subprocess_utils.could_not_stop_default(5).endswith(suffix)
        assert subprocess_utils.could_not_stop_default(None).endswith(suffix)


class TestTheWordsAreAsTheyWere:
    """Control: nothing a reader sees moved. These are the literals the reasons
    had before the sentence was composed."""

    def test_the_generic_reason(self):
        assert subprocess_utils.COULD_NOT_STOP_REASON == (
            "ASH could not stop the tool, which may still be running"
        )

    def test_the_ending_a_timeout_text_adds(self):
        assert subprocess_utils.COULD_NOT_STOP_ENDING == (
            ", and ASH could not stop the tool, which may still be running"
        )

    def test_the_default_reason_for_a_pid(self):
        assert subprocess_utils.could_not_stop_default(5) == (
            "ASH could not stop the tool (pid 5), which may still be running"
        )

    def test_the_default_reason_for_no_pid_and_for_a_bool(self):
        assert subprocess_utils.could_not_stop_default(None) == (
            subprocess_utils.COULD_NOT_STOP_REASON
        )
        assert subprocess_utils.could_not_stop_default(True) == (
            subprocess_utils.COULD_NOT_STOP_REASON
        )

    def test_the_marker_still_opens_the_pid_form(self):
        assert subprocess_utils.could_not_stop_default(5).startswith(
            f"{subprocess_utils.COULD_NOT_STOP_MARKER} 5)"
        )


class TestTheSpawnRecord:
    def test_its_reason_is_the_default_reason_for_the_childs_pid(self):
        record = subprocess_utils._StartedChild()
        record.process = _Running()

        reason = record.not_stopped()

        assert reason == (
            f"ASH could not stop the tool (pid {_Running.pid}), {_SUFFIX}"
        )
        assert reason == subprocess_utils.could_not_stop_default(_Running.pid)

    def test_a_refused_stop_words_it_the_same_whatever_a_poll_says(self):
        record = subprocess_utils._StartedChild()
        record.process = _Running()
        record.stop_refused = True

        assert record.not_stopped() == subprocess_utils.could_not_stop_default(
            _Running.pid
        )


#: What the scan looks for in a string constant: the ending, and the opening of
#: the sentence.
_PATTERNS = (_SUFFIX, "ASH could not stop")

#: The module-level names whose own statement may spell it: the constant, the
#: marker that opens the pid form, and the composer.
_HOMES = {
    "COULD_NOT_STOP_SUFFIX",
    "COULD_NOT_STOP_MARKER",
    "could_not_stop_sentence",
}


def _documentation_ids(tree: ast.AST) -> set:
    """The ids of the string constants that are docstrings."""
    ids = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                ids.add(id(first.value))
    return ids


def _is_a_home(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.FunctionDef):
        return statement.name in _HOMES
    if isinstance(statement, ast.Assign):
        return any(
            isinstance(target, ast.Name) and target.id in _HOMES
            for target in statement.targets
        )
    return False


def _spellings(source: str) -> List[str]:
    """Every string constant of the code in ``source`` that holds a pattern, other
    than the homes' own. Docstrings and comments describe the sentence and are
    not read; an f-string's literal parts are string constants and are."""
    tree = ast.parse(source)
    documentation = _documentation_ids(tree)
    found = []
    for statement in tree.body:
        if _is_a_home(statement):
            continue
        for node in ast.walk(statement):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in documentation
                and any(pattern in node.value for pattern in _PATTERNS)
            ):
                found.append(f"line {node.lineno}: {node.value!r}")
    return found


_SPELLS_IT = """
def raise_it(tool, pid):
    raise ScanCancelled(
        f"stopping; ASH could not stop {tool} (pid {pid}), which may still be running"
    )
"""

_SPELLS_THE_ENDING_ALONE = """
def reason(pid):
    return f"the tool (pid {pid}) which may still be running"
"""

_COMPOSES_IT = """
def raise_it(tool, pid):
    raise ScanCancelled(
        "stopping; " + could_not_stop_sentence(f"{tool} (pid {pid})")
    )
"""

_ONLY_DESCRIBES_IT = '''
def note():
    """A tool ASH could not stop, which may still be running."""
    # ASH could not stop it, which may still be running.
    return 1
'''

_THE_HOMES = f'''
COULD_NOT_STOP_MARKER = "ASH could not stop the tool (pid"
COULD_NOT_STOP_SUFFIX = "{_SUFFIX}"

def could_not_stop_sentence(referent):
    return f"ASH could not stop {{referent}}, {{COULD_NOT_STOP_SUFFIX}}"
'''


def test_the_scan_flags_a_site_that_spells_the_sentence():
    """The planted-positive control: a raise site that writes the whole sentence,
    and one that writes only the ending."""
    assert len(_spellings(_SPELLS_IT)) >= 1
    assert len(_spellings(_SPELLS_THE_ENDING_ALONE)) == 1


def test_the_scan_passes_a_site_that_composes_it():
    """The negative control, with a docstring and a comment that describe it and
    the homes that spell it."""
    assert _spellings(_COMPOSES_IT) == []
    assert _spellings(_ONLY_DESCRIBES_IT) == []
    assert _spellings(_THE_HOMES) == []


def test_no_code_in_subprocess_utils_spells_the_sentence_outside_its_homes():
    source = Path(subprocess_utils.__file__).read_text(encoding="utf-8")

    assert _spellings(source) == []
