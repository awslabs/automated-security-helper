"""Positive control for the ASH pull-request gate. Every function here is meant
to be flagged; nothing here should ever be copied into real code.

WHY EACH ARGUMENT IS A VARIABLE AND NOT A LITERAL
-------------------------------------------------
bandit grades the shell-injection checks by what is passed, not by the call
alone. `subprocess.call("ls", shell=True)` on a *literal* string is LOW, which
is below the gate's default MEDIUM threshold and would make this file a
non-actionable control that silently proves nothing. Passing a variable is what
makes B602 and B605 HIGH. Do not "simplify" these to literals.

Verified severities (see expected.json for provenance):
  B602 subprocess with shell=True  -> HIGH
  B605 start process with a shell  -> HIGH
  B307 use of eval                 -> MEDIUM
  B404 import subprocess           -> LOW  (below threshold, non-actionable)
"""

import os
import subprocess


def run_untrusted(cmd):
    # bandit B602, HIGH: shell=True with a non-literal argument.
    return subprocess.call(cmd, shell=True)


def shell_out(user_input):
    # bandit B605, HIGH: hands a constructed string to a shell.
    return os.system("echo " + user_input)


def unsafe_eval(expression):
    # bandit B307, MEDIUM: evaluates arbitrary input.
    return eval(expression)
