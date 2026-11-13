# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sigterm_plugins fixture's tool: block until the stop path kills the group.

Ignores SIGTERM, so a stop that only signalled the process would not end it:
ending requires the group SIGKILL the cancellable spawn sends after its grace.
Writes its pid to the file ``argv[1]`` names only after the handler is set, so
the test's "the tool is running" moment is also "the tool is unkillable by a
plain SIGTERM". The pid file is created empty first and written after, as a
busy host can make one ``write_text`` visible between its two steps.
"""

import pathlib
import os
import signal
import sys
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
pid_file = pathlib.Path(sys.argv[1])
pid_file.touch()
pid_file.write_text(str(os.getpid()))
time.sleep(120)
