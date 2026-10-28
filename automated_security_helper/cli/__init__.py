#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import signal

#: Whether this process started with SIGINT ignored, as a POSIX shell starts a
#: background job so that Ctrl-C reaches only the job in the foreground. Read
#: once, when the first CLI module is imported: the console script imports
#: cli.entrypoint, and so this package, before Typer, Rich or uvicorn run, and
#: uvicorn replaces whatever SIGINT disposition it finds (cli/mcp._run_uvicorn).
SIGINT_IGNORED_AT_START = signal.getsignal(signal.SIGINT) == signal.SIG_IGN
