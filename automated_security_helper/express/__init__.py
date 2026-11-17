# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Express mode: a resident warm daemon that removes ASH's startup cost.

A cold ``ash scan`` pays the interpreter start and the eager import of the CLI,
its models and every built-in plugin module before any scanning work begins --
around two seconds on a typical machine. A pre-commit hook pays it on every
commit. Express mode keeps one resident Python process per user with those
modules already imported; each scan request forks that warm process
(copy-on-write imports, clean per-run state) and the forked child drops into
the normal CLI entry with the request's argv, so the scan itself is the same
code a cold run executes.

The pieces:

* :mod:`automated_security_helper.express.runtime` -- paths, the wire protocol
  and the identity checks shared by the client and the daemon. Standard
  library only.
* :mod:`automated_security_helper.express.client` -- the thin client the console
  entry point calls before it imports the heavy CLI. Standard library only:
  importing anything heavier would spend the time the daemon exists to save.
* :mod:`automated_security_helper.express.daemon` -- the resident process. It
  imports the heavy modules once, listens on a per-user unix socket, and
  forks a child per scan.
* ``ash express start|stop|status`` -- the management commands
  (automated_security_helper/cli/express.py).

Security model, in one place: the socket is a unix stream socket in a 0700
directory owned by the invoking user, the socket file itself is 0600, the
daemon reads the connecting peer's uid from the kernel (``SO_PEERCRED``) and
refuses any uid but its own, and there is no TCP listener and no network
transport of any kind. A platform where any of that is unavailable simply has
no express mode: every scan falls back to the ordinary cold in-process run.

This package's modules import nothing outside the standard library at module
scope (the daemon imports the heavy modules inside its serve loop), so the
thin client stays thin.
"""
