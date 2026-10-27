# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Threads that carry the context of the code that starts them.

A thread made with threading.Thread starts in an empty context: a line it
logs belongs to no run, and a cancellation check in it reads no scope. The
factory here copies the starting code's context into the thread, so what the
run set -- its log scope, its cancellation scope, every other context
variable -- holds on the thread too. Its own module, not the logging one,
because it carries thread and cancellation semantics and is documented plugin
API; ``utils.log`` re-exports it for the callers that reached it there.
"""

import contextvars
import threading
from typing import Any, Callable, Iterable, Mapping, Optional


def ash_thread(
    target: Callable[..., Any],
    args: Iterable[Any] = (),
    kwargs: Optional[Mapping[str, Any]] = None,
    *,
    name: Optional[str] = None,
    daemon: Optional[bool] = None,
) -> threading.Thread:
    """A thread that runs ``target(*args, **kwargs)`` in this context, copied.

    For ASH and plugin code that starts a thread of its own during a scan. A
    thread made with threading.Thread starts in an empty context, so a line it
    logs belongs to no run: a CLI scan's ash.log still takes it, but the MCP
    server, which runs several sessions' scans in one process, puts it in no
    scan's ash.log, only in the server's own log. This thread carries the
    scan's log scope, as ASH's scanner workers do, so its lines are its scan's,
    and so does every other context variable the scan set, its cancellation
    scope among them. The context is copied here, when the thread is made.
    Returned unstarted: call ``start()``, as with threading.Thread.

    For an executor, submit through a copy the same way:
    ``pool.submit(contextvars.copy_context().run, fn, *args)``.
    """
    context = contextvars.copy_context()
    return threading.Thread(
        target=context.run,
        args=(target, *args),
        kwargs=dict(kwargs or {}),
        name=name,
        daemon=daemon,
    )
