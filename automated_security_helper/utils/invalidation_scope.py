"""The invalidation scope enum, defined where ``utils`` and ``core`` both reach it.

``utils/ash_lock.py`` records and checks it, and the layer order does not let
``utils`` import ``core``. ``core.enums`` re-exports the class, so
``core.enums.InvalidationScope`` is this same class.
"""

from enum import Enum


class InvalidationScope(str, Enum):
    """What makes a recorded symbol suppression stop applying (``.ash.lock``).

    ``FILE``: any change to the code of the suppression's file. ``SYMBOL``: a
    change to the code of the suppressed definition itself (its lines, every
    definition bearing its name, the headers of the definitions it sits in, and
    the file's prelude). Layout between tokens is never a change. Each recorded
    scope carries one; ``ash suppress add --invalidation-scope`` chooses it for
    a new scope, ``ash suppress refresh --invalidation-scope`` converts one.
    """

    FILE = "file"
    SYMBOL = "symbol"

    def __str__(self) -> str:
        return self.value
