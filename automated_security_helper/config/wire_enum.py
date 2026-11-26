# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The shared pieces of a config field whose type is a wire-spelled enum.

``sandbox.mode`` (``SandboxMode``) and ``output_formats`` (``ExportFormat``) read
a name from YAML, an environment reference or the command line, hold the enum
member, and dump the name again in every mode. Each used to carry its own copy
of the conversion and of the dump, and each future config field of this kind
would have copied them again. Two pieces are shared here:

* :func:`wire_enum_validator` builds the before-validator that turns a name into
  its member. The field supplies only what differs: how a refusal reads, whether
  the name is stripped, and whether a non-text input is refused or left for
  pydantic's own type check.
* :func:`wire_value` is the serializer body. It never raises and never quotes the
  value, because the models do not validate assignment: a field can hold a plain
  string that names no member (``cfg.sandbox.mode = "bogus"``), and a dump of it
  must not fail with a message that quotes a value that may have come from the
  environment.

The ``@field_serializer`` declarations stay on the models, one line each: the
stored-results schema generator looks a serializer up by its qualified name
(``AshConfig._output_format_values`` in ``schemas/generate_schemas.py``).
"""

from enum import Enum
from typing import Any, Callable, Type


def wire_value(value: Any) -> str:
    """The text a wire-enum field dumps: the member's value, else the text as held.

    Never raises, and never puts the held value in an error.
    """
    return str(getattr(value, "value", value))


def wire_enum_validator(
    enum_class: Type[Enum],
    refuse: Callable[[Any], Any],
    *,
    strip: bool = False,
) -> Callable[[Any], Any]:
    """A before-validator turning a name into a member of ``enum_class``.

    Config files are validated with ``strict=True``, which accepts only a member
    for an enum field, so a name read from YAML would be refused; converting here
    keeps the enum type. A member passes through. A text that names a member
    (stripped first when ``strip``) becomes the plain member, so the loader's
    carrier ``str`` subclass for an environment reference does not survive.
    Anything else goes to ``refuse``, which raises the field's own refusal, or
    returns the input to leave it to pydantic's type check.
    """

    def validate(value: Any) -> Any:
        if isinstance(value, enum_class):
            return value
        if isinstance(value, str):
            name = value.strip() if strip else str(value)
            try:
                return enum_class(name)
            except ValueError:
                pass
        return refuse(value)

    return validate
