# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Vocabularies that cross the models, base and plugin layers.

A vocabulary lives here when more than one layer names its members. A
vocabulary one module owns stays in that module, and an enum that already has
a home stays there.

Every member's value is the spelling the wire carries. Compare members by
identity and take ``.value`` where text leaves the process (an f-string, a log
line, an argv, a tag): ``str(member)`` and ``format(member)`` render the
qualified member name on some supported interpreters.
"""

from enum import Enum


class FailureKind(str, Enum):
    """What failed when a converter could not convert an input.

    ``INPUT`` is the file not being one the converter could hand to its tool;
    ``TOOL`` is the tool, or the run, failing. The kind decides who may waive
    the completeness gate: only an ``INPUT`` failure can be accepted by an
    ``ash-unconverted-input`` suppression. Any value this version does not know
    reads as ``TOOL``, the side that is never accepted.
    """

    INPUT = "input"
    TOOL = "tool"
