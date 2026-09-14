# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A dumped ``AshAggregatedResults`` can be loaded back.

Why this file exists
--------------------
``cli/merge.py:1109`` writes the merged results file with
``merged.model_dump_json(indent=2)`` -- no ``by_alias``. ``cli/merge.py:357``
reads results files back with ``AshAggregatedResults.model_validate_json``. So
dump-then-load is a real path through the product, not a test-only shape, and
running ``ash merge`` over a directory that already holds merged output takes it.

That path breaks whenever ``AshAggregatedResults.__pydantic_custom_init__`` is
``True``. With the flag set, pydantic-core stops validating the input mapping in
place and instead materializes one and calls ``cls(**data)``, which re-enters
validation with **Python field names**. Several nested CycloneDX models are
``extra="forbid"`` and populate by alias only (``bom-ref``, ``mime-type``), so the
Python-named keys that ``model_dump_json()`` emits are rejected as extra inputs.
Measured on the real ``tests/test_data/outputs/ash_aggregated_results.json``: the
file itself loads, and reloading its own dump fails with 4637 validation errors.
A single CycloneDX component is enough to reproduce it, which is what the test
below uses.

The flag is ``True`` for exactly one reason: ``AshAggregatedResults`` defines
``__init__``, to retry the ``AshConfig`` forward-reference rebuild on first use
(see ``test_forward_ref_resolves_in_any_import_order.py`` for why that retry
cannot be dropped). ``_model_construction`` derives the flag from
``not getattr(cls.__init__, '__pydantic_base_init__', False)``, so
``models/asharp_model.py`` marks its override the way Pydantic marks its own two
pass-through inits, and the flag stays ``False``.

**That marker is what this file protects.** A single line reading
``__init__.__pydantic_base_init__ = True`` looks exactly like dead code, and
deleting it produces no import error, no type error, and no failure in any test
that only checks deserialization of a file ASH wrote with ``by_alias=True``. It
fails here instead.

Both assertions are deliberate: the first names the mechanism and stays readable
if the round-trip payload ever drifts, the second proves the consequence a user
would actually hit. Neither needs a subprocess -- unlike the import-order guard,
this property is not masked by the module-scope ``model_rebuild()`` prologues in
the rest of the suite, because it does not depend on when the rebuild ran.
"""

from automated_security_helper.models.asharp_model import AshAggregatedResults

# One CycloneDX component. The trigger is not an alias in the *input* -- an input
# with "bom-ref" and one without both fail once the flag is True -- it is that the
# dump emits mime_type and bom_ref for a model that only accepts mime-type and
# bom-ref. So the payload deliberately keeps a component rather than being
# minimized down to "{}", which reloads fine either way and would prove nothing.
_ONE_COMPONENT = (
    '{"cyclonedx": {"components": ['
    '{"type": "library", "name": "zipp", "version": "3.21.0"}]}}'
)


def test_custom_init_stays_false():
    """The __init__ override must not turn on pydantic-core's custom_init path."""
    assert AshAggregatedResults.__pydantic_custom_init__ is False, (
        "__pydantic_custom_init__ is True, so pydantic-core will materialize a "
        "mapping and call cls(**data) on every model_validate_json instead of "
        "validating in place. That re-enters validation with Python field names "
        "and breaks the dump-then-load path in cli/merge.py. Most likely cause: "
        "the __init__.__pydantic_base_init__ = True marker in "
        "models/asharp_model.py was removed, or Pydantic changed how "
        "_model_construction derives this flag."
    )


def test_dumped_results_load_back():
    """model_dump_json() output survives model_validate_json(), as merge needs."""
    model = AshAggregatedResults.model_validate_json(_ONE_COMPONENT)
    assert model.cyclonedx is not None
    assert len(model.cyclonedx.components) == 1

    # No by_alias, matching cli/merge.py:1109 exactly.
    dumped = model.model_dump_json()

    reloaded = AshAggregatedResults.model_validate_json(dumped)
    assert reloaded.cyclonedx is not None, (
        "the dumped results reloaded, but lost cyclonedx on the way"
    )
    assert len(reloaded.cyclonedx.components) == 1, (
        "the dumped results reloaded, but the CycloneDX component did not survive"
    )
    assert reloaded.cyclonedx.components[0].name == "zipp"
