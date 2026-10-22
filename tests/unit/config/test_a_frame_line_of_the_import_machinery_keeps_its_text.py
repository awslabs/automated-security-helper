# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A masked module's needles leave ASH's and importlib's own frame lines readable.

A masked segment spelled like the import machinery's own vocabulary
("import_module", "exec_module") blanked frame text that is the same for
every failing load -- `, in import_module` became `, in <value>` -- and the
blanking itself told a reader what the segment is called. The module-form
needles now carry a frame exemption: inside a traceback frame line of ASH's
or the import machinery's own files, from after the quoted path through the
source line printed under it, a module form keeps the text. Everywhere else
the form redacts as before, a plain environment value sharing the form keeps
the strict treatment, and the quoted path itself is never exempt (a plugin
under ASH's opt-in root puts the masked leaf in that path).

The distribution needle grows the same way: PEP 503 treats every run of
"-", "_" and "." as one separator, so the canonical literal alone left every
other separator spelling readable. The canonical form now carries a variant
pattern matched case-insensitively in the canonical's own band: anywhere for
a canonical of the anywhere band, as the literal is matched -- a dist-info
file name runs the spelling straight into "-1.0" -- and whole-name bounded
for a shorter one. A name that does not normalize segment for segment
("segtopash.plugins", "segtop.smash.plugins") stays another name's text.

Cells: must-flag (an ASH frame's call text, an importlib frame's own
function name, a separator variant, the canonical form carrying the
pattern); must-not-flag (a third-party frame, frame-shaped text inside a
line, a frame line sheltering the next frame line, a shared plain value, a
variant glued into a word, a short canonical); and the str-behavior control
(module-form needles leave a plain value's output byte-identical).
"""

from __future__ import annotations

from automated_security_helper.config.config_validator import redact_values
from automated_security_helper.plugins.loader import _masked_module_forms

MASKED = "segtop_ash_plugins.import_module"
DIST = "segtop_ash_plugins"

ASH_FRAME = (
    '  File "/w/automated_security_helper/plugins/loader.py", line 645, '
    "in load_additional_plugin_modules\n"
    "    module = importlib.import_module(module_path)\n"
)
IMPORTLIB_FRAME = (
    '  File "/usr/lib/python3.14/importlib/__init__.py", line 88, '
    "in import_module\n"
    "    return _bootstrap._gcd_import(name[level:], package, level)\n"
)
THIRD_PARTY_FRAME = (
    '  File "/w/site-packages/otherpkg/hook.py", line 3, in import_module\n'
    "    raise RuntimeError(name)\n"
)


# --- must-flag: the machinery's own text survives --------------------------


def test_an_ash_frames_import_call_keeps_its_text():
    redacted = redact_values(ASH_FRAME, _masked_module_forms(MASKED))
    assert "importlib.import_module(module_path)" in redacted, redacted
    assert "in load_additional_plugin_modules" in redacted, redacted


def test_an_importlib_frames_own_function_name_keeps_its_text():
    redacted = redact_values(IMPORTLIB_FRAME, _masked_module_forms(MASKED))
    assert ", in import_module" in redacted, redacted


def test_a_separator_variant_of_the_distribution_name_is_hidden():
    text = (
        "No package metadata was found for Segtop.Ash_Plugins "
        "(from Segtop.Ash_Plugins-1.0.dist-info)\n"
    )
    redacted = redact_values(text, _masked_module_forms(DIST))
    assert "Segtop.Ash_Plugins" not in redacted, redacted
    assert "<value>" in redacted, redacted


def test_the_canonical_distribution_form_carries_the_variant_pattern():
    carrying = [
        str(form)
        for form in _masked_module_forms(DIST)
        if getattr(form, "pattern", None) is not None
    ]
    assert carrying == ["segtop-ash-plugins"], carrying


# --- must-not-flag: everywhere else the needles redact as before ------------


def test_a_third_party_frame_quoting_the_segment_is_still_hidden():
    redacted = redact_values(THIRD_PARTY_FRAME, _masked_module_forms(MASKED))
    assert "import_module" not in redacted, redacted


def test_frame_shaped_text_inside_a_line_is_still_hidden():
    text = (
        'the tool said: File "/w/automated_security_helper/x.py", line 1, '
        "in import_module and stopped\n"
    )
    redacted = redact_values(text, _masked_module_forms(MASKED))
    assert "import_module" not in redacted, redacted


def test_an_ash_frame_does_not_shelter_the_frame_line_under_it():
    text = (
        '  File "/w/automated_security_helper/plugins/loader.py", line 645, '
        "in load_additional_plugin_modules\n"
        '  File "/w/site-packages/otherpkg/hook.py", line 3, in import_module\n'
    )
    redacted = redact_values(text, _masked_module_forms(MASKED))
    assert "import_module" not in redacted, redacted
    assert "in load_additional_plugin_modules" in redacted, redacted


def test_an_importlib_frame_does_not_shelter_the_error_line_under_it():
    text = (
        '  File "<frozen importlib._bootstrap>", line 1360, in _find_and_load\n'
        "ModuleNotFoundError: No module named 'segtop_ash_plugins'\n"
    )
    redacted = redact_values(text, _masked_module_forms(MASKED))
    assert "segtop_ash_plugins" not in redacted, redacted


def test_the_quoted_path_of_an_ash_frame_is_never_exempt():
    # A plugin under ASH's opt-in root puts the masked leaf inside an
    # automated_security_helper path, so the path field keeps full redaction.
    value = "automated_security_helper.plugin_modules.kqoptleafq_ash_plugins"
    text = (
        '  File "/w/automated_security_helper/plugin_modules/'
        'kqoptleafq_ash_plugins/__init__.py", line 1, in <module>\n'
        "    raise RuntimeError('body refuses')\n"
    )
    redacted = redact_values(text, _masked_module_forms(value))
    assert "kqoptleafq_ash_plugins" not in redacted, redacted


def test_a_frame_under_an_opt_in_plugin_root_masks_its_source_line():
    # The frame's path is under ASH's package directory, but it also holds
    # the masked value's forms, so nothing in the frame is exempt.
    value = "automated_security_helper.plugin_modules.kqoptleafq_ash_plugins"
    text = (
        '  File "/w/automated_security_helper/plugin_modules/'
        'kqoptleafq_ash_plugins/__init__.py", line 3, in <module>\n'
        "    import kqoptleafq_ash_plugins.helper\n"
    )
    redacted = redact_values(text, _masked_module_forms(value))
    assert "kqoptleafq_ash_plugins" not in redacted, redacted


def test_a_frame_whose_path_holds_a_prefix_form_is_not_exempt():
    text = (
        '  File "/w/automated_security_helper/segtop_ash_plugins/__init__.py", '
        "line 3, in setup\n"
        "    import_module('x')\n"
    )
    redacted = redact_values(text, _masked_module_forms(MASKED))
    assert "segtop_ash_plugins" not in redacted, redacted
    assert "import_module" not in redacted, redacted


def test_a_directory_named_like_importlib_is_not_the_standard_library():
    text = (
        '  File "/w/site-packages/importlib_metadata/__init__.py", line 9, '
        "in import_module\n"
        "    return _gcd_import(name)\n"
    )
    redacted = redact_values(text, _masked_module_forms(MASKED))
    assert "import_module" not in redacted, redacted


def test_a_directory_named_like_the_package_is_not_the_package():
    text = (
        '  File "/w/automated_security_helper_extras/hook.py", line 9, '
        "in import_module\n"
    )
    redacted = redact_values(text, _masked_module_forms(MASKED))
    assert "import_module" not in redacted, redacted


def test_a_frozen_importlib_frame_keeps_its_text():
    text = (
        '  File "<frozen importlib._bootstrap>", line 1360, in import_module\n'
        "    return _gcd_import(name)\n"
    )
    redacted = redact_values(text, _masked_module_forms(MASKED))
    assert ", in import_module" in redacted, redacted


def test_a_value_shared_with_a_module_form_keeps_the_strict_treatment():
    values = ("import_module", *_masked_module_forms(MASKED))
    redacted = redact_values(IMPORTLIB_FRAME, values)
    assert "import_module" not in redacted, redacted


def test_a_name_that_does_not_normalize_to_the_distribution_stays_readable():
    # The partial-normalize collisions: a missing separator and a different
    # segment are other names, however close their spelling.
    text = "segtopash.plugins and segtop.smash.plugins stay readable\n"
    assert redact_values(text, _masked_module_forms(DIST)) == text


def test_a_short_canonicals_variants_match_only_whole():
    # Band from the canonical's length: "kq-zw" is under the anywhere band,
    # so its separator variants are matched whole-name only.
    forms = _masked_module_forms("kq_zw")
    hidden = redact_values("the value kq.zw was printed\n", forms)
    assert "kq.zw" not in hidden and "<value>" in hidden, hidden
    kept = "skq.zw and kq.zwx stay readable\n"
    assert redact_values(kept, forms) == kept


def test_a_short_canonical_name_adds_no_pattern():
    carrying = [
        str(form)
        for form in _masked_module_forms("a_b")
        if getattr(form, "pattern", None) is not None
    ]
    assert carrying == [], carrying


# --- the str-behavior control -----------------------------------------------


def test_module_form_needles_leave_a_plain_values_output_identical():
    text = (
        "the operator value kqplainsecretz was printed beside importlib "
        "text and a loader word\n"
    )
    alone = redact_values(text, ("kqplainsecretz",))
    beside = redact_values(text, ("kqplainsecretz", *_masked_module_forms(MASKED)))
    assert alone == beside, (alone, beside)
    assert "kqplainsecretz" not in alone, alone
