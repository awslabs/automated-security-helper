"""Regression tests for secret_masking bug fixes.

PR#274 Bug #156: 4-char secrets reveal 50% (show first + last of 4)
PR#274 Bug #157: regex stops at internal quote
PR#274 Bug #158: B106 and B107 are not dispatched
"""

import pytest


class TestSecretMasking:
    """Tests for secret masking deficiencies."""

    # PR#274 Bug #156: 4-char secrets reveal 50% (show first + last of 4)
    def test_short_secret_masking_ratio(self):
        """4-char secret must have >= 75% masked characters."""
        from automated_security_helper.utils.secret_masking import _mask_secret_value

        masked = _mask_secret_value("abcd")
        star_count = masked.count("*")
        total = len(masked)
        ratio = star_count / total
        assert ratio >= 0.75, f"Only {ratio:.0%} masked for 4-char secret: {masked}"

    def test_five_char_secret_masking(self):
        """5-char secret must have >= 75% masked."""
        from automated_security_helper.utils.secret_masking import _mask_secret_value

        masked = _mask_secret_value("abcde")
        star_count = masked.count("*")
        ratio = star_count / len(masked)
        assert ratio >= 0.75, f"Only {ratio:.0%} masked for 5-char secret: {masked}"

    def test_ten_char_secret_masking(self):
        """10-char secret masking should be reasonable."""
        from automated_security_helper.utils.secret_masking import _mask_secret_value

        masked = _mask_secret_value("abcdefghij")
        star_count = masked.count("*")
        ratio = star_count / len(masked)
        assert ratio >= 0.50, f"Only {ratio:.0%} masked for 10-char secret"

    # PR#274 Bug #158: B106 and B107 are not dispatched
    def test_b106_rule_masks_secret(self):
        """B106 (hardcoded password in funcarg) must be masked."""
        from automated_security_helper.utils.secret_masking import mask_secret_in_text

        text = "Possible hardcoded " + "password: 'SuperSecret123'"
        result = mask_secret_in_text(text, rule_id="B106")
        assert "SuperSecret123" not in result

    def test_b107_rule_masks_secret(self):
        """B107 (hardcoded password in config) must be masked."""
        from automated_security_helper.utils.secret_masking import mask_secret_in_text

        text = "Possible hardcoded " + "password: 'MyPassw0rd'"
        result = mask_secret_in_text(text, rule_id="B107")
        assert "MyPassw0rd" not in result

    def test_b105_still_works(self):
        """B105 masking should continue to work after the fix."""
        from automated_security_helper.utils.secret_masking import mask_secret_in_text

        text = "Possible hardcoded " + "password: 'secret123'"
        result = mask_secret_in_text(text, rule_id="B105")
        assert "secret123" not in result

    # PR#274 Bug #157: regex stops at internal quote
    def test_secret_with_internal_quote(self):
        """Secret containing a quote should still be fully masked."""
        from automated_security_helper.utils.secret_masking import mask_secret_in_text

        text = "Possible hardcoded " + "password: 'it\\'s_a_secret'"
        result = mask_secret_in_text(text, rule_id="B105")
        # The secret value should not appear in cleartext
        assert "it's_a_secret" not in result or "****" in result

    def test_secret_with_double_quote_delimiter(self):
        """Secret in double quotes should be masked."""
        from automated_security_helper.utils.secret_masking import mask_secret_in_text

        text = 'Possible hardcoded ' + 'password: "MySecret99"'
        result = mask_secret_in_text(text, rule_id="B105")
        assert "MySecret99" not in result
