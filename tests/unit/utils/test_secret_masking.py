"""Tests for secret masking utilities."""

from automated_security_helper.utils.secret_masking import (
    mask_secret_in_text,
    _mask_bandit_b105_secret,
    _mask_secret_value,
)


class TestSecretMasking:
    """Test cases for secret masking functionality."""

    def test_mask_secret_value_short(self):
        """Test masking of short secrets."""
        assert _mask_secret_value("abc") == "***"
        assert _mask_secret_value("ab") == "**"
        assert _mask_secret_value("a") == "*"
        assert _mask_secret_value("") == ""

    def test_mask_secret_value_medium(self):
        """Test masking of medium-length secrets (>= 75% masked for short)."""
        assert _mask_secret_value("test1234") == "t******4"  # 8 chars: show first + last
        assert _mask_secret_value("secret") == "s*****"  # 6 chars: show first only
        assert _mask_secret_value("pass") == "p***"  # 4 chars: show first only

    def test_mask_secret_value_long(self):
        """Test masking of long secrets."""
        long_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        masked = _mask_secret_value(long_secret)
        assert masked.startswith("wJ")
        assert masked.endswith("Y")
        assert "*" in masked
        assert len(masked) == len(long_secret)

    def test_mask_bandit_b105_single_quote(self):
        """Test masking of B105 findings with single quotes."""
        text = "Possible hardcoded password: 'super_secret_password_123'"
        result = _mask_bandit_b105_secret(text)
        assert "super_secret_password_123" not in result
        assert result.startswith("Possible hardcoded password: 'su")
        assert result.endswith("3'")

    def test_mask_bandit_b105_double_quote(self):
        """Test masking of B105 findings with double quotes."""
        text = 'Possible hardcoded password: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        result = _mask_bandit_b105_secret(text)
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result
        assert result.startswith('Possible hardcoded password: "wJ')
        assert result.endswith('Y"')

    def test_mask_bandit_b105_no_match(self):
        """Test that non-matching text is not modified."""
        text = "Some other security finding"
        result = _mask_bandit_b105_secret(text)
        assert result == text

    def test_mask_secret_in_text_b105(self):
        """Test the main masking function with B105 rule."""
        text = "Possible hardcoded password: 'test_secret'"
        result = mask_secret_in_text(text, "B105")
        assert "test_secret" not in result
        assert "Possible hardcoded password:" in result

    def test_mask_secret_in_text_other_rule(self):
        """Test that other rules are not affected."""
        text = "Some other finding with 'secret' in it"
        result = mask_secret_in_text(text, "B101")
        assert result == text

    def test_mask_secret_in_text_no_rule(self):
        """Test that text without rule ID is not modified."""
        text = "Possible hardcoded password: 'secret'"
        result = mask_secret_in_text(text, None)
        assert result == text

    def test_mask_secret_in_text_empty_text(self):
        """Test that empty text is handled correctly."""
        result = mask_secret_in_text("", "B105")
        assert result == ""

    def test_mask_secret_in_text_none_text(self):
        """Test that None text is handled correctly."""
        result = mask_secret_in_text(None, "B105")
        assert result is None

    def test_real_world_examples(self):
        """Test with real-world examples from the issue description."""
        # Example 1: AWS Secret Key
        text1 = (
            "Possible hardcoded password: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
        )
        result1 = mask_secret_in_text(text1, "B105")
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result1
        assert "Possible hardcoded password:" in result1
        assert result1.startswith("Possible hardcoded password: 'wJ")
        assert result1.endswith("Y'")

        # Example 2: Database Password
        text2 = "Possible hardcoded password: 'super_secret_password_123'"
        result2 = mask_secret_in_text(text2, "B105")
        assert "super_secret_password_123" not in result2
        assert "Possible hardcoded password:" in result2
        assert result2.startswith("Possible hardcoded password: 'su")
        assert result2.endswith("3'")
