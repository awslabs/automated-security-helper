from automated_security_helper.utils.meta_analysis.get_message_text import (
    get_message_text,
)


def test_get_message_text_with_text():
    """Test getting message text when text field is present."""
    result = {"message": {"text": "Test finding"}}

    message = get_message_text(result)
    assert message == "Test finding"


def test_get_message_text_with_markdown():
    """Test getting message text when markdown field is present."""
    result = {"message": {"markdown": "**Test** finding"}}

    message = get_message_text(result)
    assert message == ""  # Implementation doesn't handle markdown


def test_get_message_text_with_both():
    """Test getting message text when both text and markdown fields are present."""
    result = {"message": {"text": "Test finding", "markdown": "**Test** finding"}}

    message = get_message_text(result)
    assert message == "Test finding"  # Text should be preferred


def test_get_message_text_without_message():
    """Test getting message text when message field is not present."""
    result = {"ruleId": "TEST001"}

    message = get_message_text(result)
    assert message == ""  # Returns empty string, not None


def test_get_message_text_with_empty_message():
    """Test getting message text when message field is empty."""
    result = {"message": {}}

    message = get_message_text(result)
    assert message == ""  # Returns empty string, not None
