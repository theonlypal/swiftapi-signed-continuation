

from swiftapi.openai import ChatCompletion, Choice, Message
from swiftapi.anthropic import MessageResponse, ContentBlock


class TestChatCompletion:
    pass

    def test_normal_response(self):
        r = ChatCompletion(content="Hello world", model="gpt-4o")
        assert r.choices[0].message.content == "Hello world"
        assert r.choices[0].finish_reason is None
        assert r.model == "gpt-4o"

    def test_void_response(self):
        pass
        r = ChatCompletion(content="", model="gpt-4o")
        assert r.choices[0].message.content == ""
        assert r.choices[0].finish_reason is None
        assert r.classification == "GATE_BLOCK"

    def test_content_shortcut(self):
        r = ChatCompletion(content="test", model="gpt-4o")
        assert r.content == r.choices[0].message.content

    def test_attested_flag(self):
        r = ChatCompletion(content="Hi", model="gpt-4o", attested=True, jti="abc-123")
        assert r.attested is True
        assert r.jti == "abc-123"

    def test_not_attested_by_default(self):
        r = ChatCompletion(content="Hi", model="gpt-4o")
        assert r.attested is False
        assert r.jti is None

    def test_choice_structure(self):
        r = ChatCompletion(content="test", model="gpt-4o")
        assert len(r.choices) == 1
        assert r.choices[0].index == 0
        assert isinstance(r.choices[0], Choice)
        assert isinstance(r.choices[0].message, Message)
        assert r.choices[0].message.role == "assistant"


class TestMessageResponse:
    pass

    def test_normal_response(self):
        r = MessageResponse(content="Hello world", model="claude-sonnet-4-5-20250929")
        assert r.content[0].text == "Hello world"
        assert r.stop_reason is None
        assert r.role == "assistant"

    def test_void_response(self):
        pass
        r = MessageResponse(content="", model="claude-sonnet-4-5-20250929")
        assert r.content[0].text == ""
        assert r.stop_reason is None
        assert r.classification == "GATE_BLOCK"

    def test_text_shortcut(self):
        r = MessageResponse(content="test", model="claude-sonnet-4-5-20250929")
        assert r.text == r.content[0].text

    def test_attested_flag(self):
        r = MessageResponse(content="Hi", model="claude-sonnet-4-5-20250929", attested=True, jti="abc-123")
        assert r.attested is True
        assert r.jti == "abc-123"

    def test_content_block_structure(self):
        r = MessageResponse(content="test", model="claude-sonnet-4-5-20250929")
        assert len(r.content) == 1
        assert isinstance(r.content[0], ContentBlock)
        assert r.content[0].type == "text"
