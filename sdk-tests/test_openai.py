

import pytest
from swiftapi import OpenAI
from swiftapi.exceptions import AuthenticationError

VALID_SWIFTAPI_KEY = "swiftapi_live_" + "a" * 64


class TestOpenAIInit:
    def test_requires_swiftapi_key(self):
        with pytest.raises(AuthenticationError, match="swiftapi_key is required"):
            OpenAI(openai_key="sk-test")

    def test_requires_openai_key(self):
        with pytest.raises(AuthenticationError, match="openai_key is required"):
            OpenAI(swiftapi_key=VALID_SWIFTAPI_KEY)

    def test_rejects_invalid_swiftapi_key(self):
        with pytest.raises(AuthenticationError, match="must start with"):
            OpenAI(swiftapi_key="invalid_key", openai_key="sk-test")

    def test_accepts_valid_keys(self):
        client = OpenAI(swiftapi_key=VALID_SWIFTAPI_KEY, openai_key="sk-test")
        assert client.chat is not None
        assert client.chat.completions is not None

    def test_api_key_alias(self):
        client = OpenAI(swiftapi_key=VALID_SWIFTAPI_KEY, api_key="sk-test")
        assert client.chat.completions is not None

    def test_chat_completions_namespace(self):
        client = OpenAI(swiftapi_key=VALID_SWIFTAPI_KEY, openai_key="sk-test")
        assert hasattr(client.chat, "completions")
        assert hasattr(client.chat.completions, "create")
