

import pytest
from swiftapi import Anthropic
from swiftapi.exceptions import AuthenticationError

VALID_SWIFTAPI_KEY = "swiftapi_live_" + "a" * 64


class TestAnthropicInit:
    def test_requires_swiftapi_key(self):
        with pytest.raises(AuthenticationError, match="swiftapi_key is required"):
            Anthropic(anthropic_key="sk-ant-test")

    def test_requires_anthropic_key(self):
        with pytest.raises(AuthenticationError, match="anthropic_key is required"):
            Anthropic(swiftapi_key=VALID_SWIFTAPI_KEY)

    def test_rejects_invalid_swiftapi_key(self):
        with pytest.raises(AuthenticationError, match="must start with"):
            Anthropic(swiftapi_key="invalid_key", anthropic_key="sk-ant-test")

    def test_accepts_valid_keys(self):
        client = Anthropic(swiftapi_key=VALID_SWIFTAPI_KEY, anthropic_key="sk-ant-test")
        assert client.messages is not None

    def test_api_key_alias(self):
        client = Anthropic(swiftapi_key=VALID_SWIFTAPI_KEY, api_key="sk-ant-test")
        assert client.messages is not None

    def test_messages_namespace(self):
        client = Anthropic(swiftapi_key=VALID_SWIFTAPI_KEY, anthropic_key="sk-ant-test")
        assert hasattr(client.messages, "create")
