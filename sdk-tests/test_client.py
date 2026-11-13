

import pytest
from swiftapi import SwiftAPI, __version__
from swiftapi.exceptions import AuthenticationError

VALID_SWIFTAPI_KEY = "swiftapi_live_" + "a" * 64


class TestClientInit:
    def test_requires_key(self):
        with pytest.raises(AuthenticationError, match="API key is required"):
            SwiftAPI(key="")

    def test_requires_key_none(self):
        with pytest.raises(AuthenticationError, match="API key is required"):
            SwiftAPI(key=None)

    def test_rejects_invalid_prefix(self):
        with pytest.raises(AuthenticationError, match="must start with"):
            SwiftAPI(key="sk-invalid-key-format")

    def test_accepts_valid_key(self):
        client = SwiftAPI(key=VALID_SWIFTAPI_KEY)
        assert client.key == VALID_SWIFTAPI_KEY

    def test_default_base_url(self):
        client = SwiftAPI(key=VALID_SWIFTAPI_KEY)
        assert client.base_url == "https://swiftapi.ai"

    def test_custom_base_url(self):
        client = SwiftAPI(key=VALID_SWIFTAPI_KEY, base_url="https://custom.example.com/")
        assert client.base_url == "https://custom.example.com"

    def test_user_agent_matches_version(self):
        client = SwiftAPI(key=VALID_SWIFTAPI_KEY)
        ua = client._session.headers["User-Agent"]
        assert ua == f"swiftapi-python/{__version__}"

    def test_authority_header_set(self):
        client = SwiftAPI(key=VALID_SWIFTAPI_KEY)
        assert client._session.headers["X-SwiftAPI-Authority"] == VALID_SWIFTAPI_KEY

    def test_context_manager(self):
        with SwiftAPI(key=VALID_SWIFTAPI_KEY) as client:
            assert client.key == VALID_SWIFTAPI_KEY
