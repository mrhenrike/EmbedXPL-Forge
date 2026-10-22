"""Tests for embedxpl.core.http.http_client (HTTPClient)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from embedxpl.core.http.http_client import HTTP_TIMEOUT, HTTPClient


def _make_http_client(target="10.0.0.1", port=80, ssl_on=False):
    """Create an HTTPClient bypassing Exploit.__init__.

    OptBool descriptors only accept "true"/"false" strings via __set__,
    so we manipulate the descriptor .value directly and restore in a fixture-free way.
    """
    obj = object.__new__(HTTPClient)
    obj.target = target
    obj.port = port
    # Bypass OptBool.__set__ by writing .value on the descriptor object
    HTTPClient.__dict__["ssl"].value = ssl_on
    HTTPClient.__dict__["verbosity"].value = False
    return obj


class TestHTTPClientGetTargetUrl:
    def test_http_url(self):
        cli = _make_http_client()
        assert cli.get_target_url("/api") == "http://10.0.0.1:80/api"

    def test_https_url(self):
        cli = _make_http_client(ssl_on=True, port=443)
        assert cli.get_target_url("/login") == "https://10.0.0.1:443/login"

    def test_empty_path(self):
        cli = _make_http_client()
        assert cli.get_target_url() == "http://10.0.0.1:80"

    def test_custom_port(self):
        cli = _make_http_client(port=8080)
        assert cli.get_target_url("/status") == "http://10.0.0.1:8080/status"


class TestHTTPClientRequest:
    def test_get_success(self):
        cli = _make_http_client()
        mock_session = MagicMock()
        mock_resp = MagicMock(spec=requests.Response)
        mock_resp.status_code = 200
        mock_session.get.return_value = mock_resp
        result = cli.http_request("GET", "/index.html", session=mock_session)
        assert result is mock_resp
        mock_session.get.assert_called_once()
        call_kwargs = mock_session.get.call_args
        assert call_kwargs[0][0] == "http://10.0.0.1:80/index.html"
        assert call_kwargs[1]["timeout"] == HTTP_TIMEOUT
        assert call_kwargs[1]["verify"] is False
        assert call_kwargs[1]["allow_redirects"] is False

    def test_post_success(self):
        cli = _make_http_client()
        mock_session = MagicMock()
        mock_resp = MagicMock(spec=requests.Response)
        mock_session.post.return_value = mock_resp
        result = cli.http_request("POST", "/login", session=mock_session, data={"user": "admin"})
        assert result is mock_resp
        mock_session.post.assert_called_once()

    def test_ssl_url(self):
        cli = _make_http_client(ssl_on=True, port=443)
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(spec=requests.Response)
        cli.http_request("GET", "/secure", session=mock_session)
        url = mock_session.get.call_args[0][0]
        assert url.startswith("https://")

    def test_connection_error_returns_none(self):
        cli = _make_http_client()
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        result = cli.http_request("GET", "/", session=mock_session)
        assert result is None

    def test_timeout_error_returns_none(self):
        cli = _make_http_client()
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        result = cli.http_request("GET", "/", session=mock_session)
        assert result is None

    def test_invalid_schema_returns_none(self):
        cli = _make_http_client()
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.MissingSchema("no schema")
        result = cli.http_request("GET", "/", session=mock_session)
        assert result is None

    def test_generic_request_exception_returns_none(self):
        cli = _make_http_client()
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.RequestException("unexpected")
        result = cli.http_request("GET", "/", session=mock_session)
        assert result is None

    def test_custom_kwargs_override_defaults(self):
        cli = _make_http_client()
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(spec=requests.Response)
        cli.http_request("GET", "/", session=mock_session, timeout=5, verify=True)
        call_kwargs = mock_session.get.call_args[1]
        assert call_kwargs["timeout"] == 5
        assert call_kwargs["verify"] is True


class TestHTTPClientTestConnect:
    def test_test_connect_success(self):
        cli = _make_http_client()
        mock_resp = MagicMock(spec=requests.Response)
        with patch.object(cli, "http_request", return_value=mock_resp):
            result = cli.http_test_connect()
            assert result is True

    def test_test_connect_failure(self):
        cli = _make_http_client()
        with patch.object(cli, "http_request", return_value=None):
            result = cli.http_test_connect()
            assert result is False
