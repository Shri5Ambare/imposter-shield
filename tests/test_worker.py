"""Worker utility unit tests — no network, no ML stack required.

Tests the _fetch_image security controls: SSRF rejection, oversized
Content-Length, and disallowed content-type. All network calls are mocked.

These tests are skipped automatically if Celery is not installed.
"""
import os

os.environ.setdefault("ISHLD_DATABASE_URL", "sqlite:///./test_worker_tmp.db")
os.environ.setdefault("ISHLD_SECRET_KEY", "test-secret-key-for-worker-tests")

import pytest

# Skip the entire module if Celery (or any other worker dep) isn't installed.
tasks = pytest.importorskip(
    "imposter_shield.worker.tasks",
    reason="worker dependencies (celery/redis) not installed",
)
_fetch_image = tasks._fetch_image


def test_fetch_image_rejects_private_url(tmp_path):
    """SSRF guard: localhost resolves to a blocked address → returns None."""
    result = _fetch_image("http://127.0.0.1/image.jpg", str(tmp_path))
    assert result is None


def test_fetch_image_rejects_loopback_hostname(tmp_path):
    """SSRF guard: 'localhost' hostname → returns None."""
    result = _fetch_image("http://localhost/image.jpg", str(tmp_path))
    assert result is None


def test_fetch_image_rejects_large_content_length(tmp_path, monkeypatch):
    """Download guard: declared Content-Length > cap → returns None before streaming."""
    from unittest.mock import MagicMock, patch
    from imposter_shield import config

    monkeypatch.setattr(config.settings, "allow_private_network_urls", True)

    mock_resp = MagicMock()
    mock_resp.headers = {
        "content-type": "image/jpeg",
        "content-length": str(30 * 1024 * 1024),  # 30 MB > 25 MB cap
    }
    mock_resp.raise_for_status = MagicMock()

    with patch("imposter_shield.worker.tasks.requests.get", return_value=mock_resp):
        result = _fetch_image("https://example.com/big.jpg", str(tmp_path))
    assert result is None


def test_fetch_image_rejects_wrong_content_type(tmp_path, monkeypatch):
    """Content-type allowlist: text/html response → returns None."""
    from unittest.mock import MagicMock, patch
    from imposter_shield import config

    monkeypatch.setattr(config.settings, "allow_private_network_urls", True)

    mock_resp = MagicMock()
    mock_resp.headers = {"content-type": "text/html; charset=utf-8", "content-length": "1000"}
    mock_resp.raise_for_status = MagicMock()

    with patch("imposter_shield.worker.tasks.requests.get", return_value=mock_resp):
        result = _fetch_image("https://example.com/page.html", str(tmp_path))
    assert result is None


def test_fetch_image_rejects_non_http_scheme(tmp_path):
    """SSRF guard: file:// scheme → returns None."""
    result = _fetch_image("file:///etc/passwd", str(tmp_path))
    assert result is None
