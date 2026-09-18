"""
Unit tests for MIME/RFC 822 Email Parser
"""

from app.services.email_parser import parse_email_bytes


def test_parse_email_bytes():
    raw_email = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Test Subject Line\r\n"
        b"Date: Fri, 19 Sep 2026 00:00:00 +0000\r\n"
        b"Message-ID: <msg-123@example.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Hello, this is a test email body."
    )

    res = parse_email_bytes(raw_email)
    assert res["headers"]["subject"] == "Test Subject Line"
    assert res["headers"]["from"] == "sender@example.com"
    assert "Hello, this is a test email body." in res["body"]["plain_text"]
    assert res["attachment_count"] == 0
