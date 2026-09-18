"""
Unit tests for Header Analyzer & Spoofing Detection
"""

from app.services.header_analyzer import analyze_headers


def test_analyze_headers_clean():
    headers = {
        "from": "Security Alert <security@paypal.com>",
        "reply-to": "security@paypal.com",
        "return-path": "<security@paypal.com>",
        "message-id": "<12345@paypal.com>"
    }
    hops = [
        "from mail-1.paypal.com by mx.google.com with ESMTPS id 123 (using TLSv1.3)"
    ]

    res = analyze_headers(headers, hops)
    assert res["sender"]["address"] == "security@paypal.com"
    assert res["sender"]["domain"] == "paypal.com"
    assert res["spoofing_indicators"]["reply_to_mismatch"] is False
    assert res["spoofing_indicators"]["is_display_name_spoofed"] is False
    assert res["hop_count"] == 1


def test_analyze_headers_spoofed_mismatch():
    headers = {
        "from": "PayPal Support <billing@paypal.com>",
        "reply-to": "evil@stealer.com",
        "return-path": "<bounce@attacker.org>"
    }
    hops = [
        "from relay.attacker.org (198.51.100.25) by gateway.target.com"
    ]

    res = analyze_headers(headers, hops)
    assert res["spoofing_indicators"]["reply_to_mismatch"] is True
    assert res["spoofing_indicators"]["return_path_mismatch"] is True
    assert res["originating_ip"] == "198.51.100.25"
