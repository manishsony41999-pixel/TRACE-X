"""
Unit tests for IOC Extractor
"""

from app.services.ioc_extractor import extract_iocs


def test_extract_iocs():
    parsed_email = {
        "body": {
            "plain_text": "Please visit http://phishing-site.xyz/login or contact support@phishing-site.xyz. Server IP: 198.51.100.44",
            "html": ""
        },
        "attachments": [
            {"filename": "malware.exe", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
        ]
    }
    header_analysis = {
        "sender": {"address": "attacker@evil.com", "domain": "evil.com"},
        "reply_to": {"address": "drop@evil.com", "domain": "evil.com"},
        "return_path": {"address": "bounce@evil.com", "domain": "evil.com"},
        "originating_ip": "198.51.100.99",
        "hops": []
    }

    iocs = extract_iocs(parsed_email, header_analysis)

    assert "198.51.100.44" in iocs["ips"]
    assert "198.51.100.99" in iocs["ips"]
    assert "http://phishing-site.xyz/login" in iocs["urls"]
    assert "phishing-site.xyz" in iocs["domains"]
    assert "evil.com" in iocs["domains"]
    assert "attacker@evil.com" in iocs["emails"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs["hashes"]
    assert iocs["counts"]["total"] >= 7
