"""
Unit tests for Static URL Security Analyzer
"""

from app.services.url_analyzer import analyze_urls


def test_analyze_urls_ip_hostname():
    urls = ["http://198.51.100.25/login.php"]
    res = analyze_urls(urls)
    assert len(res) == 1
    assert res[0]["risk_level"] == "high_risk"
    assert any(f["rule"] == "ip_hostname" for f in res[0]["flags"])


def test_analyze_urls_punycode():
    urls = ["https://xn--pypal-4ve.com/signin"]
    res = analyze_urls(urls)
    assert res[0]["risk_level"] == "high_risk"
    assert any(f["rule"] == "punycode_homograph" for f in res[0]["flags"])


def test_analyze_urls_non_standard_port():
    urls = ["http://example.com:8080/portal"]
    res = analyze_urls(urls)
    assert res[0]["risk_level"] == "suspicious"
    assert any(f["rule"] == "non_standard_port" for f in res[0]["flags"])


def test_analyze_urls_clean():
    urls = ["https://www.google.com/search?q=security"]
    res = analyze_urls(urls)
    assert res[0]["risk_level"] == "safe"
    assert res[0]["flag_count"] == 0
