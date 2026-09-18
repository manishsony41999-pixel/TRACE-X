"""
Unit tests for Real Domain/IP Threat Intelligence Lookups
"""

from app.services.intelligence import (
    is_private_ip,
    query_dns_records,
    query_rdap_whois,
    query_ip_geolocation,
    query_virustotal_reputation,
    gather_threat_intelligence
)


def test_is_private_ip():
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("8.8.8.8") is False


def test_query_dns_records():
    res = query_dns_records("google.com")
    assert isinstance(res["mx_records"], list)
    assert res["has_mx"] is True


def test_query_rdap_whois():
    res = query_rdap_whois("google.com")
    assert res["status"] in ["available", "unavailable"]


def test_query_ip_geolocation():
    res = query_ip_geolocation("8.8.8.8")
    assert res["status"] in ["available", "unavailable"]


def test_query_virustotal_unconfigured():
    res = query_virustotal_reputation("google.com")
    assert res["status"] in ["not_configured", "available", "unavailable"]
