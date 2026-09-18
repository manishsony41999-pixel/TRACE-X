"""
TRACE-X Real Threat Intelligence Engine
Gathers live DNS records, RDAP WHOIS data, IP Geolocation / ASN, and optional VirusTotal reputation.
Cleanly falls back to 'not_configured' or 'unavailable' without fake mock data.
"""

import os
import httpx
import dns.resolver
from typing import Dict, Any, List, Optional
import ipaddress


def is_private_ip(ip: str) -> bool:
    """Checks if an IPv4 address belongs to a private / RFC 1918 range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except ValueError:
        return False


def query_dns_records(domain: str, timeout: float = 2.0) -> Dict[str, Any]:
    """Queries MX, NS, and A records for a domain."""
    dns_data: Dict[str, Any] = {
        "mx_records": [],
        "ns_records": [],
        "a_records": [],
        "has_mx": False
    }
    if not domain:
        return dns_data

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    # MX
    try:
        mx_ans = resolver.resolve(domain, "MX")
        dns_data["mx_records"] = [str(r.exchange).rstrip(".") for r in mx_ans]
        dns_data["has_mx"] = len(dns_data["mx_records"]) > 0
    except Exception:
        dns_data["has_mx"] = False

    # NS
    try:
        ns_ans = resolver.resolve(domain, "NS")
        dns_data["ns_records"] = [str(r.target).rstrip(".") for r in ns_ans]
    except Exception:
        pass

    # A
    try:
        a_ans = resolver.resolve(domain, "A")
        dns_data["a_records"] = [str(r.address) for r in a_ans]
    except Exception:
        pass

    return dns_data


def query_rdap_whois(domain: str, timeout: float = 2.5) -> Dict[str, Any]:
    """Queries RDAP open standard registry data (rdap.org)."""
    if not domain:
        return {"status": "unavailable", "registrar": None}
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"https://rdap.org/domain/{domain}")
            if resp.status_code == 200:
                data = resp.json()
                entities = data.get("entities", [])
                registrar_name = None
                for ent in entities:
                    roles = ent.get("roles", [])
                    if "registrar" in roles or "registrant" in roles:
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    registrar_name = item[3]
                                    break
                return {
                    "status": "available",
                    "registrar": registrar_name or data.get("handle", "Registered"),
                    "events": [e.get("eventAction") for e in data.get("events", [])]
                }
    except Exception:
        pass
    return {"status": "unavailable", "registrar": None}


def query_ip_geolocation(ip: str, timeout: float = 2.0) -> Dict[str, Any]:
    """Queries IP geolocation and ASN via open standard ip-api.com."""
    if not ip or is_private_ip(ip):
        return {"status": "private_network", "country": "Private/Internal", "asn": "N/A", "isp": "Local Network"}

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,as,org")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "status": "available",
                        "country": data.get("country"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "asn": data.get("as"),
                        "org": data.get("org")
                    }
    except Exception:
        pass
    return {"status": "unavailable", "country": "Unknown", "asn": "Unknown", "isp": "Unknown"}


def query_virustotal_reputation(indicator: str, timeout: float = 2.0) -> Dict[str, Any]:
    """Queries VirusTotal API if VIRUSTOTAL_API_KEY is configured."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"status": "not_configured", "malicious": 0, "suspicious": 0}

    try:
        with httpx.Client(timeout=timeout) as client:
            headers = {"x-apikey": api_key}
            resp = client.get(f"https://www.virustotal.com/api/v3/domains/{indicator}", headers=headers)
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "status": "available",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0)
                }
    except Exception:
        pass
    return {"status": "unavailable", "malicious": 0, "suspicious": 0}


def gather_threat_intelligence(iocs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Gathers live threat intelligence across extracted domains and IP addresses.
    """
    domain_intel: Dict[str, Any] = {}
    for domain in iocs.get("domains", [])[:5]:  # Limit top 5
        dns_res = query_dns_records(domain)
        rdap_res = query_rdap_whois(domain)
        vt_res = query_virustotal_reputation(domain)
        domain_intel[domain] = {
            "dns": dns_res,
            "rdap": rdap_res,
            "virustotal": vt_res
        }

    ip_intel: Dict[str, Any] = {}
    for ip in iocs.get("ips", [])[:5]:  # Limit top 5
        is_priv = is_private_ip(ip)
        geo_res = query_ip_geolocation(ip)
        ip_intel[ip] = {
            "is_private": is_priv,
            "geolocation": geo_res
        }

    return {
        "domains": domain_intel,
        "ips": ip_intel
    }
