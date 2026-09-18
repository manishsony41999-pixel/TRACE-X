"""
TRACE-X Static URL Security Analyzer
Inspects embedded URLs for IP hostnames, homograph attacks, non-standard ports, payload patterns, and phishing paths.
"""

import re
from typing import Dict, Any, List
from urllib.parse import urlparse


def analyze_urls(urls: List[str]) -> List[Dict[str, Any]]:
    """
    Statically inspects URLs without performing active navigation.
    """
    results: List[Dict[str, Any]] = []

    ip_host_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    suspicious_keywords = ["login", "verify", "signin", "account", "update", "secure", "banking", "wallet", "password", "auth", "confirm", "invoice"]
    suspicious_tlds = [".xyz", ".top", ".club", ".work", ".click", ".buzz", ".cam", ".rest", ".tk", ".ml", ".ga", ".cf"]

    for raw_url in urls:
        flags: List[Dict[str, Any]] = []
        risk_level = "safe"

        try:
            parsed = urlparse(raw_url)
            hostname = parsed.hostname or ""
            port = parsed.port
            path = parsed.path.lower()

            # 1. IP Address as Hostname
            if re.match(ip_host_regex, hostname):
                flags.append({
                    "rule": "ip_hostname",
                    "severity": "high",
                    "message": f"URL uses raw IP address '{hostname}' instead of a registered domain name."
                })
                risk_level = "high_risk"

            # 2. Homograph / Punycode Attacks
            if hostname.startswith("xn--"):
                flags.append({
                    "rule": "punycode_homograph",
                    "severity": "high",
                    "message": "Domain uses Punycode (IDN homograph) encoding to masquerade as a legitimate brand."
                })
                risk_level = "high_risk"

            # 3. Non-standard ports
            if port and port not in [80, 443]:
                flags.append({
                    "rule": "non_standard_port",
                    "severity": "medium",
                    "message": f"URL directs to non-standard service port {port}."
                })
                if risk_level != "high_risk":
                    risk_level = "suspicious"

            # 4. Suspicious TLDs
            for tld in suspicious_tlds:
                if hostname.endswith(tld):
                    flags.append({
                        "rule": "suspicious_tld",
                        "severity": "medium",
                        "message": f"Domain registered on high-abuse TLD '{tld}'."
                    })
                    if risk_level != "high_risk":
                        risk_level = "suspicious"
                    break

            # 5. Phishing Keywords in Path / Query
            matched_keywords = [kw for kw in suspicious_keywords if kw in path]
            if len(matched_keywords) >= 2:
                flags.append({
                    "rule": "credential_harvesting_path",
                    "severity": "high",
                    "message": f"URL path contains multiple credential harvesting patterns: {', '.join(matched_keywords)}."
                })
                risk_level = "high_risk"
            elif len(matched_keywords) == 1:
                flags.append({
                    "rule": "sensitive_keyword_path",
                    "severity": "low",
                    "message": f"URL path references sensitive keyword '{matched_keywords[0]}'."
                })
                if risk_level == "safe":
                    risk_level = "suspicious"

            # 6. Excessive Subdomains
            subdomain_parts = hostname.split(".")
            if len(subdomain_parts) >= 5:
                flags.append({
                    "rule": "excessive_subdomains",
                    "severity": "medium",
                    "message": f"Domain contains {len(subdomain_parts)} nested subdomains."
                })
                if risk_level == "safe":
                    risk_level = "suspicious"

            results.append({
                "url": raw_url,
                "hostname": hostname,
                "scheme": parsed.scheme,
                "port": port,
                "risk_level": risk_level,
                "flag_count": len(flags),
                "flags": flags
            })

        except Exception as exc:
            results.append({
                "url": raw_url,
                "hostname": "",
                "scheme": "",
                "port": None,
                "risk_level": "suspicious",
                "flag_count": 1,
                "flags": [{"rule": "malformed_url", "severity": "low", "message": str(exc)}]
            })

    return results
