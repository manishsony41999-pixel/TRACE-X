"""
TRACE-X Multi-Source IOC Extractor
Extracts and deduplicates IP addresses, domain names, URLs, email addresses, and SHA-256 hashes.
"""

import re
from typing import Dict, Any, List, Set
from urllib.parse import urlparse


def extract_iocs(parsed_email: Dict[str, Any], header_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Scans email headers, body parts, and attachments to extract all forensic IOCs.
    """
    raw_text = parsed_email.get("body", {}).get("plain_text", "")
    html_text = parsed_email.get("body", {}).get("html", "")
    full_content = f"{raw_text}\n{html_text}"

    # 1. Regex Patterns
    ip_regex = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    url_regex = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s\)\"\'\<\>]*"
    email_regex = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    domain_regex = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"

    found_ips: Set[str] = set()
    found_urls: Set[str] = set()
    found_emails: Set[str] = set()
    found_domains: Set[str] = set()
    found_hashes: Set[str] = set()

    # Extract IPs from body and routing hops
    for ip in re.findall(ip_regex, full_content):
        if not ip.startswith("127.") and ip != "0.0.0.0":
            found_ips.add(ip)

    if header_analysis.get("originating_ip"):
        found_ips.add(header_analysis["originating_ip"])

    for hop in header_analysis.get("hops", []):
        if hop.get("public_ip"):
            found_ips.add(hop["public_ip"])

    # Extract URLs
    for url in re.findall(url_regex, full_content):
        # Clean trailing punctuation
        clean_url = url.rstrip(".,;!?'\")>]} ")
        found_urls.add(clean_url)
        try:
            parsed = urlparse(clean_url)
            if parsed.hostname:
                found_domains.add(parsed.hostname.lower())
        except Exception:
            pass

    # Extract Emails
    for em in re.findall(email_regex, full_content):
        found_emails.add(em.lower())

    if header_analysis.get("sender", {}).get("address"):
        found_emails.add(header_analysis["sender"]["address"].lower())
    if header_analysis.get("reply_to", {}).get("address"):
        found_emails.add(header_analysis["reply_to"]["address"].lower())
    if header_analysis.get("return_path", {}).get("address"):
        found_emails.add(header_analysis["return_path"]["address"].lower())

    # Extract Sender Domains
    if header_analysis.get("sender", {}).get("domain"):
        found_domains.add(header_analysis["sender"]["domain"].lower())
    if header_analysis.get("reply_to", {}).get("domain"):
        found_domains.add(header_analysis["reply_to"]["domain"].lower())
    if header_analysis.get("return_path", {}).get("domain"):
        found_domains.add(header_analysis["return_path"]["domain"].lower())

    # Extract Hashes from Attachments
    for att in parsed_email.get("attachments", []):
        if att.get("sha256"):
            found_hashes.add(att["sha256"])

    return {
        "ips": sorted(list(found_ips)),
        "domains": sorted(list(found_domains)),
        "urls": sorted(list(found_urls)),
        "emails": sorted(list(found_emails)),
        "hashes": sorted(list(found_hashes)),
        "counts": {
            "ips": len(found_ips),
            "domains": len(found_domains),
            "urls": len(found_urls),
            "emails": len(found_emails),
            "hashes": len(found_hashes),
            "total": len(found_ips) + len(found_domains) + len(found_urls) + len(found_emails) + len(found_hashes)
        }
    }
