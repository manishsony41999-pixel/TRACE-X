"""
TRACE-X SPF / DKIM / DMARC Authentication Engine
Parses Authentication-Results and DKIM-Signature headers and performs live DNS TXT lookups.
"""

import re
from typing import Dict, Any, List, Optional
import dns.resolver


def query_dns_txt(domain: str, timeout: float = 2.0) -> List[str]:
    """Queries live DNS TXT records for a domain with short timeout."""
    if not domain:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "TXT")
        records = []
        for rdata in answers:
            for txt_string in rdata.strings:
                records.append(txt_string.decode("utf-8", errors="ignore"))
        return records
    except Exception:
        return []


def analyze_authentication(
    sender_domain: str,
    auth_headers: List[str],
    dkim_signatures: List[str]
) -> Dict[str, Any]:
    """
    Evaluates SPF, DKIM, and DMARC status from headers and live DNS records.
    """
    spf_status = "none"
    dkim_status = "none"
    dmarc_status = "none"
    auth_details: List[str] = []

    # 1. Parse Authentication-Results headers
    for auth_hdr in auth_headers:
        auth_details.append(auth_hdr.strip())

        # SPF result
        spf_match = re.search(r"spf=([a-zA-Z]+)", auth_hdr, re.IGNORECASE)
        if spf_match:
            spf_status = spf_match.group(1).lower()

        # DKIM result
        dkim_match = re.search(r"dkim=([a-zA-Z]+)", auth_hdr, re.IGNORECASE)
        if dkim_match:
            dkim_status = dkim_match.group(1).lower()

        # DMARC result
        dmarc_match = re.search(r"dmarc=([a-zA-Z]+)", auth_hdr, re.IGNORECASE)
        if dmarc_match:
            dmarc_status = dmarc_match.group(1).lower()

    # If DKIM signature present but no header check, mark signed
    if dkim_status == "none" and len(dkim_signatures) > 0:
        dkim_status = "signed"

    # 2. Live DNS Verification
    live_spf_record = None
    live_dmarc_record = None

    if sender_domain:
        # Check SPF TXT on domain
        domain_txts = query_dns_txt(sender_domain)
        for txt in domain_txts:
            if txt.startswith("v=spf1"):
                live_spf_record = txt
                break

        # Check DMARC TXT on _dmarc.<domain>
        dmarc_txts = query_dns_txt(f"_dmarc.{sender_domain}")
        for txt in dmarc_txts:
            if txt.startswith("v=DMARC1"):
                live_dmarc_record = txt
                break

    return {
        "spf": {
            "status": spf_status,
            "live_dns_record": live_spf_record,
            "has_dns_policy": bool(live_spf_record)
        },
        "dkim": {
            "status": dkim_status,
            "signature_count": len(dkim_signatures),
            "is_signed": len(dkim_signatures) > 0
        },
        "dmarc": {
            "status": dmarc_status,
            "live_dns_record": live_dmarc_record,
            "has_dns_policy": bool(live_dmarc_record)
        },
        "raw_authentication_headers": auth_details
    }
