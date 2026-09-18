"""
TRACE-X Header Analyzer & Anomaly Detector
Inspects sender identity, spoofing indicators, reply-to / return-path mismatches, and reconstructs routing hops.
"""

import re
from email.utils import parseaddr
from typing import Dict, Any, List, Optional


def analyze_headers(headers: Dict[str, Any], received_hops: List[str]) -> Dict[str, Any]:
    """
    Analyzes email headers for spoofing, inconsistencies, and hop chains.
    """
    anomalies: List[Dict[str, Any]] = []

    # 1. Parse From header
    from_raw = headers.get("from", "")
    from_name, from_address = parseaddr(from_raw)
    from_domain = from_address.split("@")[-1].lower() if "@" in from_address else ""

    if not from_address:
        anomalies.append({
            "type": "missing_from_header",
            "message": "Email is missing a valid 'From' header."
        })

    # 2. Parse Reply-To header
    reply_to_raw = headers.get("reply-to", "")
    reply_to_name, reply_to_address = parseaddr(reply_to_raw)
    reply_to_domain = reply_to_address.split("@")[-1].lower() if "@" in reply_to_address else ""

    reply_to_mismatch = False
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        reply_to_mismatch = True
        anomalies.append({
            "type": "reply_to_domain_mismatch",
            "message": f"Reply-To domain '{reply_to_domain}' does not match From domain '{from_domain}'."
        })

    # 3. Parse Return-Path header
    return_path_raw = headers.get("return-path", "")
    _, return_path_address = parseaddr(return_path_raw)
    return_path_domain = return_path_address.split("@")[-1].lower() if "@" in return_path_address else ""

    return_path_mismatch = False
    if return_path_domain and from_domain and return_path_domain != from_domain:
        return_path_mismatch = True
        anomalies.append({
            "type": "return_path_domain_mismatch",
            "message": f"Return-Path domain '{return_path_domain}' does not match From domain '{from_domain}'."
        })

    # 4. Display Name Spoofing Detection
    is_display_name_spoofed = False
    if from_name:
        embedded_emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", from_name)
        if embedded_emails:
            for em in embedded_emails:
                if em.lower() != from_address.lower():
                    is_display_name_spoofed = True
                    anomalies.append({
                        "type": "display_name_spoofing",
                        "message": f"Display name contains address '{em}' masquerading as sender '{from_address}'."
                    })

    # 5. Check Message-ID
    if not headers.get("message-id"):
        anomalies.append({
            "type": "missing_message_id",
            "message": "Email is missing standard RFC 'Message-ID' header."
        })

    # 6. Parse Received Hops Chain (Chronological order: from oldest hop to newest)
    parsed_hops = []
    originating_ip = None

    # Received headers are stored top-to-bottom (newest first). Reverse for chronological trace.
    chronological_hops = list(reversed(received_hops))

    ip_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

    for idx, hop_str in enumerate(chronological_hops):
        from_match = re.search(r"from\s+([^\s]+)", hop_str, re.IGNORECASE)
        by_match = re.search(r"by\s+([^\s]+)", hop_str, re.IGNORECASE)
        ips = re.findall(ip_regex, hop_str)

        from_host = from_match.group(1) if from_match else "unknown"
        by_host = by_match.group(1) if by_match else "unknown"
        public_ip = None
        for ip in ips:
            # Check for non-loopback
            if not ip.startswith("127.") and ip != "0.0.0.0":
                public_ip = ip
                break

        is_tls = "using TLS" in hop_str or "with ESMTPS" in hop_str or "TLSv" in hop_str

        parsed_hops.append({
            "hop_number": idx + 1,
            "raw": hop_str.strip(),
            "from_host": from_host,
            "by_host": by_host,
            "public_ip": public_ip,
            "is_encrypted": is_tls
        })

        if idx == 0 and public_ip:
            originating_ip = public_ip

    return {
        "sender": {
            "display_name": from_name,
            "address": from_address,
            "domain": from_domain
        },
        "reply_to": {
            "display_name": reply_to_name,
            "address": reply_to_address,
            "domain": reply_to_domain
        },
        "return_path": {
            "address": return_path_address,
            "domain": return_path_domain
        },
        "spoofing_indicators": {
            "reply_to_mismatch": reply_to_mismatch,
            "return_path_mismatch": return_path_mismatch,
            "is_display_name_spoofed": is_display_name_spoofed
        },
        "anomalies": anomalies,
        "hops": parsed_hops,
        "hop_count": len(parsed_hops),
        "originating_ip": originating_ip
    }
