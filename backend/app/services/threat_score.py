"""
TRACE-X Explainable Threat Scoring Engine
Calculates a rule-based forensic risk score (0 to 100) with itemized, weighted evidence.
"""

from typing import Dict, Any, List, Optional


def calculate_threat_score(
    parsed_email: Dict[str, Any],
    header_analysis: Dict[str, Any],
    auth_analysis: Dict[str, Any],
    url_analysis: List[Dict[str, Any]],
    intelligence: Dict[str, Any],
    nlp_analysis: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates evidence across all forensic dimensions to compute an explainable threat score.
    Returns:
    - score (0 to 100)
    - risk_level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    - itemized evidence list with individual points and categories
    """
    evidence: List[Dict[str, Any]] = []

    # =========================================================================
    # 1. Email Authentication Checks (SPF, DKIM, DMARC)
    # =========================================================================
    spf_status = auth_analysis.get("spf", {}).get("status", "")
    dkim_status = auth_analysis.get("dkim", {}).get("status", "")
    dmarc_status = auth_analysis.get("dmarc", {}).get("status", "")

    if dmarc_status == "fail":
        evidence.append({
            "category": "Authentication",
            "reason": "DMARC evaluation failed for sender domain",
            "points": 25,
            "severity": "high"
        })

    if spf_status in ["fail", "softfail"]:
        evidence.append({
            "category": "Authentication",
            "reason": f"SPF {spf_status.upper()}: sending server is not authorized by domain policy",
            "points": 15,
            "severity": "medium"
        })

    if dkim_status in ["fail", "neutral"]:
        evidence.append({
            "category": "Authentication",
            "reason": "DKIM cryptographic signature verification failed or was tampered with",
            "points": 15,
            "severity": "medium"
        })

    if spf_status == "none" and dkim_status == "none" and dmarc_status == "none":
        evidence.append({
            "category": "Authentication",
            "reason": "No email authentication records (SPF, DKIM, DMARC) are configured",
            "points": 10,
            "severity": "low"
        })

    # =========================================================================
    # 2. Header & Routing Anomalies
    # =========================================================================
    for anomaly in header_analysis.get("anomalies", []):
        atype = anomaly.get("type", "")
        msg = anomaly.get("message", "")

        if atype == "reply_to_domain_mismatch":
            evidence.append({
                "category": "Headers",
                "reason": msg,
                "points": 25,
                "severity": "high"
            })
        elif atype == "display_name_spoofing":
            evidence.append({
                "category": "Headers",
                "reason": msg,
                "points": 20,
                "severity": "high"
            })
        elif atype == "return_path_domain_mismatch":
            evidence.append({
                "category": "Headers",
                "reason": msg,
                "points": 10,
                "severity": "medium"
            })
        elif atype == "missing_from_header":
            evidence.append({
                "category": "Headers",
                "reason": msg,
                "points": 30,
                "severity": "high"
            })
        elif atype == "missing_message_id":
            evidence.append({
                "category": "Headers",
                "reason": msg,
                "points": 5,
                "severity": "low"
            })

    # =========================================================================
    # 3. Attachment Risks
    # =========================================================================
    for att in parsed_email.get("attachments", []):
        if att.get("is_suspicious_extension"):
            fname = att.get("filename", "unknown")
            ext = att.get("extension", "")
            evidence.append({
                "category": "Attachments",
                "reason": f"Dangerous executable/script attachment detected: '{fname}' ({ext})",
                "points": 35,
                "severity": "high"
            })

    # =========================================================================
    # 4. URL & Link Risks
    # =========================================================================
    for u in url_analysis:
        r_level = u.get("risk_level")
        url_text = u.get("url", "")
        
        if r_level == "high_risk":
            flag_msgs = [f.get("message") for f in u.get("flags", [])]
            evidence.append({
                "category": "Links",
                "reason": f"High-risk URL detected: '{url_text}' ({'; '.join(flag_msgs)})",
                "points": 30,
                "severity": "high"
            })
        elif r_level == "suspicious":
            evidence.append({
                "category": "Links",
                "reason": f"Suspicious URL pattern detected: '{url_text}'",
                "points": 15,
                "severity": "medium"
            })

    # =========================================================================
    # 5. External Threat Intelligence Findings
    # =========================================================================
    sender_domain = header_analysis.get("sender", {}).get("domain")
    if sender_domain and sender_domain in intelligence.get("domains", {}):
        domain_intel = intelligence["domains"][sender_domain]
        if not domain_intel.get("dns", {}).get("has_mx", True):
            evidence.append({
                "category": "Intelligence",
                "reason": f"Sender domain '{sender_domain}' has no MX records and cannot receive legitimate email",
                "points": 15,
                "severity": "medium"
            })
            
        # Check VirusTotal reputation if available
        vt_stats = domain_intel.get("virustotal", {})
        if vt_stats.get("status") == "available" and vt_stats.get("malicious", 0) > 0:
            evidence.append({
                "category": "Intelligence",
                "reason": f"VirusTotal flagged sender domain as malicious ({vt_stats['malicious']} engines)",
                "points": 30,
                "severity": "high"
            })

    # =========================================================================
    # 6. Natural Language Processing & Semantic Phishing Intent
    # =========================================================================
    if nlp_analysis:
        prob = nlp_analysis.get("phishing_probability", 0.0)
        intents = nlp_analysis.get("intents_detected", [])

        if prob >= 0.75:
            evidence.append({
                "category": "Content NLP",
                "reason": f"High-confidence phishing language detected ({int(prob * 100)}% NLP probability): {', '.join(intents)}",
                "points": 25,
                "severity": "high"
            })
        elif prob >= 0.45:
            evidence.append({
                "category": "Content NLP",
                "reason": f"Suspicious urgency / credential lures identified in email body ({int(prob * 100)}% NLP probability)",
                "points": 15,
                "severity": "medium"
            })

    # =========================================================================
    # 7. Calculate Final Composite Score & Risk Classification
    # =========================================================================
    raw_points = sum(e["points"] for e in evidence)
    final_score = min(100, raw_points)

    if final_score >= 80:
        risk_level = "CRITICAL"
    elif final_score >= 55:
        risk_level = "HIGH"
    elif final_score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Human-readable summary for the analyst
    if final_score == 0:
        summary = "No suspicious threat indicators or forensic anomalies were detected in this email."
    elif risk_level == "CRITICAL":
        summary = "CRITICAL THREAT: Multiple strong indicators of malicious activity detected (e.g. payload attachments, direct spoofing, and failed authentication)."
    elif risk_level == "HIGH":
        summary = "HIGH RISK: Strong indicators of email spoofing, deceptive links, or authentication failures detected."
    elif risk_level == "MEDIUM":
        summary = "MEDIUM RISK: Notable anomalies detected (such as missing authentication or domain divergences). Manual analyst review recommended."
    else:
        summary = "LOW RISK: Minor non-critical anomalies detected with low likelihood of active malicious intent."

    return {
        "score": final_score,
        "risk_level": risk_level,
        "total_evidence_points": raw_points,
        "evidence_count": len(evidence),
        "evidence": evidence,
        "summary": summary
    }
