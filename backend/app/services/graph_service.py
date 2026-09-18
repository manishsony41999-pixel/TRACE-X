"""
TRACE-X Threat Graph & Relationship Correlation Service
Constructs node-link forensic graphs connecting Cases, Senders, Domains, IPs, Routing Hops, URLs, and File Hashes.
Discovers cross-case indicator correlation across historical investigations.
Optional Neo4j synchronization with clean fallback.
"""

import os
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from urllib.parse import urlparse
from app.models import Case, Indicator, EmailRecord


def build_threat_graph(
    case_id: str,
    investigation_result: Dict[str, Any],
    db: Optional[Session] = None
) -> Dict[str, Any]:
    """
    Constructs a comprehensive forensic threat graph for a given case.
    Returns nodes, edges, summary stats, and correlated cases.
    """
    nodes_map: Dict[str, Dict[str, Any]] = {}
    edges_list: List[Dict[str, Any]] = []

    def add_node(node_id: str, label: str, node_type: str, risk: str = "safe", details: Optional[Dict[str, Any]] = None):
        if node_id not in nodes_map:
            nodes_map[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "risk": risk,
                "details": details or {}
            }

    def add_edge(source: str, target: str, relationship: str, label: Optional[str] = None):
        if source == target:
            return
        edge_key = f"{source}->{target}:{relationship}"
        for existing in edges_list:
            if existing.get("_key") == edge_key:
                return
        edges_list.append({
            "_key": edge_key,
            "source": source,
            "target": target,
            "relationship": relationship,
            "label": label or relationship.replace("_", " ").title()
        })

    # 1. Root Case Node
    threat_score_data = investigation_result.get("threat_score") or {}
    risk_level = threat_score_data.get("risk_level", "LOW")
    score = threat_score_data.get("score", 0)
    
    case_node_id = f"case:{case_id}"
    add_node(
        node_id=case_node_id,
        label=f"Case: {case_id}",
        node_type="case",
        risk=risk_level.lower(),
        details={
            "case_id": case_id,
            "score": score,
            "risk_level": risk_level,
            "subject": investigation_result.get("email", {}).get("headers", {}).get("subject", "No Subject")
        }
    )

    # 2. Sender and Sender Domain
    header_analysis = investigation_result.get("header_analysis") or {}
    sender = header_analysis.get("sender") or {}
    sender_addr = sender.get("address")
    sender_domain = sender.get("domain")

    if sender_addr:
        sender_node_id = f"sender:{sender_addr.lower()}"
        is_spoofed = header_analysis.get("spoofing_indicators", {}).get("is_display_name_spoofed", False)
        add_node(
            node_id=sender_node_id,
            label=sender_addr,
            node_type="sender",
            risk="high_risk" if is_spoofed else ("suspicious" if risk_level in ["HIGH", "CRITICAL"] else "safe"),
            details={"address": sender_addr, "name": sender.get("display_name")}
        )
        add_edge(case_node_id, sender_node_id, "SENT_BY", "Sent By")

        if sender_domain:
            domain_node_id = f"domain:{sender_domain.lower()}"
            auth = investigation_result.get("authentication") or {}
            spf_status = auth.get("spf", {}).get("status", "neutral")
            dkim_status = auth.get("dkim", {}).get("status", "neutral")
            domain_risk = "high_risk" if (spf_status == "fail" or dkim_status == "fail") else "safe"
            
            add_node(
                node_id=domain_node_id,
                label=sender_domain,
                node_type="domain",
                risk=domain_risk,
                details={
                    "domain": sender_domain,
                    "spf": spf_status,
                    "dkim": dkim_status,
                    "dmarc": auth.get("dmarc", {}).get("status", "none")
                }
            )
            add_edge(sender_node_id, domain_node_id, "BELONGS_TO", "Belongs To Domain")

    # 3. Originating IP
    originating_ip = header_analysis.get("originating_ip")
    if originating_ip:
        ip_node_id = f"ip:{originating_ip}"
        ip_intel = investigation_result.get("intelligence", {}).get("ips", {}).get(originating_ip, {})
        geo = ip_intel.get("geolocation", {})
        add_node(
            node_id=ip_node_id,
            label=originating_ip,
            node_type="ip",
            risk="suspicious" if not ip_intel.get("is_private") else "safe",
            details={
                "ip": originating_ip,
                "country": geo.get("country", "Unknown"),
                "isp": geo.get("isp", "Unknown"),
                "asn": geo.get("asn", "Unknown")
            }
        )
        add_edge(case_node_id, ip_node_id, "ORIGINATED_AT", "Originated From IP")

    # 4. Routing Hops Chain
    prev_hop_id = f"ip:{originating_ip}" if originating_ip else case_node_id
    for hop in header_analysis.get("hops", []):
        hop_num = hop.get("hop_number")
        hop_ip = hop.get("public_ip")
        if hop_ip and hop_ip != originating_ip:
            hop_node_id = f"hop_ip:{hop_ip}"
            add_node(
                node_id=hop_node_id,
                label=f"Hop #{hop_num}: {hop_ip}",
                node_type="hop",
                risk="safe",
                details={"hop": hop_num, "from_host": hop.get("from_host"), "by_host": hop.get("by_host")}
            )
            add_edge(prev_hop_id, hop_node_id, "ROUTED_THROUGH", f"Hop #{hop_num}")
            prev_hop_id = hop_node_id

    # 5. URLs and Link Domains
    url_analysis_list = investigation_result.get("url_analysis") or []
    for ua in url_analysis_list:
        raw_url = ua.get("url")
        if not raw_url:
            continue
        url_risk = ua.get("risk_level", "safe")
        url_node_id = f"url:{raw_url}"
        
        display_label = raw_url
        if len(display_label) > 35:
            display_label = display_label[:32] + "..."

        add_node(
            node_id=url_node_id,
            label=display_label,
            node_type="url",
            risk=url_risk,
            details={
                "full_url": raw_url,
                "risk_level": url_risk,
                "flags": [f.get("message") for f in ua.get("flags", [])]
            }
        )
        add_edge(case_node_id, url_node_id, "CONTAINS_URL", "Contains Link")

        try:
            parsed = urlparse(raw_url)
            hostname = parsed.hostname
            if hostname:
                target_domain_id = f"domain:{hostname.lower()}"
                add_node(
                    node_id=target_domain_id,
                    label=hostname,
                    node_type="domain",
                    risk="high_risk" if url_risk == "high_risk" else "suspicious",
                    details={"hostname": hostname, "extracted_from_url": raw_url}
                )
                add_edge(url_node_id, target_domain_id, "HOSTED_ON", "Hosted On")
        except Exception:
            pass

    # 6. Attachment File Hashes
    iocs = investigation_result.get("iocs") or {}
    for h in iocs.get("hashes", []):
        hash_node_id = f"hash:{h}"
        add_node(
            node_id=hash_node_id,
            label=f"SHA256: {h[:10]}...",
            node_type="hash",
            risk="high_risk",
            details={"sha256": h}
        )
        add_edge(case_node_id, hash_node_id, "ATTACHMENT_HASH", "Attachment Hash")

    # 7. Cross-Case Correlation (Historical Database Match)
    correlated_cases = []
    if db is not None:
        try:
            all_indicators = []
            if sender_addr:
                all_indicators.append(sender_addr)
            if originating_ip:
                all_indicators.append(originating_ip)
            for d in iocs.get("domains", []):
                all_indicators.append(d)
            for u in iocs.get("urls", []):
                all_indicators.append(u)

            if all_indicators:
                matched_rows = db.query(Indicator).filter(
                    Indicator.case_id != case_id,
                    Indicator.value.in_(all_indicators)
                ).all()

                for match in matched_rows:
                    other_case_id = match.case_id
                    other_case = db.query(Case).filter(Case.case_id == other_case_id).first()
                    if other_case:
                        other_node_id = f"case:{other_case_id}"
                        add_node(
                            node_id=other_node_id,
                            label=f"Correlated Case: {other_case_id}",
                            node_type="case",
                            risk=other_case.risk_level.lower() if other_case.risk_level else "medium",
                            details={
                                "case_id": other_case_id,
                                "threat_score": other_case.threat_score,
                                "risk_level": other_case.risk_level,
                                "matched_indicator": match.value,
                                "indicator_type": match.type
                            }
                        )
                        add_edge(
                            case_node_id,
                            other_node_id,
                            "SHARES_INDICATOR",
                            f"Shares {match.type}: {match.value[:20]}"
                        )
                        if other_case_id not in [c["case_id"] for c in correlated_cases]:
                            correlated_cases.append({
                                "case_id": other_case_id,
                                "threat_score": other_case.threat_score,
                                "risk_level": other_case.risk_level,
                                "shared_indicator": match.value,
                                "indicator_type": match.type
                            })
        except Exception:
            pass

    # 8. Check Optional Neo4j Sync
    neo4j_uri = os.environ.get("NEO4J_URI", "")
    neo4j_status = "not_configured" if not neo4j_uri else "configured"

    clean_edges = []
    for e in edges_list:
        clean_edges.append({
            "source": e["source"],
            "target": e["target"],
            "relationship": e["relationship"],
            "label": e["label"]
        })

    return {
        "case_id": case_id,
        "nodes": list(nodes_map.values()),
        "edges": clean_edges,
        "stats": {
            "node_count": len(nodes_map),
            "edge_count": len(clean_edges),
            "correlated_cases_count": len(correlated_cases)
        },
        "correlated_cases": correlated_cases,
        "neo4j_status": neo4j_status
    }
