"""
TRACE-X Central Investigation Pipeline
Unified forensic pipeline executed for both on-demand .eml uploads and automated Gmail investigations.
Broadcasts real-time stage progress over WebSocket.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import Case, EmailRecord, Investigation, Indicator
from app.services.email_parser import parse_email_bytes
from app.services.header_analyzer import analyze_headers
from app.services.authentication import analyze_authentication
from app.services.ioc_extractor import extract_iocs
from app.services.url_analyzer import analyze_urls
from app.services.intelligence import gather_threat_intelligence
from app.services.nlp_analyzer import analyze_nlp_content
from app.services.threat_score import calculate_threat_score
from app.services.broadcaster import broadcaster


def run_investigation_pipeline(
    raw_email_bytes: bytes,
    case_id: str,
    source: str = "eml_upload",
    gmail_message_id: Optional[str] = None,
    filename: Optional[str] = "email.eml",
    db_session: Optional[Session] = None
) -> Dict[str, Any]:
    """
    Unified forensic pipeline:
    1. Parse email
    2. Header analysis & hops
    3. Authentication (SPF, DKIM, DMARC)
    4. IOC Extraction
    5. URL Risk Analysis
    6. Threat Intelligence
    7. NLP Content Analysis
    8. Explainable Threat Scoring
    9. Database Persistence & WebSocket Broadcast
    """
    should_close_db = False
    if db_session is None:
        db_session = SessionLocal()
        should_close_db = True

    try:
        # Broadcast initiation
        broadcaster.broadcast_sync("stage_update", {
            "case_id": case_id,
            "stage": "Parsing RFC 822 email & MIME structure...",
            "step": 1,
            "total_steps": 8
        })

        # 1. Parse email bytes
        parsed_email = parse_email_bytes(raw_email_bytes)

        # 2. Header analysis
        broadcaster.broadcast_sync("stage_update", {
            "case_id": case_id,
            "stage": "Analyzing sender spoofing and routing hops...",
            "step": 2,
            "total_steps": 8
        })
        header_analysis = analyze_headers(
            headers=parsed_email["headers"],
            received_hops=parsed_email["received_hops"]
        )

        # 3. Authentication checks
        broadcaster.broadcast_sync("stage_update", {
            "case_id": case_id,
            "stage": "Verifying SPF, DKIM & DMARC DNS policies...",
            "step": 3,
            "total_steps": 8
        })
        auth_analysis = analyze_authentication(
            sender_domain=header_analysis["sender"]["domain"],
            auth_headers=parsed_email["authentication_headers"],
            dkim_signatures=parsed_email["dkim_signatures"]
        )

        # 4. Extract IOCs
        broadcaster.broadcast_sync("stage_update", {
            "case_id": case_id,
            "stage": "Extracting and deduplicating IOCs...",
            "step": 4,
            "total_steps": 8
        })
        iocs = extract_iocs(parsed_email, header_analysis)

        # 5. URL analysis
        broadcaster.broadcast_sync("stage_update", {
            "case_id": case_id,
            "stage": "Inspecting embedded URLs for phishing patterns...",
            "step": 5,
            "total_steps": 8
        })
        url_analysis = analyze_urls(iocs["urls"])

        # 6. Gather Threat Intelligence
        broadcaster.broadcast_sync("stage_update", {
            "case_id": case_id,
            "stage": "Gathering live DNS, RDAP & GeoIP intelligence...",
            "step": 6,
            "total_steps": 8
        })
        intelligence = gather_threat_intelligence(iocs)

        # 7. Machine Learning / NLP Content Analysis
        broadcaster.broadcast_sync("stage_update", {
            "case_id": case_id,
            "stage": "Analyzing language intent, urgency & credential lures...",
            "step": 7,
            "total_steps": 8
        })
        nlp_analysis = analyze_nlp_content(
            subject=parsed_email.get("headers", {}).get("subject", ""),
            body_text=parsed_email.get("body", {}).get("plain_text", ""),
            html_content=parsed_email.get("body", {}).get("html", "")
        )

        # 8. Threat Scoring
        broadcaster.broadcast_sync("stage_update", {
            "case_id": case_id,
            "stage": "Calculating explainable risk score & evidence...",
            "step": 8,
            "total_steps": 8
        })
        threat_score = calculate_threat_score(
            parsed_email=parsed_email,
            header_analysis=header_analysis,
            auth_analysis=auth_analysis,
            url_analysis=url_analysis,
            intelligence=intelligence,
            nlp_analysis=nlp_analysis
        )

        # Complete Investigation Result Object
        investigation_result = {
            "email": parsed_email,
            "header_analysis": header_analysis,
            "authentication": auth_analysis,
            "iocs": iocs,
            "url_analysis": url_analysis,
            "intelligence": intelligence,
            "nlp_analysis": nlp_analysis,
            "threat_score": threat_score
        }

        # Persist or Update Case in Database
        existing_case = db_session.query(Case).filter(Case.case_id == case_id).first()
        if not existing_case:
            new_case = Case(
                case_id=case_id,
                status="completed",
                risk_level=threat_score["risk_level"],
                threat_score=threat_score["score"],
                source=source
            )
            db_session.add(new_case)
            db_session.flush()

            email_record = EmailRecord(
                case_id=case_id,
                gmail_message_id=gmail_message_id,
                sender=header_analysis.get("sender", {}).get("address"),
                recipients=parsed_email.get("headers", {}).get("to"),
                subject=parsed_email.get("headers", {}).get("subject"),
                received_at=parsed_email.get("headers", {}).get("date"),
                raw_data={"filename": filename, "size_bytes": len(raw_email_bytes)}
            )
            db_session.add(email_record)

            investigation_record = Investigation(
                case_id=case_id,
                status="completed",
                result=investigation_result
            )
            db_session.add(investigation_record)
        else:
            existing_case.status = "completed"
            existing_case.risk_level = threat_score["risk_level"]
            existing_case.threat_score = threat_score["score"]
            if existing_case.investigation:
                existing_case.investigation.status = "completed"
                existing_case.investigation.result = investigation_result
                existing_case.investigation.completed_at = datetime.now(timezone.utc)

        # Persist indicators
        for em in iocs.get("emails", []):
            db_session.add(Indicator(case_id=case_id, type="email", value=em, risk="suspicious" if em in [header_analysis["reply_to"]["address"], header_analysis["return_path"]["address"]] else "safe"))
        for ip in iocs.get("ips", []):
            db_session.add(Indicator(case_id=case_id, type="ip", value=ip, risk="suspicious" if ip == header_analysis.get("originating_ip") else "safe"))
        for d in iocs.get("domains", []):
            db_session.add(Indicator(case_id=case_id, type="domain", value=d, risk="suspicious"))
        for u in iocs.get("urls", []):
            db_session.add(Indicator(case_id=case_id, type="url", value=u, risk="high_risk" if any(ua["url"] == u and ua["risk_level"] == "high_risk" for ua in url_analysis) else "suspicious"))
        for h in iocs.get("hashes", []):
            db_session.add(Indicator(case_id=case_id, type="hash", value=h, risk="high_risk"))

        db_session.commit()

        # Broadcast case completed event
        broadcaster.broadcast_sync("case_completed", {
            "case_id": case_id,
            "threat_score": threat_score["score"],
            "risk_level": threat_score["risk_level"],
            "subject": parsed_email.get("headers", {}).get("subject"),
            "sender": header_analysis.get("sender", {}).get("address"),
            "source": source
        })

        return {
            "case_id": case_id,
            "filename": filename,
            "size_bytes": len(raw_email_bytes),
            "status": "completed",
            "threat_score": threat_score,
            "email": parsed_email,
            "header_analysis": header_analysis,
            "authentication": auth_analysis,
            "iocs": iocs,
            "url_analysis": url_analysis,
            "intelligence": intelligence,
            "nlp_analysis": nlp_analysis
        }
    except Exception as exc:
        db_session.rollback()
        raise exc
    finally:
        if should_close_db:
            db_session.close()
