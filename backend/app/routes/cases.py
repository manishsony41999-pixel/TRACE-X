"""
TRACE-X Case Management Routes
Endpoints for querying, exporting, and verifying forensic investigation cases.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models import Case, EmailRecord, Investigation, Indicator

router = APIRouter(prefix="/cases", tags=["Cases"])


@router.get("")
def list_cases(
    limit: int = 50,
    offset: int = 0,
    risk_level: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    List all investigated cases with pagination and optional risk level filter.
    """
    query = db.query(Case)
    if risk_level:
        query = query.filter(Case.risk_level == risk_level.upper())
    
    total_count = query.count()
    cases = query.order_by(Case.created_at.desc()).offset(offset).limit(limit).all()

    case_items = []
    for c in cases:
        case_items.append({
            "case_id": c.case_id,
            "status": c.status,
            "risk_level": c.risk_level,
            "threat_score": c.threat_score,
            "source": c.source,
            "subject": c.email.subject if c.email else "No Subject",
            "sender": c.email.sender if c.email else "Unknown",
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "indicator_count": len(c.indicators) if c.indicators else 0
        })

    return {
        "success": True,
        "data": {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "cases": case_items
        },
        "error": None
    }


@router.get("/{case_id}")
def get_case_details(case_id: str, db: Session = Depends(get_db)):
    """
    Retrieve full forensic case dossier including headers, authentication, IOCs, and threat score.
    """
    case = db.query(Case).filter(Case.case_id == case_id.upper()).first()
    if not case:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "success": False,
                "data": None,
                "error": {"message": f"Case '{case_id}' not found."}
            }
        )

    investigation_data = case.investigation.result if (case.investigation and case.investigation.result) else {}

    return {
        "success": True,
        "data": {
            "case_id": case.case_id,
            "status": case.status,
            "risk_level": case.risk_level,
            "threat_score": case.threat_score,
            "source": case.source,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "updated_at": case.updated_at.isoformat() if case.updated_at else None,
            "email": investigation_data.get("email"),
            "header_analysis": investigation_data.get("header_analysis"),
            "authentication": investigation_data.get("authentication"),
            "iocs": investigation_data.get("iocs"),
            "url_analysis": investigation_data.get("url_analysis"),
            "intelligence": investigation_data.get("intelligence"),
            "nlp_analysis": investigation_data.get("nlp_analysis"),
            "threat_score_details": investigation_data.get("threat_score")
        },
        "error": None
    }


@router.get("/{case_id}/nlp")
def get_case_nlp_analysis(case_id: str, db: Session = Depends(get_db)):
    """Retrieve Natural Language Processing & Machine Learning content analysis for a case."""
    case = db.query(Case).filter(Case.case_id == case_id.upper()).first()
    if not case or not case.investigation or not case.investigation.result:
        raise HTTPException(status_code=404, detail="Case or NLP data not found")
    
    return {
        "success": True,
        "data": case.investigation.result.get("nlp_analysis"),
        "error": None
    }


@router.get("/{case_id}/email")
def get_case_email(case_id: str, db: Session = Depends(get_db)):
    """Retrieve raw email and MIME metadata for a case."""
    case = db.query(Case).filter(Case.case_id == case_id.upper()).first()
    if not case or not case.investigation or not case.investigation.result:
        raise HTTPException(status_code=404, detail="Case or email data not found")
    
    return {
        "success": True,
        "data": case.investigation.result.get("email"),
        "error": None
    }


@router.get("/{case_id}/headers")
def get_case_headers(case_id: str, db: Session = Depends(get_db)):
    """Retrieve header analysis and routing hops for a case."""
    case = db.query(Case).filter(Case.case_id == case_id.upper()).first()
    if not case or not case.investigation or not case.investigation.result:
        raise HTTPException(status_code=404, detail="Case or header data not found")
    
    return {
        "success": True,
        "data": case.investigation.result.get("header_analysis"),
        "error": None
    }


@router.get("/{case_id}/authentication")
def get_case_authentication(case_id: str, db: Session = Depends(get_db)):
    """Retrieve SPF, DKIM, and DMARC verification results for a case."""
    case = db.query(Case).filter(Case.case_id == case_id.upper()).first()
    if not case or not case.investigation or not case.investigation.result:
        raise HTTPException(status_code=404, detail="Case or authentication data not found")
    
    return {
        "success": True,
        "data": case.investigation.result.get("authentication"),
        "error": None
    }


@router.get("/{case_id}/indicators")
def get_case_indicators(case_id: str, db: Session = Depends(get_db)):
    """Retrieve extracted IOCs (IPs, domains, hashes, URLs) for a case."""
    case = db.query(Case).filter(Case.case_id == case_id.upper()).first()
    if not case or not case.investigation or not case.investigation.result:
        raise HTTPException(status_code=404, detail="Case or indicator data not found")
    
    return {
        "success": True,
        "data": case.investigation.result.get("iocs"),
        "error": None
    }


@router.get("/{case_id}/score")
def get_case_score(case_id: str, db: Session = Depends(get_db)):
    """Retrieve explainable threat score and itemized evidence for a case."""
    case = db.query(Case).filter(Case.case_id == case_id.upper()).first()
    if not case or not case.investigation or not case.investigation.result:
        raise HTTPException(status_code=404, detail="Case or scoring data not found")
    
    return {
        "success": True,
        "data": case.investigation.result.get("threat_score"),
        "error": None
    }


@router.get("/{case_id}/timeline")
def get_case_timeline(case_id: str, db: Session = Depends(get_db)):
    """Retrieve chronological forensic events and hop timeline."""
    case = db.query(Case).filter(Case.case_id == case_id.upper()).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    result = case.investigation.result if (case.investigation and case.investigation.result) else {}
    hops = result.get("header_analysis", {}).get("hops", [])

    timeline = [
        {
            "step": "Email Ingestion",
            "timestamp": case.created_at.isoformat() if case.created_at else None,
            "details": f"Email ingested from {case.source}."
        }
    ]

    for h in hops:
        timeline.append({
            "step": f"Routing Hop #{h.get('hop_number')}",
            "timestamp": None,
            "details": f"Relayed from '{h.get('from_host')}' to '{h.get('by_host')}' (IP: {h.get('public_ip') or 'N/A'})."
        })

    if case.investigation:
        timeline.append({
            "step": "Investigation Complete",
            "timestamp": case.investigation.completed_at.isoformat() if case.investigation.completed_at else None,
            "details": f"Investigation completed with risk level {case.risk_level} (Score: {case.threat_score}/100)."
        })

    return {
        "success": True,
        "data": {
            "case_id": case.case_id,
            "events": timeline
        },
        "error": None
    }


@router.get("/{case_id}/graph")
def get_case_threat_graph(case_id: str, db: Session = Depends(get_db)):
    """
    Retrieve forensic relationship network graph (Nodes, Edges, Indicators, and Cross-Case Correlations).
    """
    from app.services.graph_service import build_threat_graph

    case = db.query(Case).filter(Case.case_id == case_id.upper()).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    result = case.investigation.result if (case.investigation and case.investigation.result) else {}
    graph_data = build_threat_graph(case.case_id, result, db)

    return {
        "success": True,
        "data": graph_data,
        "error": None
    }


@router.get("/{case_id}/integrity")
def get_case_integrity_ledger(case_id: str, db: Session = Depends(get_db)):
    """
    Retrieve cryptographic SHA-256 evidence integrity seal and Chain of Custody status.
    """
    from app.services.report_generator import compute_evidence_integrity

    case = db.query(Case).filter(Case.case_id == case_id.upper()).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    result = case.investigation.result if (case.investigation and case.investigation.result) else {}
    integrity_data = compute_evidence_integrity(case, result)

    return {
        "success": True,
        "data": integrity_data,
        "error": None
    }


@router.get("/{case_id}/export/json")
def export_case_json_dossier(case_id: str, db: Session = Depends(get_db)):
    """
    Download complete machine-readable forensic dossier formatted in standard JSON.
    """
    from app.services.report_generator import generate_forensic_json_report

    try:
        json_report = generate_forensic_json_report(case_id, db)
        return {
            "success": True,
            "data": json_report,
            "error": None
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/{case_id}/export/pdf")
def export_case_pdf_report(case_id: str, db: Session = Depends(get_db)):
    """
    Download publication-grade executive PDF forensic report with cryptographic seal.
    """
    from app.services.report_generator import generate_forensic_pdf_report

    try:
        pdf_bytes = generate_forensic_pdf_report(case_id, db)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=TRACE-X-Forensic-Report-{case_id}.pdf"
            }
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
