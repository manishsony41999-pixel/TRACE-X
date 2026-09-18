"""
TRACE-X Email Upload and Processing Routes
"""

import uuid
from fastapi import APIRouter, UploadFile, File, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.pipeline import run_investigation_pipeline

router = APIRouter(prefix="/emails", tags=["Emails"])

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


@router.post("/upload")
async def upload_eml_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Upload a real RFC 822 .eml file and run it through the forensic pipeline.
    """
    filename = file.filename or ""
    if not filename.lower().endswith(".eml"):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": "INVALID_FILE_TYPE",
                    "message": "Only .eml files are supported for email forensic investigation."
                }
            }
        )

    content = await file.read()
    file_size = len(content)

    if file_size == 0:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": "EMPTY_FILE",
                    "message": "The uploaded .eml file is empty (0 bytes)."
                }
            }
        )

    if file_size > MAX_FILE_SIZE:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": "FILE_TOO_LARGE",
                    "message": f"File size ({file_size} bytes) exceeds the maximum allowed limit of 10 MB."
                }
            }
        )

    case_id = f"TRX-{uuid.uuid4().hex[:8].upper()}"

    try:
        pipeline_result = run_investigation_pipeline(
            raw_email_bytes=content,
            case_id=case_id,
            source="eml_upload",
            filename=filename,
            db_session=db
        )
        return {
            "success": True,
            "data": pipeline_result,
            "error": None
        }
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": "PIPELINE_ERROR",
                    "message": str(exc)
                }
            }
        )
