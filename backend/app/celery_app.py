"""
TRACE-X Celery Background Worker Configuration
Handles asynchronous email processing and pipeline execution.
"""

import os
from celery import Celery

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "tracex",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300
)


@celery_app.task(name="tasks.run_investigation")
def async_run_investigation(raw_email_bytes_hex: str, case_id: str, source: str = "eml_upload"):
    """
    Background Celery task to execute the central forensic pipeline.
    """
    from app.services.pipeline import run_investigation_pipeline
    raw_email_bytes = bytes.fromhex(raw_email_bytes_hex)
    return run_investigation_pipeline(raw_email_bytes, case_id, source)
