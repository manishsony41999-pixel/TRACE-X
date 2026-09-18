"""
TRACE-X — Email Threat Investigation & Forensic Intelligence Platform
Main Application Entrypoint
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import init_db
from app.routes import emails, cases, gmail, ws

# Initialize database schema
init_db()

# Initialize FastAPI application
app = FastAPI(
    title="TRACE-X Backend",
    description="TRACE-X Email Threat Investigation & Forensic Intelligence Platform API",
    version="1.0.0"
)

# Configure Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(emails.router, prefix="/api")
app.include_router(cases.router, prefix="/api")
app.include_router(gmail.router, prefix="/api")
app.include_router(ws.router, prefix="/api")


@app.get("/")
def root():
    """Root endpoint: Basic status and welcome message."""
    return {
        "success": True,
        "data": {
            "message": "Welcome to TRACE-X Forensic Intelligence Platform API",
            "version": "1.0.0",
            "docs": "/docs"
        },
        "error": None
    }


@app.get("/api/health")
def health_check():
    """Health check endpoint: Verifies that the API service is running."""
    return {
        "success": True,
        "data": {
            "status": "healthy",
            "service": "TRACE-X Backend",
            "version": "1.0.0"
        },
        "error": None
    }
