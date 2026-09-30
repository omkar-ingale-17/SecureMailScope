"""SecureMailScope — Unified Application Entrypoint.

Combines FastAPI passive network-forensics backend services, REST APIs,
and React SPA frontend delivery into a single unified entrypoint outside the backend folder.

Running this file:
    python app.py
starts both backend and frontend together on http://127.0.0.1:8000 and opens the browser.
"""

import os
import io
import sys
import threading
import time
import webbrowser
import subprocess
from pathlib import Path
from typing import Optional, List

# Ensure Prototype root directory is on Python module path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.models.schemas import (
    EvidenceRecord, SessionRecord, Finding, RiskPosture,
    OverviewMetrics, ReportRecord, SystemStatus
)
from backend.storage import store
from backend.forensics.risk_engine import RiskEngine
from backend.forensics.report_generator import ReportGenerator

# Frontend build directory
FRONTEND_DIST = (ROOT_DIR / "frontend" / "dist").resolve()

app = FastAPI(
    title="SecureMailScope Unified Application",
    description="Passive Network Email Forensics & Cryptographic Security Posture System",
    version="1.0.0-prototype",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json"
)

# Enable CORS for development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== SYSTEM & HEALTH ENDPOINTS ====================

@app.get("/api/health", tags=["Health"])
def get_health():
    return {
        "status": "ok",
        "app": "SecureMailScope",
        "mode": "PASSIVE_NETWORK_FORENSICS",
        "forensic_mode": "STRICT_PASSIVE_PCAP"
    }

@app.get("/api/overview", response_model=OverviewMetrics, tags=["Metrics"])
def get_overview():
    return store.get_overview_metrics()

# ==================== EVIDENCE MANAGEMENT ENDPOINTS ====================

@app.post("/api/evidence/upload", response_model=EvidenceRecord, tags=["Evidence"])
async def upload_evidence(
    file: UploadFile = File(...),
    auto_analyze: bool = Query(True, description="Whether to automatically run passive forensic analysis upon registration")
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    valid_exts = (".pcap", ".pcapng", ".cap")
    if not any(file.filename.lower().endswith(ext) for ext in valid_exts):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file extension. Only forensic capture files ({', '.join(valid_exts)}) are accepted."
        )

    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded capture file is empty.")

    try:
        evidence = store.register_evidence(file.filename, file_bytes)
        if auto_analyze:
            analyzed_evidence = store.analyze_evidence(evidence.id)
            return analyzed_evidence
        return evidence
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register evidence: {str(e)}")

@app.get("/api/evidence", response_model=List[EvidenceRecord], tags=["Evidence"])
def list_evidence():
    return list(store.evidences.values())

@app.get("/api/evidence/{evidence_id}", response_model=EvidenceRecord, tags=["Evidence"])
def get_evidence(evidence_id: str):
    if evidence_id not in store.evidences:
        raise HTTPException(status_code=404, detail="Evidence record not found.")
    return store.evidences[evidence_id]

@app.post("/api/evidence/{evidence_id}/analyze", response_model=EvidenceRecord, tags=["Evidence"])
def trigger_analysis(evidence_id: str):
    if evidence_id not in store.evidences:
        raise HTTPException(status_code=404, detail="Evidence record not found.")
    return store.analyze_evidence(evidence_id)

@app.delete("/api/evidence/{evidence_id}", tags=["Evidence"])
def delete_evidence(evidence_id: str):
    if evidence_id not in store.evidences:
        raise HTTPException(status_code=404, detail="Evidence record not found.")
    store.delete_evidence(evidence_id)
    return {"message": f"Evidence {evidence_id} successfully deleted."}

@app.post("/api/evidence/clear-all", tags=["Evidence"])
def clear_all_evidence():
    count = len(store.evidences)
    store.clear_all()
    return {"message": f"Cleared {count} evidence records and reset all telemetry."}

# ==================== SESSIONS ENDPOINTS ====================

@app.get("/api/sessions", response_model=List[SessionRecord], tags=["Sessions"])
def list_sessions(
    evidence_id: Optional[str] = None,
    protocol: Optional[str] = None,
    risk: Optional[str] = None,
    tls_version: Optional[str] = None,
    cert_status: Optional[str] = None,
    search: Optional[str] = None
):
    sessions = list(store.sessions.values())

    if evidence_id:
        sessions = [s for s in sessions if s.evidence_id == evidence_id]
    if protocol and protocol != "ALL":
        sessions = [s for s in sessions if s.protocol.upper() == protocol.upper()]
    if risk and risk != "ALL":
        sessions = [s for s in sessions if s.risk_level.upper() == risk.upper()]
    if tls_version and tls_version != "ALL":
        sessions = [s for s in sessions if tls_version.upper() in s.tls.tls_version.upper()]
    if cert_status and cert_status != "ALL":
        sessions = [s for s in sessions if s.certificate.certificate_status.upper() == cert_status.upper()]

    if search:
        q = search.lower()
        sessions = [
            s for s in sessions
            if q in s.session_id.lower()
            or q in s.protocol.lower()
            or q in s.network.src_ip.lower()
            or q in s.network.dst_ip.lower()
            or q in s.tls.cipher_suite.lower()
            or q in s.tls.tls_version.lower()
            or q in s.certificate.subject.lower()
        ]

    return sessions

@app.get("/api/sessions/{session_id}", response_model=SessionRecord, tags=["Sessions"])
def get_session(session_id: str):
    if session_id not in store.sessions:
        raise HTTPException(status_code=404, detail="Session record not found.")
    return store.sessions[session_id]

# ==================== FINDINGS ENDPOINTS ====================

@app.get("/api/findings", response_model=List[Finding], tags=["Findings"])
def list_findings(
    evidence_id: Optional[str] = None,
    severity: Optional[str] = None,
    protocol: Optional[str] = None,
    search: Optional[str] = None
):
    findings = list(store.findings.values())

    if evidence_id:
        findings = [f for f in findings if f.evidence_id == evidence_id]
    if severity and severity != "ALL":
        findings = [f for f in findings if f.severity.upper() == severity.upper()]
    if protocol and protocol != "ALL":
        findings = [f for f in findings if f.protocol.upper() == protocol.upper()]

    if search:
        q = search.lower()
        findings = [
            f for f in findings
            if q in f.id.lower()
            or q in f.rule_id.lower()
            or q in f.title.lower()
            or q in f.protocol.lower()
            or q in f.session_id.lower()
            or q in f.description.lower()
        ]

    # Order by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: sev_order.get(x.severity, 5))
    return findings

@app.get("/api/findings/{finding_id}", response_model=Finding, tags=["Findings"])
def get_finding(finding_id: str):
    if finding_id not in store.findings:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return store.findings[finding_id]

# ==================== RISK ANALYSIS ENDPOINTS ====================

@app.get("/api/risk-posture", response_model=RiskPosture, tags=["Risk"])
def get_risk_posture():
    return RiskEngine.calculate_posture(
        sessions=list(store.sessions.values()),
        findings=list(store.findings.values()),
        evidences=list(store.evidences.values())
    )

# ==================== REPORTS ENDPOINTS ====================

@app.get("/api/reports", response_model=List[ReportRecord], tags=["Reports"])
def list_reports():
    return list(store.reports.values())

@app.get("/api/reports/{report_id}/view", tags=["Reports"])
def view_report(report_id: str, format: str = Query("html", pattern="^(html|json)$")):
    if report_id not in store.reports:
        raise HTTPException(status_code=404, detail="Report not found.")
    rep = store.reports[report_id]
    ev = store.evidences.get(rep.evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Associated evidence missing.")

    ev_sessions = [s for s in store.sessions.values() if s.evidence_id == ev.id]
    ev_findings = [f for f in store.findings.values() if f.evidence_id == ev.id]

    if format == "json":
        json_content = ReportGenerator.generate_json(ev, ev_sessions, ev_findings)
        return Response(content=json_content, media_type="application/json")
    else:
        html_content = ReportGenerator.generate_html(ev, ev_sessions, ev_findings)
        return HTMLResponse(content=html_content)

@app.get("/api/reports/{report_id}/download", tags=["Reports"])
def download_report(report_id: str, format: str = Query("pdf", pattern="^(pdf|html|json)$")):
    if report_id not in store.reports:
        raise HTTPException(status_code=404, detail="Report not found.")
    rep = store.reports[report_id]
    ev = store.evidences.get(rep.evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Associated evidence missing.")

    ev_sessions = [s for s in store.sessions.values() if s.evidence_id == ev.id]
    ev_findings = [f for f in store.findings.values() if f.evidence_id == ev.id]

    if format == "json":
        json_content = ReportGenerator.generate_json(ev, ev_sessions, ev_findings)
        return Response(
            content=json_content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="SecureMailScope_{ev.id}_report.json"'}
        )
    elif format == "html":
        html_content = ReportGenerator.generate_html(ev, ev_sessions, ev_findings)
        return Response(
            content=html_content,
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="SecureMailScope_{ev.id}_report.html"'}
        )
    else:  # pdf
        pdf_bytes = ReportGenerator.generate_pdf(ev, ev_sessions, ev_findings)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="SecureMailScope_{ev.id}_report.pdf"'}
        )

# ==================== SETTINGS & STATUS ====================

@app.get("/api/settings/status", response_model=SystemStatus, tags=["Settings"])
def get_system_status():
    return SystemStatus()

# ==================== SAMPLE DATA SEEDING (DISABLED) ====================
@app.post("/api/sample-data/seed", tags=["Internal"])
def seed_sample_pcaps():
    raise HTTPException(
        status_code=403,
        detail="Dummy data seeding is disabled. SecureMailScope strictly analyzes real PCAP or PCAPNG captures uploaded by the investigator."
    )

# ==================== FRONTEND STATIC & SPA ROUTING ====================
# Mount assets directory from frontend/dist
assets_dir = FRONTEND_DIST / "assets"
if assets_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

@app.get("/{full_path:path}", tags=["Frontend UI"])
async def serve_frontend(full_path: str):
    """
    Unified frontend delivery:
    Serves exact static files from frontend/dist if they exist,
    otherwise falls back to index.html for React SPA client-side routing.
    """
    # Guard against accidental API routing captures
    if full_path.startswith("api"):
        raise HTTPException(status_code=404, detail="API endpoint not found")

    target_file = FRONTEND_DIST / full_path
    if target_file.exists() and target_file.is_file():
        return FileResponse(str(target_file))

    index_html = FRONTEND_DIST / "index.html"
    if index_html.exists():
        return FileResponse(str(index_html))

    return HTMLResponse(
        content="""
        <html>
            <head><title>SecureMailScope — Build Missing</title></head>
            <body style="background:#080D1A;color:#00F2FE;font-family:sans-serif;padding:40px;text-align:center;">
                <h2>SecureMailScope — Frontend Distribution Not Found</h2>
                <p style="color:#94A3B8;">Please run <code>npm run build</code> inside the <code>frontend</code> directory.</p>
            </body>
        </html>
        """,
        status_code=503
    )

# ==================== SINGLE ENTRYPOINT RUNNER ====================
def _auto_open_browser(url: str):
    """Wait for server to bind port, then open user's default browser."""
    time.sleep(1.2)
    try:
        webbrowser.open(url)
    except Exception:
        pass

if __name__ == "__main__":
    import uvicorn

    server_url = "http://127.0.0.1:8000"

    print("\n" + "=" * 70)
    print("  SecureMailScope - Passive Network Email Forensics System")
    print("  Unified Single-Entrypoint Server")
    print(f"  * Frontend UI:  {server_url}/")
    print(f"  * Backend API:  {server_url}/api")
    print(f"  * API Docs:     {server_url}/api/docs")
    print("=" * 70 + "\n")

    # Launch browser automatically in a separate background thread
    threading.Thread(target=_auto_open_browser, args=(server_url,), daemon=True).start()

    # Start FastAPI server hosting BOTH backend API and frontend React SPA
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
