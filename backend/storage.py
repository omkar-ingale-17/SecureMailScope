import os
import json
import hashlib
import datetime
from typing import Dict, List, Optional, Any
from .models.schemas import (
    EvidenceRecord, SessionRecord, Finding, RiskPosture,
    OverviewMetrics, ReportRecord, SystemStatus
)
from .forensics.pcap_parser import PCAPParser
from .forensics.rules_engine import RulesEngine
from .forensics.risk_engine import RiskEngine
from .forensics.report_generator import ReportGenerator

class ForensicStore:
    def __init__(self, data_dir: Optional[str] = None):
        if data_dir is None or data_dir == "storage_data":
            self.data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "storage_data"))
        else:
            self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self.evidence_files_dir = os.path.join(self.data_dir, "pcaps")
        os.makedirs(self.evidence_files_dir, exist_ok=True)
        self.state_file = os.path.join(self.data_dir, "forensic_state.json")

        self.evidences: Dict[str, EvidenceRecord] = {}
        self.sessions: Dict[str, SessionRecord] = {}
        self.findings: Dict[str, Finding] = {}
        self.reports: Dict[str, ReportRecord] = {}
        self.file_cache: Dict[str, bytes] = {}

        self._load_state()

    def register_evidence(self, filename: str, file_bytes: bytes) -> EvidenceRecord:
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        ev_id = f"EV-{sha256_hash[:8].upper()}"
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        size_bytes = len(file_bytes)
        if size_bytes < 1024:
            size_display = f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            size_display = f"{size_bytes / 1024:.1f} KB"
        else:
            size_display = f"{size_bytes / (1024 * 1024):.2f} MB"

        rec = EvidenceRecord(
            id=ev_id,
            filename=filename,
            file_size_bytes=size_bytes,
            file_size_display=size_display,
            sha256=sha256_hash,
            uploaded_at=now_str,
            analysis_status="UPLOADED",
            session_count=0,
            finding_count=0,
            risk_score=0,
            risk_level="SECURE",
            protocols_found=[]
        )

        self.evidences[ev_id] = rec
        self.file_cache[ev_id] = file_bytes

        # Save to disk
        filepath = os.path.join(self.evidence_files_dir, f"{ev_id}_{filename}")
        with open(filepath, "wb") as f:
            f.write(file_bytes)

        self._save_state()
        return rec

    def analyze_evidence(self, evidence_id: str) -> EvidenceRecord:
        if evidence_id not in self.evidences:
            raise KeyError(f"Evidence ID {evidence_id} not found.")

        ev = self.evidences[evidence_id]
        ev.analysis_status = "PROCESSING"

        # Clear any prior sessions/findings for this evidence
        self.sessions = {sid: s for sid, s in self.sessions.items() if s.evidence_id != evidence_id}
        self.findings = {fid: f for fid, f in self.findings.items() if f.evidence_id != evidence_id}
        self.reports = {rid: r for rid, r in self.reports.items() if r.evidence_id != evidence_id}

        file_bytes = self.file_cache.get(evidence_id)
        if not file_bytes:
            filepath = os.path.join(self.evidence_files_dir, f"{evidence_id}_{ev.filename}")
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    file_bytes = f.read()
                    self.file_cache[evidence_id] = file_bytes
            else:
                ev.analysis_status = "FAILED"
                ev.error_message = "PCAP file data not found on disk."
                return ev

        try:
            # 1. PCAP Parsing & Session Reassembly
            extracted_sessions = PCAPParser.parse_file(file_bytes)

            ev_findings: List[Finding] = []
            ev_sessions: List[SessionRecord] = []
            protocols = set()

            f_counter = len(self.findings) + 1

            for s_idx, s_dict in enumerate(extracted_sessions, 1):
                proto = s_dict["protocol"]
                protocols.add(proto)
                s_dict["session_id"] = f"{ev.id.replace('EV-', '')}-SESS-{s_idx:03d}"

                # 2. Security Rules & Risk Engine
                findings, chain, risk_score, risk_level = RulesEngine.evaluate_session(
                    session=s_dict,
                    evidence_id=ev.id,
                    evidence_filename=ev.filename,
                    finding_counter_start=f_counter
                )
                f_counter += len(findings)

                sess_rec = SessionRecord(
                    session_id=s_dict["session_id"],
                    evidence_id=ev.id,
                    evidence_filename=ev.filename,
                    protocol=proto,
                    network=s_dict["network"],
                    starttls_detected=s_dict["starttls_detected"],
                    starttls_status=s_dict["starttls_status"],
                    tls=s_dict["tls"],
                    certificate=s_dict["certificate"],
                    risk_level=risk_level,
                    risk_score=risk_score,
                    findings=findings,
                    evidence_chain=chain
                )

                self.sessions[sess_rec.session_id] = sess_rec
                ev_sessions.append(sess_rec)

                for f in findings:
                    self.findings[f.id] = f
                    ev_findings.append(f)

            # Update evidence stats
            ev.analysis_status = "ANALYZED"
            ev.session_count = len(ev_sessions)
            ev.finding_count = len(ev_findings)
            ev.protocols_found = sorted(list(protocols))

            # Calculate evidence risk posture using deterministic RiskEngine
            ev_posture = RiskEngine.calculate_posture(
                sessions=ev_sessions,
                findings=ev_findings,
                evidences=[ev]
            )
            ev.risk_score = ev_posture.overall_score
            ev.risk_level = ev_posture.severity

            # 3. Create Report Record
            rep_id = f"REP-{ev.id}"
            now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            self.reports[rep_id] = ReportRecord(
                id=rep_id,
                evidence_id=ev.id,
                evidence_filename=ev.filename,
                generated_at=now_str,
                formats=["JSON", "HTML", "PDF"],
                risk_score=ev.risk_score,
                risk_level=ev.risk_level,
                session_count=ev.session_count,
                finding_count=ev.finding_count
            )

            self._save_state()
            return ev

        except Exception as e:
            ev.analysis_status = "FAILED"
            ev.error_message = str(e)
            self._save_state()
            return ev

    def delete_evidence(self, evidence_id: str) -> bool:
        if evidence_id not in self.evidences:
            return False
        ev = self.evidences.pop(evidence_id)
        self.sessions = {sid: s for sid, s in self.sessions.items() if s.evidence_id != evidence_id}
        self.findings = {fid: f for fid, f in self.findings.items() if f.evidence_id != evidence_id}
        self.reports = {rid: r for rid, r in self.reports.items() if r.evidence_id != evidence_id}
        self.file_cache.pop(evidence_id, None)

        filepath = os.path.join(self.evidence_files_dir, f"{evidence_id}_{ev.filename}")
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except OSError:
                pass

        self._save_state()
        return True

    def clear_all(self) -> None:
        self.evidences.clear()
        self.sessions.clear()
        self.findings.clear()
        self.reports.clear()
        self.file_cache.clear()
        if os.path.exists(self.evidence_files_dir):
            for f in os.listdir(self.evidence_files_dir):
                fp = os.path.join(self.evidence_files_dir, f)
                if os.path.isfile(fp):
                    try:
                        os.remove(fp)
                    except OSError:
                        pass
        if os.path.exists(self.state_file):
            try:
                os.remove(self.state_file)
            except OSError:
                pass

    def _save_state(self) -> None:
        try:
            state = {
                "evidences": {k: v.model_dump() for k, v in self.evidences.items()},
                "sessions": {k: v.model_dump() for k, v in self.sessions.items()},
                "findings": {k: v.model_dump() for k, v in self.findings.items()},
                "reports": {k: v.model_dump() for k, v in self.reports.items()},
            }
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        except Exception:
            pass

    def _load_state(self) -> None:
        if not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                state = json.load(f)
            self.evidences = {k: EvidenceRecord(**v) for k, v in state.get("evidences", {}).items()}
            self.sessions = {k: SessionRecord(**v) for k, v in state.get("sessions", {}).items()}
            self.findings = {k: Finding(**v) for k, v in state.get("findings", {}).items()}
            self.reports = {k: ReportRecord(**v) for k, v in state.get("reports", {}).items()}

            # Align loaded records to redefined risk categories
            # Low: 0-20, Medium: 21-40, High: 41-60, Critical: >60
            for sid, s in self.sessions.items():
                if s.risk_score > 60:
                    s.risk_level = "CRITICAL"
                elif s.risk_score >= 41:
                    s.risk_level = "HIGH"
                elif s.risk_score >= 21:
                    s.risk_level = "MEDIUM"
                elif s.risk_score > 0:
                    s.risk_level = "LOW"
                else:
                    s.risk_level = "SECURE"
                for node in s.evidence_chain:
                    if node.step == "RISK":
                        node.title = f"Risk Score: {s.risk_score}/100 ({s.risk_level})"
                        node.details = f"Explainable posture calculated as {s.risk_level}"
                        node.status = "critical" if s.risk_level in ("CRITICAL", "HIGH") else ("warning" if s.risk_level == "MEDIUM" else "secure")
                        if "severity" in node.technical_props:
                            node.technical_props["severity"] = s.risk_level

            for eid, ev in self.evidences.items():
                if ev.risk_score > 60:
                    ev.risk_level = "CRITICAL"
                elif ev.risk_score >= 41:
                    ev.risk_level = "HIGH"
                elif ev.risk_score >= 21:
                    ev.risk_level = "MEDIUM"
                elif ev.risk_score > 0:
                    ev.risk_level = "LOW"
                else:
                    ev.risk_level = "SECURE"

            for rid, rep in self.reports.items():
                if rep.risk_score > 60:
                    rep.risk_level = "CRITICAL"
                elif rep.risk_score >= 41:
                    rep.risk_level = "HIGH"
                elif rep.risk_score >= 21:
                    rep.risk_level = "MEDIUM"
                elif rep.risk_score > 0:
                    rep.risk_level = "LOW"
                else:
                    rep.risk_level = "SECURE"

            self._save_state()
        except Exception:
            pass

    def get_overview_metrics(self) -> OverviewMetrics:
        all_evidences = list(self.evidences.values())
        all_sessions = list(self.sessions.values())
        all_findings = list(self.findings.values())

        at_risk = sum(1 for s in all_sessions if s.risk_level in ("CRITICAL", "HIGH", "MEDIUM"))
        high_crit = sum(1 for f in all_findings if f.severity in ("CRITICAL", "HIGH"))

        # Risk distribution
        risk_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SECURE": 0}
        for s in all_sessions:
            risk_dist[s.risk_level] = risk_dist.get(s.risk_level, 0) + 1

        # Protocol distribution
        proto_dist = {"SMTP": 0, "IMAP": 0, "POP3": 0}
        for s in all_sessions:
            proto_dist[s.protocol] = proto_dist.get(s.protocol, 0) + 1

        # TLS distribution
        tls_dist = {"TLS 1.3": 0, "TLS 1.2": 0, "TLS 1.1": 0, "TLS 1.0": 0, "SSL 3.0": 0, "Cleartext (No TLS)": 0, "Unknown": 0}
        for s in all_sessions:
            ver = s.tls.tls_version
            if not s.tls.tls_detected:
                tls_dist["Cleartext (No TLS)"] += 1
            elif "TLS 1.3" in ver:
                tls_dist["TLS 1.3"] += 1
            elif "TLS 1.2" in ver:
                tls_dist["TLS 1.2"] += 1
            elif "TLS 1.1" in ver:
                tls_dist["TLS 1.1"] += 1
            elif "TLS 1.0" in ver:
                tls_dist["TLS 1.0"] += 1
            elif "SSL 3.0" in ver:
                tls_dist["SSL 3.0"] += 1
            else:
                tls_dist["Unknown"] += 1

        # Cert health distribution
        cert_dist = {"VALID": 0, "EXPIRED": 0, "NOT_YET_VALID": 0, "WEAK_KEY": 0, "WEAK_SIGNATURE": 0, "SELF_SIGNED": 0, "NOT OBSERVABLE": 0}
        for s in all_sessions:
            c_stat = s.certificate.certificate_status
            cert_dist[c_stat] = cert_dist.get(c_stat, 0) + 1

        # Sort recent findings (high/crit first, then recent)
        recent = sorted(all_findings, key=lambda f: (0 if f.severity == "CRITICAL" else (1 if f.severity == "HIGH" else 2)), reverse=False)[:10]

        return OverviewMetrics(
            total_evidence=len(all_evidences),
            total_sessions=len(all_sessions),
            at_risk_sessions=at_risk,
            high_critical_findings=high_crit,
            total_findings=len(all_findings),
            risk_distribution=risk_dist,
            protocol_distribution=proto_dist,
            tls_distribution=tls_dist,
            cert_health_distribution=cert_dist,
            recent_findings=recent
        )

store = ForensicStore()
