from typing import List, Dict, Any
from ..models.schemas import RiskPosture, ContributingFactor, SessionRecord, Finding, EvidenceRecord

class RiskEngine:
    @staticmethod
    def calculate_posture(
        sessions: List[SessionRecord],
        findings: List[Finding],
        evidences: List[EvidenceRecord]
    ) -> RiskPosture:
        """
        Calculates explainable aggregate risk posture across all analyzed evidence.
        Never fabricates scores; if no sessions exist, score is 0.
        """
        if not sessions:
            return RiskPosture(
                overall_score=0,
                severity="SECURE",
                contributing_factors=[],
                risk_distribution={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SECURE": 0},
                risk_by_protocol={"SMTP": 0, "IMAP": 0, "POP3": 0},
                risk_by_evidence=[]
            )

        # Factor buckets
        factors_map: Dict[str, Dict[str, Any]] = {
            "Cleartext Email Transmission": {"points": 0, "severity": "CRITICAL", "count": 0, "details": "Unencrypted traffic observed without TLS"},
            "Deprecated TLS Protocol (v1.0 / SSLv3)": {"points": 0, "severity": "CRITICAL", "count": 0, "details": "Negotiation of deprecated, exploitable protocol versions"},
            "Weak / Prohibited Cipher Suite": {"points": 0, "severity": "HIGH", "count": 0, "details": "Vulnerable ciphers such as 3DES, RC4, or NULL"},
            "X.509 Certificate Expiration / Key Issues": {"points": 0, "severity": "HIGH", "count": 0, "details": "Expired certificates or sub-2048-bit RSA keys"},
            "Absence of Perfect Forward Secrecy": {"points": 0, "severity": "MEDIUM", "count": 0, "details": "Static key exchange vulnerable to retroactive decryption"},
            "Legacy CBC / Weak Digest Algorithm": {"points": 0, "severity": "LOW", "count": 0, "details": "SHA-1 signatures or CBC mode padding vulnerabilities"},
        }

        risk_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SECURE": 0}
        risk_by_proto = {"SMTP": 0, "IMAP": 0, "POP3": 0}

        for s in sessions:
            risk_dist[s.risk_level] = risk_dist.get(s.risk_level, 0) + 1
            if s.protocol in risk_by_proto:
                if s.risk_level in ("CRITICAL", "HIGH", "MEDIUM"):
                    risk_by_proto[s.protocol] += 1

        for f in findings:
            r_id = f.rule_id
            if "CLEARTEXT" in r_id:
                bucket = factors_map["Cleartext Email Transmission"]
                bucket["points"] = min(35, bucket["points"] + 15)
                bucket["count"] += 1
            elif "DEPRECATED-TLS" in r_id:
                bucket = factors_map["Deprecated TLS Protocol (v1.0 / SSLv3)"]
                bucket["points"] = min(30, bucket["points"] + 15)
                bucket["count"] += 1
            elif "WEAK-CIPHER" in r_id:
                bucket = factors_map["Weak / Prohibited Cipher Suite"]
                bucket["points"] = min(25, bucket["points"] + 12)
                bucket["count"] += 1
            elif "EXPIRED" in r_id or "WEAK-KEY" in r_id or "NOT-YET-VALID" in r_id:
                bucket = factors_map["X.509 Certificate Expiration / Key Issues"]
                bucket["points"] = min(20, bucket["points"] + 10)
                bucket["count"] += 1
            elif "NO-PFS" in r_id:
                bucket = factors_map["Absence of Perfect Forward Secrecy"]
                bucket["points"] = min(15, bucket["points"] + 5)
                bucket["count"] += 1
            elif "CBC" in r_id or "WEAK-SIG" in r_id or "SELF-SIGNED" in r_id:
                bucket = factors_map["Legacy CBC / Weak Digest Algorithm"]
                bucket["points"] = min(10, bucket["points"] + 4)
                bucket["count"] += 1

        contributing: List[ContributingFactor] = []
        raw_score = 0
        for name, data in factors_map.items():
            if data["count"] > 0:
                contributing.append(ContributingFactor(
                    factor=name,
                    points=data["points"],
                    severity=data["severity"],
                    details=f"{data['count']} session violation(s) - {data['details']}",
                    count=data["count"]
                ))
                raw_score += data["points"]

        overall_score = min(100, raw_score)

        # Redefined Risk Categories:
        # Low risk: 0 to 20
        # Medium risk: 21 to 40
        # High risk: 41 to 60
        # Critical: above 60
        if overall_score > 60:
            severity = "CRITICAL"
        elif overall_score >= 41:
            severity = "HIGH"
        elif overall_score >= 21:
            severity = "MEDIUM"
        elif overall_score > 0:
            severity = "LOW"
        else:
            severity = "SECURE"

        # Risk by evidence
        risk_by_ev = []
        for ev in evidences:
            ev_sessions = [s for s in sessions if s.evidence_id == ev.id]
            ev_findings = [f for f in findings if f.evidence_id == ev.id]
            
            score = ev.risk_score if (hasattr(ev, 'risk_score') and ev.risk_score > 0) else max([s.risk_score for s in ev_sessions], default=0)
            if score > 60:
                highest_sev = "CRITICAL"
            elif score >= 41:
                highest_sev = "HIGH"
            elif score >= 21:
                highest_sev = "MEDIUM"
            elif score > 0:
                highest_sev = "LOW"
            else:
                highest_sev = "SECURE"

            risk_by_ev.append({
                "evidence_id": ev.id,
                "filename": ev.filename,
                "score": score,
                "severity": highest_sev,
                "session_count": len(ev_sessions),
                "finding_count": len(ev_findings)
            })

        return RiskPosture(
            overall_score=overall_score,
            severity=severity,
            contributing_factors=contributing,
            risk_distribution=risk_dist,
            risk_by_protocol=risk_by_proto,
            risk_by_evidence=risk_by_ev
        )
