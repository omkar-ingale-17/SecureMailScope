import json
import datetime
import io
from collections import defaultdict
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from ..models.schemas import EvidenceRecord, SessionRecord, Finding


# ─── Helper: aggregate findings by rule ─────────────────────────────
def _aggregate_by_rule(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Group findings by rule_id. Returns sorted list (by occurrence count desc)."""
    rule_map: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        if f.rule_id not in rule_map:
            rule_map[f.rule_id] = {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "occurrences": 0,
                "affected_session_ids": set(),
                "recommendation": f.recommendation,
            }
        rule_map[f.rule_id]["occurrences"] += 1
        rule_map[f.rule_id]["affected_session_ids"].add(f.session_id)

    result = []
    for rk, rv in rule_map.items():
        rv["affected_sessions"] = len(rv["affected_session_ids"])
        del rv["affected_session_ids"]
        result.append(rv)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    result.sort(key=lambda x: (sev_order.get(x["severity"], 5), -x["occurrences"]))
    return result


# ─── Helper: derive key observations ─────────────────────────────────
def _key_observations(aggregated: List[Dict[str, Any]]) -> List[str]:
    """Return 3-5 high-level observation strings from aggregated data."""
    obs = []
    for r in aggregated[:6]:
        obs.append(f"{r['title']} ({r['occurrences']} occurrence{'s' if r['occurrences'] != 1 else ''}, {r['affected_sessions']} session{'s' if r['affected_sessions'] != 1 else ''})")
    return obs[:5]


# ─── Helper: priority actions ─────────────────────────────────────────
def _priority_actions(aggregated: List[Dict[str, Any]]) -> List[str]:
    """Return unique priority actions derived from rules."""
    seen = set()
    actions = []
    for r in aggregated:
        rec = r["recommendation"]
        # Use first sentence as action
        action = rec.split(".")[0].strip()
        if action and action not in seen:
            seen.add(action)
            actions.append(action)
        if len(actions) >= 6:
            break
    return actions


class ReportGenerator:
    # ─────────────────────────────────────────────────────────────────
    # JSON
    # ─────────────────────────────────────────────────────────────────
    @staticmethod
    def generate_json(evidence: EvidenceRecord, sessions: List[SessionRecord], findings: List[Finding]) -> str:
        aggregated = _aggregate_by_rule(findings)
        key_obs = _key_observations(aggregated)
        prio_acts = _priority_actions(aggregated)
        
        sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev_count[f.severity] = sev_count.get(f.severity, 0) + 1
        affected_sess = len({f.session_id for f in findings})

        crit_recs = list({r["recommendation"] for r in aggregated if r["severity"] == "CRITICAL"})
        high_recs = list({r["recommendation"] for r in aggregated if r["severity"] == "HIGH"})
        med_recs = list({r["recommendation"] for r in aggregated if r["severity"] == "MEDIUM"})

        data = {
            "application": "SecureMailScope",
            "module": "Passive Email Forensics Report",
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "evidence": evidence.model_dump() if hasattr(evidence, "model_dump") else evidence.dict(),
            "executive_summary": {
                "risk_score": evidence.risk_score,
                "risk_level": evidence.risk_level,
                "total_sessions": len(sessions),
                "total_findings": len(findings),
                "affected_sessions": affected_sess,
                "severity_counts": sev_count,
                "key_observations": key_obs,
                "priority_actions": prio_acts
            },
            "findings_aggregated_by_rule": aggregated,
            "risk_breakdown": {
                "overall_score": evidence.risk_score,
                "severity_level": evidence.risk_level,
                "severity_distribution": sev_count,
                "risk_scale": {
                    "LOW": "0 to 20",
                    "MEDIUM": "21 to 40",
                    "HIGH": "41 to 60",
                    "CRITICAL": "above 60"
                },
                "risk_methodology": "Deterministic calculation bounded by rule violation weights (Low: 0-20, Medium: 21-40, High: 41-60, Critical: >60)."
            },
            "remediation_plan": {
                "priority_1_critical": crit_recs,
                "priority_2_high": high_recs,
                "priority_3_medium": med_recs,
                "verification_notes": "Apply in staging environment, capture traffic, and re-analyze."
            },
            "verification_workflow": [
                {"step": 1, "action": "Current Assessment", "detail": "Review baseline report and identify all critical findings"},
                {"step": 2, "action": "Apply Remediation", "detail": "Implement recommended cryptographic and mail transfer configurations"},
                {"step": 3, "action": "Capture New PCAP", "detail": "Collect fresh network traffic from corrected mail endpoints"},
                {"step": 4, "action": "Analyze with SecureMailScope", "detail": "Upload verification PCAP and run passive analysis"},
                {"step": 5, "action": "Compare Results", "detail": "Verify reduction in findings count and risk posture score"},
                {"step": 6, "action": "Verify Security Posture", "detail": "Confirm all critical and high findings are completely resolved"}
            ],
            "sessions": [s.model_dump() if hasattr(s, "model_dump") else s.dict() for s in sessions],
            "findings": [f.model_dump() if hasattr(f, "model_dump") else f.dict() for f in findings],
        }
        return json.dumps(data, indent=2)

    # ─────────────────────────────────────────────────────────────────
    # HTML — full upgraded report
    # ─────────────────────────────────────────────────────────────────
    @staticmethod
    def generate_html(evidence: EvidenceRecord, sessions: List[SessionRecord], findings: List[Finding]) -> str:
        # ── Pre-compute aggregations ──────────────────────────────────
        aggregated  = _aggregate_by_rule(findings)
        key_obs     = _key_observations(aggregated)
        prio_acts   = _priority_actions(aggregated)
        sev_count   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev_count[f.severity] = sev_count.get(f.severity, 0) + 1
        affected_sess = len({f.session_id for f in findings})

        risk_color = (
            "#ef4444" if evidence.risk_level in ("CRITICAL", "HIGH")
            else ("#eab308" if evidence.risk_level == "MEDIUM"
                  else "#10b981")
        )

        # ── Section builders ──────────────────────────────────────────
        def sev_badge(sev: str) -> str:
            c = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#06b6d4"}.get(sev, "#94a3b8")
            return f'<span style="color:{c};font-weight:700;">{sev}</span>'

        # 1. Evidence metadata
        meta_html = f"""
        <div class="card">
            <h2>1. Evidence Chain of Custody &amp; Metadata</h2>
            <div class="meta-grid">
                <div class="meta-item"><label>Evidence ID</label><span>{evidence.id}</span></div>
                <div class="meta-item"><label>Filename</label><span>{evidence.filename}</span></div>
                <div class="meta-item"><label>SHA-256 Digest</label><span style="font-size:10.5px;">{evidence.sha256}</span></div>
                <div class="meta-item"><label>File Size</label><span>{evidence.file_size_display}</span></div>
                <div class="meta-item"><label>Sessions Analyzed</label><span>{len(sessions)}</span></div>
                <div class="meta-item"><label>Findings Detected</label><span>{len(findings)}</span></div>
                <div class="meta-item"><label>Evidence Risk Posture</label><span style="color:{risk_color};">{evidence.risk_level} ({evidence.risk_score}/100)</span></div>
                <div class="meta-item"><label>Analysis Timestamp</label><span>{evidence.uploaded_at}</span></div>
            </div>
        </div>"""

        # 2. Executive Summary
        obs_items  = "".join(f"<li>{o}</li>" for o in key_obs) or "<li>No significant observations.</li>"
        act_items  = "".join(f"<li>{a}</li>" for a in prio_acts) or "<li>Review identified findings.</li>"
        exec_html = f"""
        <div class="card">
            <h2>2. Executive Security Summary</h2>
            <div class="meta-grid" style="margin-bottom:16px;">
                <div class="meta-item"><label>Overall Risk</label><span style="color:{risk_color};font-size:16px;">{evidence.risk_level} &mdash; {evidence.risk_score}/100</span></div>
                <div class="meta-item"><label>Sessions Analyzed</label><span>{len(sessions)}</span></div>
                <div class="meta-item"><label>Total Findings</label><span>{len(findings)}</span></div>
                <div class="meta-item"><label>Affected Sessions</label><span>{affected_sess}</span></div>
                <div class="meta-item"><label>Critical Findings</label><span style="color:#ef4444;">{sev_count["CRITICAL"]}</span></div>
                <div class="meta-item"><label>High Findings</label><span style="color:#f97316;">{sev_count["HIGH"]}</span></div>
                <div class="meta-item"><label>Medium Findings</label><span style="color:#eab308;">{sev_count["MEDIUM"]}</span></div>
                <div class="meta-item"><label>Low Findings</label><span style="color:#06b6d4;">{sev_count["LOW"]}</span></div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
                <div>
                    <p style="font-size:11px;color:#64748b;text-transform:uppercase;margin:0 0 8px;letter-spacing:0.5px;">Key Observations</p>
                    <ul style="margin:0;padding-left:18px;color:#cbd5e1;font-size:12.5px;line-height:1.7;">{obs_items}</ul>
                </div>
                <div>
                    <p style="font-size:11px;color:#64748b;text-transform:uppercase;margin:0 0 8px;letter-spacing:0.5px;">Priority Actions</p>
                    <ul style="margin:0;padding-left:18px;color:#cbd5e1;font-size:12.5px;line-height:1.7;">{act_items}</ul>
                </div>
            </div>
        </div>"""

        # 3. Findings Aggregation (by rule)
        agg_rows = ""
        for r in aggregated:
            agg_rows += f"""
            <tr style="border-bottom:1px solid #1e293b;">
                <td style="padding:9px 10px;vertical-align:top;">{sev_badge(r["severity"])}</td>
                <td style="padding:9px 10px;vertical-align:top;"><strong style="color:#f1f5f9;">{r["title"]}</strong><br><small style="color:#00f2fe;font-family:monospace;">{r["rule_id"]}</small></td>
                <td style="padding:9px 10px;vertical-align:top;text-align:center;font-family:monospace;font-weight:700;color:#f1f5f9;">{r["occurrences"]}</td>
                <td style="padding:9px 10px;vertical-align:top;text-align:center;font-family:monospace;color:#94a3b8;">{r["affected_sessions"]}</td>
            </tr>"""
        agg_html = f"""
        <div class="card">
            <h2>3. Security Findings Summary <span style="font-size:12px;color:#64748b;">(Aggregated by Rule)</span></h2>
            <p style="font-size:12px;color:#94a3b8;margin:0 0 12px;">One session can trigger multiple rules. <em>Occurrences</em> counts total rule violations; <em>Affected Sessions</em> counts distinct sessions.</p>
            <table>
                <colgroup><col style="width:12%;"><col style="width:48%;"><col style="width:20%;"><col style="width:20%;"></colgroup>
                <thead><tr><th>Severity</th><th>Finding / Rule</th><th style="text-align:center;">Occurrences</th><th style="text-align:center;">Affected Sessions</th></tr></thead>
                <tbody>{agg_rows if agg_rows else "<tr><td colspan='4' style='padding:16px;text-align:center;color:#10b981;'>No findings detected.</td></tr>"}</tbody>
            </table>
        </div>"""

        # 4. Risk Breakdown
        _sev_bar_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#06b6d4"}
        _sev_bars = ""
        for sv in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            _sev_c = _sev_bar_colors.get(sv, "#94a3b8")
            _sev_pct = str(round(sev_count[sv] / len(findings) * 100)) if len(findings) > 0 else "0"
            _sev_bars += (
                f'<div style="display:flex;align-items:center;gap:8px;">'
                f'<span style="width:70px;font-size:11px;color:{_sev_c};">{sv}</span>'
                f'<div style="flex:1;background:#1e293b;border-radius:3px;height:8px;">'
                f'<div style="background:{_sev_c};width:{_sev_pct}%;height:100%;border-radius:3px;"></div>'
                f'</div>'
                f'<span style="font-size:11px;font-family:monospace;color:#94a3b8;">{sev_count[sv]}</span>'
                f'</div>'
            )
        risk_html = f"""
        <div class="card">
            <h2>4. Risk Breakdown</h2>
            <div style="display:flex;align-items:center;gap:20px;margin-bottom:18px;">
                <div style="text-align:center;padding:16px 24px;border:2px solid {risk_color};border-radius:8px;min-width:100px;">
                    <div style="font-size:36px;font-weight:900;color:{risk_color};font-family:monospace;">{evidence.risk_score}</div>
                    <div style="font-size:11px;color:#64748b;margin-top:2px;">/ 100</div>
                    <div style="font-size:13px;font-weight:700;color:{risk_color};margin-top:6px;">{evidence.risk_level}</div>
                </div>
                <div style="flex:1;">
                    <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:10px;">Severity Distribution</div>
                    <div style="display:flex;flex-direction:column;gap:6px;">
                        {_sev_bars}
                    </div>
                </div>
            </div>
            <div style="background:#090E1A;border:1px solid #1c2936;border-radius:6px;padding:12px;font-size:12px;color:#94a3b8;line-height:1.6;">
                <strong style="color:#E2E8F0;">Risk Methodology:</strong> The risk score is computed deterministically from rule violations detected in the PCAP capture.
                Categories: <strong style="color:#06b6d4;">Low Risk (0–20)</strong>, <strong style="color:#eab308;">Medium Risk (21–40)</strong>, <strong style="color:#f97316;">High Risk (41–60)</strong>, and <strong style="color:#ef4444;">Critical Risk (&gt;60)</strong>.
                Each rule category contributes a bounded point allocation (e.g., Cleartext Transport up to 35 pts, Deprecated TLS up to 30 pts). The score is capped at 100.
                Detailed per-factor contributions are available in the JSON export.
            </div>
        </div>"""

        # 5. Priority Findings (top critical/high by affected sessions)
        top_findings = [r for r in aggregated if r["severity"] in ("CRITICAL", "HIGH")][:6]
        if not top_findings:
            top_findings = aggregated[:4]
        pf_items = ""
        for r in top_findings:
            ic = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#06b6d4"}.get(r["severity"], "#94a3b8")
            pf_items += f"""
            <div style="display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-bottom:1px solid #1e293b;">
                <div style="color:{ic};font-size:11px;font-weight:700;min-width:65px;">{r["severity"]}</div>
                <div style="flex:1;">
                    <div style="color:#f1f5f9;font-weight:600;font-size:13px;">{r["title"]}</div>
                    <div style="color:#64748b;font-size:11px;font-family:monospace;">{r["rule_id"]}</div>
                </div>
                <div style="text-align:right;min-width:80px;">
                    <div style="color:{ic};font-weight:700;font-size:14px;">{r["occurrences"]}</div>
                    <div style="color:#64748b;font-size:10px;">occurrences</div>
                </div>
                <div style="text-align:right;min-width:80px;">
                    <div style="color:#94a3b8;font-weight:600;font-size:13px;">{r["affected_sessions"]}</div>
                    <div style="color:#64748b;font-size:10px;">sessions</div>
                </div>
            </div>"""
        prio_html = f"""
        <div class="card">
            <h2>5. Priority Findings</h2>
            <p style="font-size:12px;color:#94a3b8;margin:0 0 12px;">Highest-priority rule violations requiring immediate attention. Sorted by severity then occurrence count.</p>
            {pf_items if pf_items else "<p style='color:#10b981;'>No priority findings detected.</p>"}
        </div>"""

        # 6. Remediation Plan (derived from real recommendations)
        crit_recs  = list({r["recommendation"] for r in aggregated if r["severity"] == "CRITICAL"})[:4]
        high_recs  = list({r["recommendation"] for r in aggregated if r["severity"] == "HIGH"})[:3]
        med_recs   = list({r["recommendation"] for r in aggregated if r["severity"] == "MEDIUM"})[:3]
        def checklist(items: List[str]) -> str:
            if not items:
                return "<li style='color:#64748b;'>No items in this priority tier.</li>"
            return "".join(f"<li style='margin-bottom:4px;'>{i}</li>" for i in items)

        rem_html = f"""
        <div class="card">
            <h2>6. Remediation Plan</h2>
            <p style="font-size:12px;color:#94a3b8;margin:0 0 14px;">Actions derived directly from the detected findings and rule recommendations. This plan must be implemented by the responsible infrastructure team.</p>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;">
                <div style="border:1px solid rgba(239,68,68,0.3);border-radius:6px;padding:14px;">
                    <div style="color:#ef4444;font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:10px;">Priority 1 &mdash; Critical</div>
                    <ul style="margin:0;padding-left:18px;color:#cbd5e1;font-size:12px;line-height:1.8;">{checklist(crit_recs)}</ul>
                </div>
                <div style="border:1px solid rgba(249,115,22,0.25);border-radius:6px;padding:14px;">
                    <div style="color:#f97316;font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:10px;">Priority 2 &mdash; High</div>
                    <ul style="margin:0;padding-left:18px;color:#cbd5e1;font-size:12px;line-height:1.8;">{checklist(high_recs)}</ul>
                </div>
                <div style="border:1px solid rgba(234,179,8,0.25);border-radius:6px;padding:14px;">
                    <div style="color:#eab308;font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:10px;">Priority 3 &mdash; Medium / Verification</div>
                    <ul style="margin:0;padding-left:18px;color:#cbd5e1;font-size:12px;line-height:1.8;">{checklist(med_recs)}
                        <li style="margin-bottom:4px;">Apply configuration changes in a test environment first</li>
                        <li style="margin-bottom:4px;">Capture new controlled traffic after changes</li>
                        <li style="margin-bottom:4px;">Re-analyze the verification PCAP with SecureMailScope</li>
                    </ul>
                </div>
            </div>
        </div>"""

        # 7. Verification Workflow
        verif_html = """
        <div class="card">
            <h2>7. Remediation Verification Workflow</h2>
            <p style="font-size:12px;color:#94a3b8;margin:0 0 14px;">Follow this workflow to confirm that remediation actions have resolved the identified vulnerabilities.</p>
            <div style="display:flex;align-items:center;gap:0;flex-wrap:wrap;">"""
        steps = [
            ("CURRENT ASSESSMENT", "Review this report and identify all critical findings"),
            ("APPLY REMEDIATION", "Implement the recommended configuration changes"),
            ("CAPTURE NEW PCAP", "Collect a fresh packet capture from the corrected environment"),
            ("ANALYZE WITH SECUREMAILSCOPE", "Upload the verification PCAP and run passive analysis"),
            ("COMPARE RESULTS", "Compare new findings count and risk score against this baseline"),
            ("VERIFY SECURITY POSTURE", "Confirm that critical and high findings are resolved"),
        ]
        for i, (title, desc) in enumerate(steps):
            _arrow = '<div style="color:#00f2fe;padding:0 6px;font-size:18px;">&#8594;</div>' if i < len(steps) - 1 else ""
            verif_html += (
                f'<div style="display:flex;align-items:center;gap:0;">'
                f'<div style="text-align:center;padding:10px 14px;background:#111923;border:1px solid #1c2936;border-radius:6px;min-width:120px;">'
                f'<div style="font-size:10px;color:#00f2fe;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;">{title}</div>'
                f'<div style="font-size:10.5px;color:#64748b;margin-top:4px;line-height:1.4;">{desc}</div>'
                f'</div>'
                f'{_arrow}'
                f'</div>'
            )
        verif_html += """
            </div>
            <div style="margin-top:14px;padding:10px 14px;background:#090E1A;border:1px solid #1c2936;border-radius:6px;font-size:12px;color:#94a3b8;line-height:1.6;">
                <strong style="color:#E2E8F0;">Note:</strong> Automatic before/after comparison is not yet implemented. Verification requires manual re-analysis and comparison of finding counts and risk scores between this report and the verification report.
            </div>
        </div>"""

        # 8. Detailed findings inventory
        findings_rows = ""
        for f in findings:
            sev_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#06b6d4"}.get(f.severity, "#94a3b8")
            findings_rows += f"""
            <tr style="border-bottom:1px solid #1e293b;">
                <td style="padding:9px 10px;color:{sev_color};font-weight:bold;vertical-align:top;">{f.severity}</td>
                <td style="padding:9px 10px;vertical-align:top;overflow-wrap:anywhere;word-break:break-word;">
                    <strong style="color:#f1f5f9;">{f.title}</strong><br>
                    <small style="color:#00f2fe;font-family:monospace;font-size:11px;">{f.rule_id}</small>
                </td>
                <td style="padding:9px 10px;font-family:monospace;vertical-align:top;">{f.protocol}</td>
                <td style="padding:9px 10px;font-family:monospace;font-size:11px;vertical-align:top;overflow-wrap:anywhere;word-break:break-all;">{f.session_id}</td>
                <td style="padding:9px 10px;color:#cbd5e1;vertical-align:top;overflow-wrap:anywhere;word-break:break-word;">{f.recommendation}</td>
            </tr>"""

        inv_html = f"""
        <div class="card">
            <h2>8. Detailed Findings Inventory ({len(findings)} total)</h2>
            <p style="font-size:12px;color:#94a3b8;margin:0 0 12px;">Complete listing of all rule violations detected. Each row represents one finding instance tied to a specific session and evidence artifact.</p>
            <table>
                <colgroup><col style="width:10%;"><col style="width:28%;"><col style="width:8%;"><col style="width:17%;"><col style="width:37%;"></colgroup>
                <thead><tr><th>Severity</th><th>Finding / Rule</th><th>Protocol</th><th>Session ID</th><th>Forensic Recommendation</th></tr></thead>
                <tbody>{findings_rows if findings_rows else "<tr><td colspan='5' style='padding:16px;text-align:center;color:#10b981;'>No security findings detected.</td></tr>"}</tbody>
            </table>
        </div>"""

        # 9. Session inventory
        sessions_rows = ""
        for s in sessions:
            rc = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "SECURE": "#10b981"}.get(s.risk_level, "#eab308")
            sessions_rows += f"""
            <tr style="border-bottom:1px solid #1e293b;">
                <td style="padding:8px 10px;font-family:monospace;font-size:11px;vertical-align:top;overflow-wrap:anywhere;word-break:break-all;">{s.session_id}</td>
                <td style="padding:8px 10px;font-weight:bold;vertical-align:top;">{s.protocol}</td>
                <td style="padding:8px 10px;font-family:monospace;font-size:11px;vertical-align:top;overflow-wrap:anywhere;word-break:break-all;">{s.network.src_ip}:{s.network.src_port}</td>
                <td style="padding:8px 10px;font-family:monospace;font-size:11px;vertical-align:top;overflow-wrap:anywhere;word-break:break-all;">{s.network.dst_ip}:{s.network.dst_port}</td>
                <td style="padding:8px 10px;font-family:monospace;font-size:11px;vertical-align:top;">{s.tls.tls_version}</td>
                <td style="padding:8px 10px;font-family:monospace;font-size:10.5px;vertical-align:top;overflow-wrap:anywhere;word-break:break-all;">{s.tls.cipher_suite}</td>
                <td style="padding:8px 10px;color:{rc};font-weight:bold;vertical-align:top;white-space:nowrap;">{s.risk_level} ({s.risk_score})</td>
            </tr>"""

        sess_html = f"""
        <div class="card">
            <h2>9. Reconstructed Email Protocol Sessions ({len(sessions)})</h2>
            <table>
                <colgroup><col style="width:17%;"><col style="width:7%;"><col style="width:16%;"><col style="width:16%;"><col style="width:10%;"><col style="width:16%;"><col style="width:18%;"></colgroup>
                <thead><tr><th>Session ID</th><th>Protocol</th><th>Source Endpoint</th><th>Dest Endpoint</th><th>TLS Version</th><th>Cipher Suite</th><th>Risk Posture</th></tr></thead>
                <tbody>{sessions_rows if sessions_rows else "<tr><td colspan='7' style='padding:16px;text-align:center;color:#64748b;'>No email sessions extracted.</td></tr>"}</tbody>
            </table>
        </div>"""

        # Compose full HTML
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>SecureMailScope Forensics Report &mdash; {evidence.filename}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ background-color:#080B10;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;padding:32px;margin:0;line-height:1.5; }}
        .header {{ border-bottom:2px solid #00f2fe;padding-bottom:20px;margin-bottom:28px;display:flex;justify-content:space-between;align-items:flex-end; }}
        .brand {{ font-size:22px;font-weight:800;letter-spacing:2px;color:#00f2fe;font-family:monospace; }}
        .subtitle {{ font-size:12px;color:#94a3b8;letter-spacing:1px;text-transform:uppercase;margin-top:4px; }}
        .card {{ background:#0D121A;border:1px solid #1C2936;border-radius:8px;padding:20px;margin-bottom:24px;overflow:hidden; }}
        h2 {{ color:#38bdf8;font-size:14px;text-transform:uppercase;letter-spacing:1px;margin-top:0;margin-bottom:16px;border-bottom:1px solid #1C2936;padding-bottom:8px;display:flex;justify-content:space-between; }}
        table {{ width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed;word-wrap:break-word; }}
        th {{ background:#111923;color:#94a3b8;text-align:left;padding:10px;font-size:10.5px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid #1C2936; }}
        td {{ overflow-wrap:anywhere;word-break:break-word;vertical-align:top; }}
        .meta-grid {{ display:grid;grid-template-columns:repeat(4,1fr);gap:16px; }}
        .meta-item {{ overflow:hidden; }}
        .meta-item label {{ display:block;font-size:10.5px;color:#64748b;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px; }}
        .meta-item span {{ font-size:13px;font-weight:600;color:#f1f5f9;font-family:monospace;overflow-wrap:anywhere;word-break:break-all;display:block; }}
        @media print {{ body {{ padding:16px; }} .card {{ break-inside:avoid; }} }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="brand">SECUREMAILSCOPE</div>
            <div class="subtitle">PASSIVE NETWORK EMAIL FORENSICS &amp; CRYPTOGRAPHIC POSTURE REPORT</div>
        </div>
        <div style="font-size:11px;color:#64748b;font-family:monospace;">CONFIDENTIAL FORENSIC AUDIT DOSSIER</div>
    </div>
    {meta_html}
    {exec_html}
    {agg_html}
    {risk_html}
    {prio_html}
    {rem_html}
    {verif_html}
    {inv_html}
    {sess_html}
</body>
</html>"""

    # ─────────────────────────────────────────────────────────────────
    # PDF — upgraded report
    # ─────────────────────────────────────────────────────────────────
    @staticmethod
    def generate_pdf(evidence: EvidenceRecord, sessions: List[SessionRecord], findings: List[Finding]) -> bytes:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        elements = []
        styles = getSampleStyleSheet()

        # Paragraph styles
        title_style = ParagraphStyle("Title2", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=colors.HexColor("#0f172a"), spaceAfter=4)
        sub_style   = ParagraphStyle("Sub2",   parent=styles["Normal"],   fontName="Helvetica-Bold", fontSize=9,  leading=13, textColor=colors.HexColor("#0284c7"), spaceAfter=10)
        h2_style    = ParagraphStyle("H2b",    parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=15, textColor=colors.HexColor("#0f172a"), spaceBefore=12, spaceAfter=6)
        h3_style    = ParagraphStyle("H3b",    parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=9,  leading=12, textColor=colors.HexColor("#0284c7"), spaceBefore=6, spaceAfter=4)
        body_style  = ParagraphStyle("Body2",  parent=styles["Normal"],   fontName="Helvetica",      fontSize=8,  leading=10, textColor=colors.HexColor("#334155"))
        mono_style  = ParagraphStyle("Mono2",  parent=styles["Normal"],   fontName="Courier",        fontSize=7,  leading=9,  textColor=colors.HexColor("#1e293b"))
        note_style  = ParagraphStyle("Note2",  parent=styles["Normal"],   fontName="Helvetica-Oblique", fontSize=7.5, leading=10, textColor=colors.HexColor("#475569"))
        th_style    = ParagraphStyle("TH2",    parent=styles["Normal"],   fontName="Helvetica-Bold", fontSize=8,  leading=10, textColor=colors.white)
        cell_bold   = ParagraphStyle("CellB2", parent=styles["Normal"],   fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=colors.HexColor("#0f172a"))
        cell_body   = ParagraphStyle("CellBo2",parent=styles["Normal"],   fontName="Helvetica",      fontSize=7.5, leading=9.5, textColor=colors.HexColor("#334155"))
        cell_mono   = ParagraphStyle("CellM2", parent=styles["Normal"],   fontName="Courier",        fontSize=7,   leading=9,  textColor=colors.HexColor("#1e293b"))
        cell_crit   = ParagraphStyle("CritC2", parent=styles["Normal"],   fontName="Helvetica-Bold", fontSize=7.5, leading=9.5, textColor=colors.HexColor("#dc2626"))
        cell_high   = ParagraphStyle("HighC2", parent=styles["Normal"],   fontName="Helvetica-Bold", fontSize=7.5, leading=9.5, textColor=colors.HexColor("#ea580c"))
        cell_med    = ParagraphStyle("MedC2",  parent=styles["Normal"],   fontName="Helvetica-Bold", fontSize=7.5, leading=9.5, textColor=colors.HexColor("#ca8a04"))
        cell_sec    = ParagraphStyle("SecC2",  parent=styles["Normal"],   fontName="Helvetica-Bold", fontSize=7.5, leading=9.5, textColor=colors.HexColor("#16a34a"))

        def sev_style_pdf(sev: str) -> ParagraphStyle:
            return {"CRITICAL": cell_crit, "HIGH": cell_high, "MEDIUM": cell_med}.get(sev, cell_sec)

        sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev_count[f.severity] = sev_count.get(f.severity, 0) + 1
        affected_sess = len({f.session_id for f in findings})
        aggregated    = _aggregate_by_rule(findings)
        key_obs       = _key_observations(aggregated)
        prio_acts     = _priority_actions(aggregated)

        # ── Title
        elements.append(Paragraph("SECUREMAILSCOPE FORENSIC REPORT", title_style))
        elements.append(Paragraph("PASSIVE NETWORK EMAIL FORENSICS &amp; CRYPTOGRAPHIC POSTURE", sub_style))
        elements.append(Spacer(1, 4))

        # ── 1. Evidence metadata (total 540 pt)
        elements.append(Paragraph("1. Evidence Chain of Custody", h2_style))
        meta_data = [
            [Paragraph("<b>Evidence ID:</b>",  cell_body), Paragraph(evidence.id,          cell_mono), Paragraph("<b>Filename:</b>",  cell_body), Paragraph(evidence.filename,             cell_bold)],
            [Paragraph("<b>File Size:</b>",    cell_body), Paragraph(evidence.file_size_display, cell_body), Paragraph("<b>Risk Posture:</b>", cell_body), Paragraph(f"<b>{evidence.risk_level}</b> ({evidence.risk_score}/100)", cell_crit if evidence.risk_level in ("CRITICAL","HIGH") else cell_sec)],
            [Paragraph("<b>Sessions:</b>",     cell_body), Paragraph(str(len(sessions)),   cell_mono), Paragraph("<b>Findings:</b>",  cell_body), Paragraph(str(len(findings)),            cell_mono)],
            [Paragraph("<b>SHA-256:</b>",      cell_body), Paragraph(evidence.sha256,      cell_mono), Paragraph("<b>Timestamp:</b>", cell_body), Paragraph(evidence.uploaded_at,          cell_mono)],
        ]
        meta_tbl = Table(meta_data, colWidths=[90, 180, 90, 180])
        meta_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,-1), colors.HexColor("#f8fafc")),
            ("VALIGN", (0,0),(-1,-1), "TOP"),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4), ("TOPPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING", (0,0),(-1,-1), 6),   ("RIGHTPADDING", (0,0),(-1,-1), 6),
            ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(meta_tbl)
        elements.append(Spacer(1, 10))

        # ── 2. Executive Summary
        elements.append(Paragraph("2. Executive Security Summary", h2_style))
        exec_data = [
            [Paragraph("<b>Overall Risk</b>", cell_body), Paragraph(f"<b>{evidence.risk_level} &mdash; {evidence.risk_score}/100</b>", cell_crit if evidence.risk_level in ("CRITICAL","HIGH") else cell_sec),
             Paragraph("<b>Sessions Analyzed</b>", cell_body), Paragraph(str(len(sessions)), cell_bold)],
            [Paragraph("<b>Total Findings</b>", cell_body), Paragraph(str(len(findings)), cell_bold),
             Paragraph("<b>Affected Sessions</b>", cell_body), Paragraph(str(affected_sess), cell_bold)],
            [Paragraph("<b>Critical</b>", cell_body), Paragraph(str(sev_count["CRITICAL"]), cell_crit),
             Paragraph("<b>High</b>", cell_body),     Paragraph(str(sev_count["HIGH"]), cell_high)],
            [Paragraph("<b>Medium</b>", cell_body),   Paragraph(str(sev_count["MEDIUM"]), cell_med),
             Paragraph("<b>Low</b>", cell_body),      Paragraph(str(sev_count["LOW"]), cell_sec)],
        ]
        exec_tbl = Table(exec_data, colWidths=[100, 170, 100, 170])
        exec_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,-1), colors.HexColor("#f0f9ff")),
            ("VALIGN", (0,0),(-1,-1), "TOP"),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4), ("TOPPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING", (0,0),(-1,-1), 6),   ("RIGHTPADDING", (0,0),(-1,-1), 6),
            ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(exec_tbl)
        elements.append(Spacer(1, 6))
        elements.append(Paragraph("<b>Key Observations</b>", h3_style))
        for ob in key_obs:
            elements.append(Paragraph(f"• {ob}", body_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("<b>Priority Actions</b>", h3_style))
        for act in prio_acts:
            elements.append(Paragraph(f"• {act}", body_style))
        elements.append(Spacer(1, 10))

        # ── 3. Findings Aggregation (50+130+60+60+240=540)
        elements.append(Paragraph("3. Security Findings Summary (Aggregated by Rule)", h2_style))
        elements.append(Paragraph("One session can trigger multiple rules. Occurrences = total violations; Affected Sessions = distinct sessions.", note_style))
        elements.append(Spacer(1, 4))
        if aggregated:
            agg_data = [[Paragraph("Severity", th_style), Paragraph("Finding / Rule ID", th_style), Paragraph("Occurrences", th_style), Paragraph("Affected Sessions", th_style)]]
            for r in aggregated:
                agg_data.append([
                    Paragraph(r["severity"], sev_style_pdf(r["severity"])),
                    Paragraph(f"<b>{r['title']}</b><br/><font name='Courier' size='6.5'>{r['rule_id']}</font>", cell_body),
                    Paragraph(str(r["occurrences"]), cell_bold),
                    Paragraph(str(r["affected_sessions"]), cell_bold),
                ])
            agg_tbl = Table(agg_data, colWidths=[55, 300, 90, 95])
            agg_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#0f172a")),
                ("VALIGN", (0,0),(-1,-1), "TOP"),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4), ("TOPPADDING", (0,0),(-1,-1), 4),
                ("LEFTPADDING", (0,0),(-1,-1), 5),   ("RIGHTPADDING", (0,0),(-1,-1), 5),
                ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ]))
            elements.append(agg_tbl)
        else:
            elements.append(Paragraph("No findings detected.", cell_body))
        elements.append(Spacer(1, 10))

        # ── 4. Risk Breakdown
        elements.append(Paragraph("4. Risk Breakdown", h2_style))
        risk_level_color = colors.HexColor("#dc2626") if evidence.risk_level in ("CRITICAL","HIGH") else colors.HexColor("#16a34a")
        risk_data = [[
            Paragraph(f"<b>Overall Risk Score:</b> {evidence.risk_score}/100", cell_bold),
            Paragraph(f"<b>Risk Level:</b> {evidence.risk_level}", ParagraphStyle("RL", parent=cell_bold, textColor=risk_level_color)),
            Paragraph(f"<b>Critical:</b> {sev_count['CRITICAL']}  <b>High:</b> {sev_count['HIGH']}  <b>Medium:</b> {sev_count['MEDIUM']}  <b>Low:</b> {sev_count['LOW']}", cell_body),
        ]]
        risk_tbl = Table(risk_data, colWidths=[180, 120, 240])
        risk_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,-1), colors.HexColor("#f8fafc")),
            ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
            ("BOTTOMPADDING", (0,0),(-1,-1), 6), ("TOPPADDING", (0,0),(-1,-1), 6),
            ("LEFTPADDING", (0,0),(-1,-1), 8),   ("RIGHTPADDING", (0,0),(-1,-1), 8),
            ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(risk_tbl)
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(
            "Risk Methodology: The score is computed deterministically from detected rule violations (Low: 0-20, Medium: 21-40, High: 41-60, Critical: >60). Each category has a bounded point allocation (Cleartext: max 35pts, Deprecated TLS: max 30pts, Weak Cipher: max 25pts, Certificate Issues: max 20pts, No PFS: max 15pts, Legacy CBC: max 10pts). The score is capped at 100. Detailed per-factor data is available in the JSON export.",
            note_style
        ))
        elements.append(Spacer(1, 10))

        # ── 5. Priority Findings
        elements.append(Paragraph("5. Priority Findings", h2_style))
        top_f = [r for r in aggregated if r["severity"] in ("CRITICAL","HIGH")][:6] or aggregated[:4]
        if top_f:
            pf_data = [[Paragraph("Severity", th_style), Paragraph("Finding", th_style), Paragraph("Occurrences", th_style), Paragraph("Affected Sessions", th_style)]]
            for r in top_f:
                pf_data.append([
                    Paragraph(r["severity"], sev_style_pdf(r["severity"])),
                    Paragraph(f"<b>{r['title']}</b>", cell_body),
                    Paragraph(str(r["occurrences"]), cell_bold),
                    Paragraph(str(r["affected_sessions"]), cell_bold),
                ])
            pf_tbl = Table(pf_data, colWidths=[55, 330, 75, 80])
            pf_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#1e293b")),
                ("VALIGN", (0,0),(-1,-1), "TOP"),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4), ("TOPPADDING", (0,0),(-1,-1), 4),
                ("LEFTPADDING", (0,0),(-1,-1), 5),   ("RIGHTPADDING", (0,0),(-1,-1), 5),
                ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            elements.append(pf_tbl)
        else:
            elements.append(Paragraph("No priority findings detected.", cell_body))
        elements.append(Spacer(1, 10))

        # ── 6. Remediation Plan
        elements.append(Paragraph("6. Remediation Plan", h2_style))
        crit_recs = list({r["recommendation"] for r in aggregated if r["severity"] == "CRITICAL"})[:4]
        high_recs = list({r["recommendation"] for r in aggregated if r["severity"] == "HIGH"})[:3]
        med_recs  = list({r["recommendation"] for r in aggregated if r["severity"] == "MEDIUM"})[:3]
        elements.append(Paragraph("Priority 1 — Critical", ParagraphStyle("P1", parent=h3_style, textColor=colors.HexColor("#dc2626"))))
        for rec in (crit_recs or ["No critical findings."]):
            elements.append(Paragraph(f"&#9744; {rec}", body_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("Priority 2 — High", ParagraphStyle("P2", parent=h3_style, textColor=colors.HexColor("#ea580c"))))
        for rec in (high_recs or ["No high findings."]):
            elements.append(Paragraph(f"&#9744; {rec}", body_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("Priority 3 — Medium / Verification", ParagraphStyle("P3", parent=h3_style, textColor=colors.HexColor("#ca8a04"))))
        for rec in (med_recs or []):
            elements.append(Paragraph(f"&#9744; {rec}", body_style))
        elements.append(Paragraph("&#9744; Apply configuration changes in a test environment first", body_style))
        elements.append(Paragraph("&#9744; Capture new controlled traffic after changes", body_style))
        elements.append(Paragraph("&#9744; Re-analyze the verification PCAP with SecureMailScope", body_style))
        elements.append(Spacer(1, 10))

        # ── 7. Verification Workflow
        elements.append(Paragraph("7. Remediation Verification Workflow", h2_style))
        workflow_steps = [
            "Current Assessment  &#8594;",
            "Apply Remediation  &#8594;",
            "Capture New PCAP  &#8594;",
            "Analyze with SecureMailScope  &#8594;",
            "Compare Results  &#8594;",
            "Verify Security Posture"
        ]
        elements.append(Paragraph(" &nbsp; ".join(workflow_steps), body_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("Note: Automatic before/after comparison is not yet implemented. Verification requires manual re-analysis and comparison of finding counts and risk scores.", note_style))
        elements.append(Spacer(1, 10))

        # ── 8. Detailed Findings Inventory (540 pt: 50+95+130+75+190)
        elements.append(Paragraph(f"8. Detailed Findings Inventory ({len(findings)} total)", h2_style))
        if findings:
            find_data = [[Paragraph("Severity", th_style), Paragraph("Rule ID", th_style), Paragraph("Finding Title", th_style), Paragraph("Session ID", th_style), Paragraph("Forensic Recommendation", th_style)]]
            for f in findings:
                find_data.append([
                    Paragraph(f.severity, sev_style_pdf(f.severity)),
                    Paragraph(f.rule_id, cell_mono),
                    Paragraph(f.title, cell_bold),
                    Paragraph(f.session_id, cell_mono),
                    Paragraph(f.recommendation, cell_body),
                ])
            find_tbl = Table(find_data, colWidths=[50, 95, 130, 75, 190])
            find_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#0f172a")),
                ("VALIGN", (0,0),(-1,-1), "TOP"),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4), ("TOPPADDING", (0,0),(-1,-1), 4),
                ("LEFTPADDING", (0,0),(-1,-1), 5),   ("RIGHTPADDING", (0,0),(-1,-1), 5),
                ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ]))
            elements.append(find_tbl)
        else:
            elements.append(Paragraph("No security violations found. Conforms to security baseline.", cell_body))
        elements.append(Spacer(1, 10))

        # ── 9. Sessions (first 30; 540 pt: 75+40+110+110+75+130)
        elements.append(Paragraph(f"9. Reconstructed Protocol Sessions ({len(sessions)})", h2_style))
        if sessions:
            sess_data = [[Paragraph("Session ID", th_style), Paragraph("Proto", th_style), Paragraph("Source", th_style), Paragraph("Destination", th_style), Paragraph("TLS", th_style), Paragraph("Cipher &amp; Risk", th_style)]]
            for s in sessions[:30]:
                rs = cell_crit if s.risk_level == "CRITICAL" else (cell_high if s.risk_level == "HIGH" else (cell_sec if s.risk_level == "SECURE" else cell_med))
                sess_data.append([
                    Paragraph(s.session_id, cell_mono),
                    Paragraph(s.protocol, cell_bold),
                    Paragraph(f"{s.network.src_ip}:{s.network.src_port}", cell_mono),
                    Paragraph(f"{s.network.dst_ip}:{s.network.dst_port}", cell_mono),
                    Paragraph(s.tls.tls_version, cell_mono),
                    Paragraph(f"{s.tls.cipher_suite}<br/><b>Risk:</b> {s.risk_level} ({s.risk_score})", cell_body),
                ])
            sess_tbl = Table(sess_data, colWidths=[75, 40, 110, 110, 75, 130])
            sess_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#1e293b")),
                ("VALIGN", (0,0),(-1,-1), "TOP"),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4), ("TOPPADDING", (0,0),(-1,-1), 4),
                ("LEFTPADDING", (0,0),(-1,-1), 5),   ("RIGHTPADDING", (0,0),(-1,-1), 5),
                ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ]))
            elements.append(sess_tbl)
            if len(sessions) > 30:
                elements.append(Spacer(1, 4))
                elements.append(Paragraph(f"<i>... Showing first 30 of {len(sessions)} reassembled sessions. Full telemetry is in the JSON export.</i>", note_style))

        doc.build(elements)
        return buf.getvalue()
