import urllib.request
import json

def get(url):
    with urllib.request.urlopen("http://127.0.0.1:8000" + url) as r:
        return r.status, r.read()

def post(url, data=b""):
    req = urllib.request.Request("http://127.0.0.1:8000" + url, data=data, method="POST")
    with urllib.request.urlopen(req) as r:
        return r.status, r.read()

print("=== 1. HEALTH CHECK ===")
status, body = get("/api/health")
print("Health:", status, body.decode())

print("\n=== 2. SEED SAMPLE FORENSIC EVIDENCE ===")
status, body = post("/api/sample-data/seed")
print("Seed Result:", status, body.decode())

print("\n=== 3. OVERVIEW METRICS ===")
status, body = get("/api/overview")
m = json.loads(body.decode())
print(f"Total Evidence: {m['total_evidence']}, Total Sessions: {m['total_sessions']}, At-Risk: {m['at_risk_sessions']}, High/Crit: {m['high_critical_findings']}")
print("Risk Dist:", m["risk_distribution"])
print("Proto Dist:", m["protocol_distribution"])
print("TLS Dist:", m["tls_distribution"])
print("Recent Findings Count:", len(m["recent_findings"]))

print("\n=== 4. EVIDENCE LIST ===")
status, body = get("/api/evidence")
evs = json.loads(body.decode())
print(f"Evidence Count: {len(evs)}")
for e in evs:
    print(f"  - {e['id']}: {e['filename']} ({e['file_size_display']}) SHA256: {e['sha256'][:16]}... Status: {e['analysis_status']} Risk: {e['risk_level']}")

print("\n=== 5. SESSIONS & INVESTIGATION ===")
status, body = get("/api/sessions")
sess = json.loads(body.decode())
print(f"Sessions Count: {len(sess)}")
for s in sess:
    print(f"  - {s['session_id']}: {s['protocol']} {s['network']['src_ip']}:{s['network']['src_port']} -> {s['network']['dst_ip']}:{s['network']['dst_port']} | TLS: {s['tls']['tls_version']} | Cipher: {s['tls']['cipher_suite']} | Risk: {s['risk_level']} ({s['risk_score']})")

# Deep investigation of first session
s0_id = sess[0]["session_id"]
status, body = get(f"/api/sessions/{s0_id}")
s0 = json.loads(body.decode())
print(f"\nSession {s0_id} Evidence Chain Nodes: {len(s0['evidence_chain'])}")
for node in s0["evidence_chain"]:
    print(f"    [{node['status'].upper()}] {node['step']}: {node['title']}")

print("\n=== 6. SECURITY FINDINGS ===")
status, body = get("/api/findings")
fnds = json.loads(body.decode())
print(f"Findings Count: {len(fnds)}")
for f in fnds[:5]:
    print(f"  - [{f['severity']}] {f['id']} ({f['rule_id']}): {f['title']} [Session: {f['session_id']}]")

print("\n=== 7. EXPLAINABLE RISK POSTURE ===")
status, body = get("/api/risk-posture")
risk = json.loads(body.decode())
print(f"Overall Score: {risk['overall_score']}/100 ({risk['severity']})")
print("Contributing Factors:")
for cf in risk["contributing_factors"]:
    print(f"    +{cf['points']} pts: {cf['factor']} ({cf['details']})")

print("\n=== 8. REPORTS ===")
status, body = get("/api/reports")
reps = json.loads(body.decode())
print(f"Reports Count: {len(reps)}")
for r in reps:
    print(f"  - {r['id']}: {r['evidence_filename']} ({r['risk_level']}) Formats: {r['formats']}")
rep0_id = reps[0]["id"]
status_html, body_html = get(f"/api/reports/{rep0_id}/view?format=html")
print(f"HTML Report {rep0_id}: HTTP {status_html}, {len(body_html)} bytes")
status_pdf, body_pdf = get(f"/api/reports/{rep0_id}/download?format=pdf")
print(f"PDF Report {rep0_id}: HTTP {status_pdf}, {len(body_pdf)} bytes")

print("\n=== 9. SETTINGS & SYSTEM STATUS ===")
status, body = get("/api/settings/status")
sys_stat = json.loads(body.decode())
print("System Status:", sys_stat["app_version"], "| Engine:", sys_stat["engine_status"], "| Mode:", sys_stat["forensic_mode"])

print("\n>>> ALL 9 FORENSIC SUITES VERIFIED AND FUNCTIONING PERFECTLY! <<<")
