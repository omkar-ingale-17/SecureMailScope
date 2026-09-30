# SecureMailScope 🛡️🔍

> **Passive Network Email Forensics & Cryptographic Security Posture System**

SecureMailScope is a specialized network forensics tool designed to inspect, reconstruct, and analyze email traffic passively from packet captures (`.pcap` / `.pcapng`). It evaluates cryptographic health, identifies protocol downgrade vulnerabilities, and generates forensic-grade audit reports.

---

## 🚀 Key Features

- **Passive PCAP Ingestion**: Parses email protocols (SMTP, IMAP, POP3, and explicit/implicit TLS/STARTTLS) without active network probing.
- **Cryptographic & TLS Analysis**: Audits TLS versions, cipher suites, key exchange mechanisms, and handshake integrity.
- **Certificate Verification**: Analyzes certificate validity, expiration, self-signed status, key strength, and Subject Alternative Names (SAN).
- **Rule & Risk Engine**: Evaluates sessions against security rules to compute real-time risk posture metrics and actionable findings.
- **Forensic Evidence & Session Tracking**: Preserves digital chain of custody with SHA-256 evidence hashing and timeline reconstruction.
- **PDF Report Generation**: Exports comprehensive, auditor-ready forensic reports.
- **Unified Single-Entrypoint**: Serves both FastAPI backend endpoints and the React SPA frontend from a single command.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn, Scapy, Cryptography, ReportLab
- **Frontend**: React 18, TypeScript, Vite, Modern Glassmorphism UI, Lucide Icons
- **Storage**: In-memory forensic state store with JSON persistence

---

## ⚡ Quick Start

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ (for frontend development/builds)

### 2. Setup & Installation
```bash
# Clone the repository
git clone https://github.com/omkar-ingale-17/SecureMailScope.git
cd SecureMailScope
```

### 3. Run the Application
```bash
python app.py
```
- **Web UI**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **API Docs (Swagger UI)**: [http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs)

---

## 🔮 Future Implementation Key Points

- **Live Capture & SPAN/TAP Integration**: Real-time passive packet sniffing on active network interfaces.
- **DNS Authentication Correlation**: Cross-referencing traffic with live/historical SPF, DKIM, and DMARC records.
- **AI/ML Anomaly Detection**: Unsupervised clustering for subtle credential exfiltration patterns and behavioral anomalies.
- **SIEM & Syslog Forwarding**: Direct CEF/Syslog integration for Splunk, Elastic, and Microsoft Sentinel.
- **Multi-Tenant RBAC & Audit Trails**: Role-based access control, team collaboration, and tamper-proof audit logs for enterprise SOCs.
- **Expanded Protocol Support**: Passive inspection for Webmail (HTTP/HTTPS/REST APIs) and Exchange ActiveSync (EAS).

---

## 📄 License
This project is developed for forensic research and cybersecurity posture evaluation.
