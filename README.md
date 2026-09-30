# SecureMailScope 🛡️🔍
> **Passive Network Email Forensics & Cryptographic Security Posture System**

[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB.svg?logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Vite](https://img.shields.io/badge/Vite-8.x-646CFF.svg?logo=vite&logoColor=white)](https://vitejs.dev)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📌 Overview

**SecureMailScope** is a passive network email forensics and cryptographic risk assessment platform. It inspects raw network packet captures (**PCAP / PCAPNG / CAP**) to evaluate the security and cryptographic posture of email transport protocols (**SMTP, IMAP, POP3**, and their **TLS/SSL** encrypted channels).

Operating in **strict passive forensic mode**, SecureMailScope performs zero packet injection or active probing—ensuring zero operational footprint and maintaining evidentiary integrity for digital forensic investigations and compliance audits.

```
                  +-----------------------------------+
                  |   Raw Packet Captures (.pcap)     |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  |  Native PCAP / PCAPNG Parser      |
                  |  (TCP Stream Reconstruction)      |
                  +-----------------+-----------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
            v                                               v
+-----------------------+                       +-----------------------+
|  Email Protocol Engine|                       | TLS & PKI Analyzer    |
| (SMTP / IMAP / POP3)  |                       | (Handshakes & X.509)  |
+-----------+-----------+                       +-----------+-----------+
            |                                               |
            +-----------------------+-----------------------+
                                    |
                                    v
                  +-----------------------------------+
                  | Deterministic Security Rule Engine|
                  |     & Explainable Risk Engine     |
                  +-----------------+-----------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
            v                                               v
+-----------------------+                       +-----------------------+
| Interactive React SPA |                       | Forensic PDF / HTML / |
|   Cyber Dashboard     |                       | JSON Executive Reports|
+-----------------------+                       +-----------------------+
```

---

## ✨ Key Features

- 🕵️ **Strict Passive Analysis**: Pure offline/passive analysis of PCAP & PCAPNG binary captures without active network probing or scanning.
- 📦 **Native Binary Packet Parsing**: Built-in Python binary decoder for Classic PCAP (microsecond & nanosecond timestamps) and PCAPNG format with TCP stream reassembly and port-agnostic protocol detection.
- 🔐 **Cryptographic & TLS Inspector**:
  - Full TLS Record Layer and Handshake Protocol dissection.
  - Identification of TLS versions (SSL 2.0/3.0, TLS 1.0, 1.1, 1.2, 1.3).
  - Cipher suite enumeration, key exchange mechanism verification, and Perfect Forward Secrecy (PFS / DHE / ECDHE) auditing.
- 📜 **X.509 Certificate Forensics**:
  - DER certificate extraction and public key analysis (RSA, ECC, DSA, Ed25519).
  - Validation of validity windows (expired / not-yet-valid).
  - Self-signed certificate identification, SAN (Subject Alternative Names) inspection, and SHA-256 fingerprinting.
- ⚠️ **STARTTLS & Downgrade Attack Detection**:
  - Tracks plaintext command exchanges (e.g. `EHLO`, `STARTTLS`, `STLS`, `CAPA`).
  - Flags plaintext credential transmissions and STARTTLS stripping/downgrade scenarios.
- 📊 **Explainable Risk Scoring (0–100)**:
  - Transparent mathematical scoring model detailing exact contributing factors and penalty points.
- 🔗 **Evidence Chain of Custody**:
  - Step-by-step forensic progression nodes documenting packet-level findings and evidentiary integrity.
- 📑 **Publication-Ready Forensic Reports**:
  - One-click export to **PDF** (via ReportLab styling), standalone **HTML**, and structured **JSON**.
- 🚀 **Unified Single-Entrypoint Architecture**:
  - Run the entire stack (FastAPI backend + React 19 SPA) seamlessly via `python app.py`.

---

## 🛡️ Protocol & Rule Coverage

| Protocol | Default Ports | Secure Transport | Forensic Checks |
| :--- | :--- | :--- | :--- |
| **SMTP** | 25, 587 | SMTPS (465) / STARTTLS | Plaintext AUTH, STARTTLS stripping, Cleartext relay |
| **IMAP** | 143 | IMAPS (993) / STARTTLS | Cleartext LOGIN, Unencrypted mailbox synchronization |
| **POP3** | 110 | POP3S (995) / STLS | Cleartext USER/PASS commands, Insecure mailbox polling |
| **TLS** | All standard ports | TLS 1.2 / TLS 1.3 | Deprecated protocols, Insecure ciphers, Missing PFS |

### Core Security Rules

- `RULE-NET-01-CLEARTEXT`: Raw unencrypted email traffic transmitted in cleartext.
- `RULE-NET-02-STARTTLS-DOWNGRADE`: STARTTLS capability offered but not negotiated/upgraded.
- `RULE-TLS-01-DEPRECATED-VERSION`: Usage of obsolete cryptographic protocols (SSL 3.0, TLS 1.0, TLS 1.1).
- `RULE-TLS-02-WEAK-CIPHER`: Usage of broken ciphers (RC4, 3DES, DES, EXPORT, NULL).
- `RULE-TLS-03-NO-PFS`: Key exchange lacks Perfect Forward Secrecy (static RSA).
- `RULE-CERT-01-EXPIRED`: Expired or not-yet-valid X.509 server certificate.
- `RULE-CERT-02-SELF-SIGNED`: Untrusted or self-signed certificate in email transport.
- `RULE-CERT-03-WEAK-KEY`: Weak public key length (e.g., RSA < 2048-bit).
- `RULE-CERT-04-WEAK-SIGNATURE`: Deprecated hashing algorithm in signature (MD5, SHA-1).

---

## 📂 Project Structure

```
SecureMailScope/
├── app.py                          # Unified single-entrypoint application runner
├── .gitignore                      # Comprehensive Git exclusion rules
├── README.md                       # Documentation & usage guide
│
├── backend/                        # Backend Python package
│   ├── __init__.py
│   ├── storage.py                  # In-memory & disk state persistence layer
│   ├── test_pipeline.py            # Diagnostic & forensic pipeline test suite
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py              # Pydantic data models & telemetry schemas
│   └── forensics/
│       ├── __init__.py
│       ├── pcap_parser.py          # Binary PCAP/PCAPNG packet parser & stream reassembler
│       ├── tls_analyzer.py         # TLS Record Layer & cipher suite decoder
│       ├── cert_analyzer.py        # X.509 DER certificate extractor (PyCA Cryptography)
│       ├── rules_engine.py         # Deterministic security rule & finding evaluator
│       ├── risk_engine.py          # Mathematical explainable risk posture engine
│       └── report_generator.py     # PDF (ReportLab), HTML, and JSON report builder
│
└── frontend/                       # Modern React + Vite SPA
    ├── package.json
    ├── tsconfig.json
    ├── vite.config.ts
    ├── index.html
    └── src/
        ├── main.tsx
        ├── App.tsx                 # Root layout, navigation & status header
        ├── App.css
        ├── index.css               # Futuristic cybersecurity design system
        ├── pages/
        │   ├── OverviewPage.tsx    # Dashboard with risk distribution & charts
        │   ├── EvidencePage.tsx    # Evidence upload & capture registration
        │   ├── SessionsPage.tsx    # Email sessions grid with multi-filtering
        │   ├── FindingsPage.tsx    # Security findings triage & remediation advisories
        │   ├── RiskPage.tsx        # Risk posture analysis & score breakdowns
        │   ├── ReportsPage.tsx     # Report generation & download center
        │   └── SettingsPage.tsx    # System diagnostics & forensic mode indicators
        └── services/
            └── api.ts              # Typed API communication service
```

---

## ⚡ Getting Started

### Prerequisites

- **Python**: Version `3.10` or higher
- **Node.js**: Version `18.x` or higher (for frontend build)
- **Git**

---

### 1. Clone the Repository

```bash
git clone https://github.com/omkar-ingale-17/SecureMailScope.git
cd SecureMailScope
```

---

### 2. Set Up Python Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Windows (cmd.exe):
.\venv\Scripts\activate.bat
# Linux / macOS:
source venv/bin/activate

# Install backend dependencies
pip install fastapi uvicorn pydantic cryptography reportlab
```

---

### 3. Build the Frontend

```bash
cd frontend
npm install
npm run build
cd ..
```

---

### 4. Launch SecureMailScope

Run the unified single-entrypoint runner:

```bash
python app.py
```

- **Frontend Application**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/) *(automatically opens in your browser)*
- **REST API Base**: [http://127.0.0.1:8000/api](http://127.0.0.1:8000/api)
- **Interactive API Docs (Swagger UI)**: [http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs)
- **OpenAPI JSON**: [http://127.0.0.1:8000/api/openapi.json](http://127.0.0.1:8000/api/openapi.json)

---

## 🛠️ Development Mode (Optional)

If you are actively making changes to the frontend UI with instant Hot Module Replacement (HMR):

1. **Start Backend Server**:
   ```bash
   uvicorn app:app --host 127.0.0.1 --port 8000 --reload
   ```

2. **Start Vite Dev Server** (in a separate terminal):
   ```bash
   cd frontend
   npm run dev
   ```
   *Vite dev server will run on `http://localhost:5173/` and proxy API calls to port `8000`.*

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health, operation mode, and forensic integrity status |
| `GET` | `/api/overview` | High-level metrics, risk distributions, and recent telemetry |
| `POST` | `/api/evidence/upload` | Upload and register PCAP/PCAPNG evidence for forensic analysis |
| `GET` | `/api/evidence` | List all registered evidence captures |
| `GET` | `/api/evidence/{id}` | Retrieve details of a specific evidence record |
| `POST` | `/api/evidence/{id}/analyze`| Trigger / re-run passive forensic analysis on an evidence item |
| `DELETE`| `/api/evidence/{id}` | Remove an evidence capture and its associated sessions |
| `POST` | `/api/evidence/clear-all` | Clear all evidence captures and reset forensic database |
| `GET` | `/api/sessions` | Query email sessions (supports protocol, risk, TLS, and search filters) |
| `GET` | `/api/sessions/{id}` | Deep session view with evidence chain of custody and packet details |
| `GET` | `/api/findings` | List all detected security findings and rule violations |
| `GET` | `/api/findings/{id}` | Retrieve detailed finding description, impact, and remediation |
| `GET` | `/api/risk-posture` | Explainable risk posture, aggregate score, and penalty factors |
| `GET` | `/api/reports` | List generated forensic audit reports |
| `GET` | `/api/reports/{id}/view` | View standalone HTML or JSON report in browser |
| `GET` | `/api/reports/{id}/download`| Download report as formatted **PDF**, **HTML**, or **JSON** |
| `GET` | `/api/settings/status` | System specifications, engine status, and engine version |

---

## 🧪 Forensic Pipeline Verification

Run the built-in diagnostic test pipeline:

```bash
python backend/test_pipeline.py
```

This verifies:
1. Health endpoint response.
2. Overview telemetry aggregation.
3. Evidence registration and SHA-256 integrity verification.
4. TCP stream reassembly & protocol identification.
5. TLS record dissection & cipher suite extraction.
6. X.509 certificate chain validation.
7. Finding generation across severity levels.
8. Explainable risk calculation.
9. Multi-format report compilation (PDF & HTML).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## ⚠️ Disclaimer

SecureMailScope is designed for legitimate cybersecurity defense, compliance auditing, and authorized digital forensics investigation. Always obtain proper authorization before capturing or analyzing network communications.
