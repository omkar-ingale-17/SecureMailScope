import datetime
from typing import List, Dict, Any, Tuple
from ..models.schemas import Finding, EvidenceChainNode

class RulesEngine:
    @staticmethod
    def evaluate_session(
        session: Dict[str, Any],
        evidence_id: str,
        evidence_filename: str,
        finding_counter_start: int = 1
    ) -> Tuple[List[Finding], List[EvidenceChainNode], int, str]:
        """
        Applies deterministic security rules to a captured email session.
        Returns:
            - findings: list of rule violations
            - evidence_chain: chain of custody / forensic inspection nodes
            - risk_score: 0-100 explainable risk score
            - risk_level: SECURE, LOW, MEDIUM, HIGH, CRITICAL
        """
        findings: List[Finding] = []
        f_idx = finding_counter_start
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        net = session["network"]
        tls = session["tls"]
        cert = session["certificate"]
        proto = session["protocol"]
        sess_id = session["session_id"]
        starttls_status = session.get("starttls_status", "NOT_OFFERED")

        # 1. Cleartext / Missing STARTTLS rule
        if not tls["tls_detected"]:
            f = Finding(
                id=f"FND-{f_idx:04d}",
                rule_id="RULE-NET-01-CLEARTEXT",
                severity="CRITICAL",
                title=f"Unencrypted Cleartext {proto} Traffic",
                protocol=proto,
                evidence_id=evidence_id,
                evidence_filename=evidence_filename,
                session_id=sess_id,
                detected_at=now_str,
                status="CONFIRMED",
                description=f"Passive analysis observed raw unencrypted {proto} communication between {net['src_ip']}:{net['src_port']} and {net['dst_ip']}:{net['dst_port']}. No TLS encryption was established.",
                why_it_matters="Authentication credentials, mailbox commands, and email metadata are transmitted in cleartext over the network, subject to interception, credential harvesting, and passive eavesdropping.",
                technical_details=f"Stream observed {net['packet_count']} packets with STARTTLS status: '{starttls_status}'. No TLS record layer handshake was initiated.",
                recommendation=f"Enforce mandatory STARTTLS or direct TLS (Port 465 for SMTPS, 993 for IMAPS, 995 for POP3S). Reject cleartext fallback."
            )
            findings.append(f)
            f_idx += 1

        elif starttls_status == "OFFERED_NOT_UPGRADED":
            f = Finding(
                id=f"FND-{f_idx:04d}",
                rule_id="RULE-NET-02-STARTTLS-DOWNGRADE",
                severity="HIGH",
                title="STARTTLS Offered But Not Negotiated",
                protocol=proto,
                evidence_id=evidence_id,
                evidence_filename=evidence_filename,
                session_id=sess_id,
                detected_at=now_str,
                status="CONFIRMED",
                description=f"Server advertised STARTTLS capability, but negotiation did not complete successfully or was aborted by the client.",
                why_it_matters="Can indicate passive/active STARTTLS stripping attacks (e.g. STRIPTLS) where an adversary removes the STARTTLS capability to force unencrypted transmission.",
                technical_details=f"STARTTLS command/advertisement observed, but TLS session failed to establish properly.",
                recommendation="Enforce MTA-STS (RFC 8461) and DANE (RFC 7672) to require cryptographic TLS negotiation and prevent downgrade attacks."
            )
            findings.append(f)
            f_idx += 1

        # 2. Deprecated TLS Version
        tls_ver = tls["tls_version"]
        if tls["tls_detected"]:
            if "SSL 3.0" in tls_ver or "TLS 1.0" in tls_ver:
                f = Finding(
                    id=f"FND-{f_idx:04d}",
                    rule_id="RULE-CRYPTO-01-DEPRECATED-TLS",
                    severity="CRITICAL",
                    title=f"Prohibited Deprecated Protocol Version: {tls_ver}",
                    protocol=proto,
                    evidence_id=evidence_id,
                    evidence_filename=evidence_filename,
                    session_id=sess_id,
                    detected_at=now_str,
                    status="CONFIRMED",
                    description=f"The session negotiated {tls_ver}, which was deprecated by IETF RFC 8996 due to fundamental vulnerabilities (BEAST, POODLE).",
                    why_it_matters="Legacy versions lack modern cryptographic primitives and have known exploitable flaws allowing session decryption.",
                    technical_details=f"ServerHello / Handshake record negotiated protocol version {tls_ver}.",
                    recommendation="Disable SSLv3, TLS 1.0, and TLS 1.1 in mail transfer agent (MTA) configuration. Require TLS 1.2 as minimum, TLS 1.3 preferred."
                )
                findings.append(f)
                f_idx += 1
            elif "TLS 1.1" in tls_ver:
                f = Finding(
                    id=f"FND-{f_idx:04d}",
                    rule_id="RULE-CRYPTO-02-DEPRECATED-TLS11",
                    severity="HIGH",
                    title="Deprecated Protocol Version: TLS 1.1",
                    protocol=proto,
                    evidence_id=evidence_id,
                    evidence_filename=evidence_filename,
                    session_id=sess_id,
                    detected_at=now_str,
                    status="CONFIRMED",
                    description=f"The session negotiated TLS 1.1, which is formally deprecated by IETF RFC 8996.",
                    why_it_matters="TLS 1.1 relies on weak SHA-1/MD5 combinations in handshakes and lacks modern authenticated encryption (AEAD).",
                    technical_details=f"Negotiated version: TLS 1.1.",
                    recommendation="Configure TLS minimum protocol to TLS 1.2 across all inbound and outbound mail gateways."
                )
                findings.append(f)
                f_idx += 1

        # 3. Weak Cipher Suite
        cipher = tls.get("cipher_suite", "")
        if "RC4" in cipher or "3DES" in cipher or "DES" in cipher or "NULL" in cipher:
            f = Finding(
                id=f"FND-{f_idx:04d}",
                rule_id="RULE-CRYPTO-03-WEAK-CIPHER",
                severity="CRITICAL",
                title=f"Weak/Prohibited Cipher Suite: {cipher}",
                protocol=proto,
                evidence_id=evidence_id,
                evidence_filename=evidence_filename,
                session_id=sess_id,
                detected_at=now_str,
                status="CONFIRMED",
                description=f"Session utilized obsolete or broken cipher suite ({cipher}).",
                why_it_matters="Vulnerable to cryptanalytic attacks (e.g. Sweet32 for 3DES, biases in RC4 keystream).",
                technical_details=f"Cipher Code: {tls.get('cipher_code', 'Unknown')}. Cipher Suite: {cipher}.",
                recommendation="Remove RC4, 3DES, and DES from cipher configuration. Enforce AES-GCM or CHACHA20-POLY1305."
            )
            findings.append(f)
            f_idx += 1
        elif "CBC" in cipher and "SHA" in cipher:
            f = Finding(
                id=f"FND-{f_idx:04d}",
                rule_id="RULE-CRYPTO-04-CBC-SHA1",
                severity="MEDIUM",
                title=f"Legacy CBC Mode Cipher with SHA-1: {cipher}",
                protocol=proto,
                evidence_id=evidence_id,
                evidence_filename=evidence_filename,
                session_id=sess_id,
                detected_at=now_str,
                status="CONFIRMED",
                description=f"Cipher suite {cipher} uses Cipher Block Chaining (CBC) with SHA-1 MAC.",
                why_it_matters="CBC modes are prone to padding oracle vulnerabilities (Lucky Thirteen, Zombie POODLE), and SHA-1 collision resistance is broken.",
                technical_details=f"Cipher: {cipher}. MAC: SHA1. Mode: CBC.",
                recommendation="Prioritize AEAD ciphers (AES-GCM, ChaCha20-Poly1305) over CBC-mode ciphers."
            )
            findings.append(f)
            f_idx += 1

        # 4. Lack of Forward Secrecy
        if tls["tls_detected"] and tls["forward_secrecy"] == "NOT SUPPORTED":
            f = Finding(
                id=f"FND-{f_idx:04d}",
                rule_id="RULE-CRYPTO-05-NO-PFS",
                severity="MEDIUM",
                title="Absence of Perfect Forward Secrecy (PFS)",
                protocol=proto,
                evidence_id=evidence_id,
                evidence_filename=evidence_filename,
                session_id=sess_id,
                detected_at=now_str,
                status="CONFIRMED",
                description="Session negotiated static RSA key exchange without ephemeral Diffie-Hellman (ECDHE/DHE).",
                why_it_matters="If the server's long-term RSA private key is compromised in the future, all historically recorded PCAP sessions can be decrypted in retrospect.",
                technical_details=f"Key Exchange: {tls['key_exchange']}. Forward Secrecy: NOT SUPPORTED.",
                recommendation="Configure mail server to require ephemeral key exchange (ECDHE) for all TLS connections."
            )
            findings.append(f)
            f_idx += 1

        # 5. Certificate Findings
        if cert.get("certificate_status") == "EXPIRED":
            f = Finding(
                id=f"FND-{f_idx:04d}",
                rule_id="RULE-CERT-01-EXPIRED",
                severity="HIGH",
                title=f"Expired X.509 Certificate in {proto} Session",
                protocol=proto,
                evidence_id=evidence_id,
                evidence_filename=evidence_filename,
                session_id=sess_id,
                detected_at=now_str,
                status="CONFIRMED",
                description=f"The presented certificate expired on {cert['valid_until']}.",
                why_it_matters="Expired certificates break trust chains and may cause connecting MTAs or mail clients to reject connections or bypass verification.",
                technical_details=f"Subject: {cert['subject']}. Valid Until: {cert['valid_until']}.",
                recommendation="Renew the certificate and implement automated renewal (ACME / Let's Encrypt or enterprise PKI monitoring)."
            )
            findings.append(f)
            f_idx += 1
        elif cert.get("certificate_status") == "NOT_YET_VALID":
            f = Finding(
                id=f"FND-{f_idx:04d}",
                rule_id="RULE-CERT-02-NOT-YET-VALID",
                severity="HIGH",
                title="Certificate Not Yet Valid",
                protocol=proto,
                evidence_id=evidence_id,
                evidence_filename=evidence_filename,
                session_id=sess_id,
                detected_at=now_str,
                status="CONFIRMED",
                description=f"The certificate validity begins at {cert['valid_from']}, which is in the future.",
                why_it_matters="Indicates either system clock skew on the capture host/server or premature certificate deployment.",
                technical_details=f"Subject: {cert['subject']}. Valid From: {cert['valid_from']}.",
                recommendation="Verify server system time synchronization via NTP and certificate activation timestamp."
            )
            findings.append(f)
            f_idx += 1

        if cert.get("certificate_status") == "WEAK_KEY":
            f = Finding(
                id=f"FND-{f_idx:04d}",
                rule_id="RULE-CERT-03-WEAK-KEY",
                severity="HIGH",
                title=f"Weak Public Key Length: {cert.get('key_length')}",
                protocol=proto,
                evidence_id=evidence_id,
                evidence_filename=evidence_filename,
                session_id=sess_id,
                detected_at=now_str,
                status="CONFIRMED",
                description=f"The certificate uses an RSA key size of {cert.get('key_length')}, below the recommended 2048-bit minimum.",
                why_it_matters="RSA 1024-bit keys can be factored with state-level or modest cloud computing resources, allowing certificate spoofing and MITM attacks.",
                technical_details=f"Algorithm: {cert['public_key_algorithm']}, Key Length: {cert['key_length']}.",
                recommendation="Reissue certificate with RSA 2048-bit minimum or 256-bit ECDSA (P-256)."
            )
            findings.append(f)
            f_idx += 1

        if cert.get("certificate_status") == "WEAK_SIGNATURE":
            f = Finding(
                id=f"FND-{f_idx:04d}",
                rule_id="RULE-CERT-04-WEAK-SIG",
                severity="HIGH",
                title=f"Weak Certificate Signature Algorithm: {cert.get('signature_algorithm')}",
                protocol=proto,
                evidence_id=evidence_id,
                evidence_filename=evidence_filename,
                session_id=sess_id,
                detected_at=now_str,
                status="CONFIRMED",
                description=f"Certificate was signed using deprecated digest algorithm ({cert.get('signature_algorithm')}).",
                why_it_matters="Hash collision vulnerabilities enable adversaries to forge certificates matching the signature.",
                technical_details=f"Signature Algorithm: {cert.get('signature_algorithm')}.",
                recommendation="Replace certificate with one signed by SHA-256 or stronger."
            )
            findings.append(f)
            f_idx += 1

        if cert.get("is_self_signed"):
            f = Finding(
                id=f"FND-{f_idx:04d}",
                rule_id="RULE-CERT-05-SELF-SIGNED",
                severity="LOW",
                title="Self-Signed Certificate Observed",
                protocol=proto,
                evidence_id=evidence_id,
                evidence_filename=evidence_filename,
                session_id=sess_id,
                detected_at=now_str,
                status="CONFIRMED",
                description="The presented certificate is self-signed rather than issued by a trusted public Certificate Authority.",
                why_it_matters="Self-signed certificates cannot be validated by external mail relays unless pinned via TLSA (DANE).",
                technical_details=f"Issuer matches Subject: {cert['subject']}.",
                recommendation="Deploy certificates signed by a recognized public CA or establish DANE TLSA records."
            )
            findings.append(f)
            f_idx += 1

        # Calculate session risk score (0 - 100)
        risk_score = 0
        has_critical = False
        has_high = False
        has_med = False

        for f in findings:
            if f.severity == "CRITICAL":
                risk_score += 40
                has_critical = True
            elif f.severity == "HIGH":
                risk_score += 25
                has_high = True
            elif f.severity == "MEDIUM":
                risk_score += 12
                has_med = True
            elif f.severity == "LOW":
                risk_score += 5

        risk_score = min(100, risk_score)

        # Redefined Risk Categories:
        # Low risk: 0 to 20
        # Medium risk: 21 to 40
        # High risk: 41 to 60
        # Critical: above 60
        if risk_score > 60:
            risk_level = "CRITICAL"
        elif risk_score >= 41:
            risk_level = "HIGH"
        elif risk_score >= 21:
            risk_level = "MEDIUM"
        elif risk_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "SECURE"

        # Construct Evidence Chain (10 inspectable nodes as specified in prompt)
        chain = RulesEngine._build_evidence_chain(session, findings, risk_score, risk_level, evidence_filename)

        return findings, chain, risk_score, risk_level

    @staticmethod
    def _build_evidence_chain(
        session: Dict[str, Any],
        findings: List[Finding],
        risk_score: int,
        risk_level: str,
        evidence_filename: str
    ) -> List[EvidenceChainNode]:
        net = session["network"]
        tls = session["tls"]
        cert = session["certificate"]
        proto = session["protocol"]
        starttls_status = session.get("starttls_status", "NOT_OFFERED")

        # 1. PCAP
        pcap_status = "neutral"
        pcap_node = EvidenceChainNode(
            step="PCAP",
            title="PCAP Capture Source",
            status=pcap_status,
            details=f"Extracted from forensic capture '{evidence_filename}'",
            technical_props={
                "evidence_file": evidence_filename,
                "packet_count": net["packet_count"],
                "duration": f"{net['session_duration']}s",
                "start_time": net["start_time"],
                "end_time": net["end_time"],
            }
        )

        # 2. TCP STREAM
        tcp_node = EvidenceChainNode(
            step="TCP_STREAM",
            title=f"TCP Stream ({net['src_ip']}:{net['src_port']} -> {net['dst_ip']}:{net['dst_port']})",
            status="neutral",
            details="Passive 5-tuple TCP reconstruction",
            technical_props={
                "client_endpoint": f"{net['src_ip']}:{net['src_port']}",
                "server_endpoint": f"{net['dst_ip']}:{net['dst_port']}",
                "packets_observed": net["packet_count"],
                "flow_duration_sec": net["session_duration"]
            }
        )

        # 3. EMAIL PROTOCOL
        proto_status = "secure" if tls["tls_detected"] else "critical"
        email_proto_node = EvidenceChainNode(
            step="EMAIL_PROTOCOL",
            title=f"{proto} Session Detected",
            status=proto_status,
            details=f"Application protocol: {proto}",
            technical_props={
                "protocol": proto,
                "server_port": net["dst_port"],
                "cleartext_exposure": not tls["tls_detected"]
            }
        )

        # 4. STARTTLS
        st_status = "neutral"
        st_desc = "Direct TLS Port"
        if starttls_status == "OFFERED_AND_ACCEPTED":
            st_status = "secure"
            st_desc = "STARTTLS Offered & Negotiated"
        elif starttls_status == "OFFERED_NOT_UPGRADED":
            st_status = "warning"
            st_desc = "STARTTLS Offered But Not Upgraded"
        elif starttls_status == "NOT_OFFERED":
            st_status = "critical" if not tls["tls_detected"] else "neutral"
            st_desc = "STARTTLS Not Offered"

        starttls_node = EvidenceChainNode(
            step="STARTTLS",
            title=f"STARTTLS: {st_desc}",
            status=st_status,
            details=f"Negotiation status: {starttls_status}",
            technical_props={
                "detected": session.get("starttls_detected", False),
                "status": starttls_status
            }
        )

        # 5. TLS HANDSHAKE
        tls_status = "neutral"
        if not tls["tls_detected"]:
            tls_status = "critical"
            tls_desc = "No TLS Handshake (Cleartext)"
        elif "SSL 3.0" in tls["tls_version"] or "TLS 1.0" in tls["tls_version"]:
            tls_status = "critical"
            tls_desc = f"Handshake with {tls['tls_version']}"
        elif "TLS 1.1" in tls["tls_version"]:
            tls_status = "warning"
            tls_desc = f"Handshake with {tls['tls_version']}"
        else:
            tls_status = "secure"
            tls_desc = f"Handshake: {tls['tls_version']}"

        tls_handshake_node = EvidenceChainNode(
            step="TLS_HANDSHAKE",
            title=tls_desc,
            status=tls_status,
            details=f"TLS Record Layer Version: {tls['tls_version']}",
            technical_props={
                "version": tls["tls_version"],
                "handshake_status": tls["handshake_status"],
                "sni": tls["sni"],
                "alpn": tls["alpn"]
            }
        )

        # 6. CERTIFICATE
        cert_status_val = cert.get("certificate_status", "NOT OBSERVABLE")
        if cert_status_val == "VALID":
            c_status = "secure"
        elif cert_status_val in ("EXPIRED", "NOT_YET_VALID", "WEAK_KEY"):
            c_status = "critical"
        elif cert_status_val in ("WEAK_SIGNATURE", "SELF_SIGNED"):
            c_status = "warning"
        else:
            c_status = "neutral"

        cert_node = EvidenceChainNode(
            step="CERTIFICATE",
            title=f"Certificate: {cert_status_val}",
            status=c_status,
            details=f"Subject: {cert.get('subject', 'NOT OBSERVABLE')}",
            technical_props={
                "subject": cert.get("subject", "NOT OBSERVABLE"),
                "issuer": cert.get("issuer", "NOT OBSERVABLE"),
                "valid_until": cert.get("valid_until", "NOT OBSERVABLE"),
                "status": cert_status_val,
                "san": cert.get("san_list", [])
            }
        )

        # 7. CRYPTOGRAPHIC PROPERTY
        crypto_status = "secure"
        cipher = tls.get("cipher_suite", "NOT OBSERVABLE")
        if "RC4" in cipher or "3DES" in cipher or "NULL" in cipher:
            crypto_status = "critical"
        elif "CBC" in cipher or tls.get("forward_secrecy") == "NOT SUPPORTED":
            crypto_status = "warning"
        elif not tls["tls_detected"]:
            crypto_status = "critical"

        crypto_node = EvidenceChainNode(
            step="CRYPTOGRAPHIC_PROPERTY",
            title=f"Crypto: {cipher[:32] if cipher != 'NOT OBSERVABLE' else 'No Encryption'}",
            status=crypto_status,
            details=f"Cipher: {cipher} | PFS: {tls['forward_secrecy']}",
            technical_props={
                "cipher_suite": cipher,
                "key_exchange": tls["key_exchange"],
                "forward_secrecy": tls["forward_secrecy"],
                "key_length": cert.get("key_length", "NOT OBSERVABLE"),
                "signature_algo": cert.get("signature_algorithm", "NOT OBSERVABLE")
            }
        )

        # 8. SECURITY FINDING
        find_status = "secure" if not findings else ("critical" if any(f.severity == "CRITICAL" for f in findings) else "warning")
        finding_titles = [f.title for f in findings]
        finding_node = EvidenceChainNode(
            step="SECURITY_FINDING",
            title=f"{len(findings)} Finding(s) Detected" if findings else "Zero Rule Violations",
            status=find_status,
            details=" | ".join(finding_titles) if findings else "Deterministic rule engine passed without violations",
            technical_props={
                "rule_violations": [f.rule_id for f in findings],
                "finding_count": len(findings)
            }
        )

        # 9. RISK
        risk_node = EvidenceChainNode(
            step="RISK",
            title=f"Risk Score: {risk_score}/100 ({risk_level})",
            status="critical" if risk_level in ("CRITICAL", "HIGH") else ("warning" if risk_level == "MEDIUM" else "secure"),
            details=f"Explainable posture calculated as {risk_level}",
            technical_props={
                "score": risk_score,
                "severity": risk_level
            }
        )

        # 10. RECOMMENDATION
        rec_text = "Traffic satisfies baseline forensic requirements."
        if findings:
            rec_text = findings[0].recommendation

        rec_node = EvidenceChainNode(
            step="RECOMMENDATION",
            title="Forensic Remediation Action",
            status="neutral",
            details=rec_text,
            technical_props={
                "primary_action": rec_text,
                "all_recs": [f.recommendation for f in findings]
            }
        )

        return [
            pcap_node,
            tcp_node,
            email_proto_node,
            starttls_node,
            tls_handshake_node,
            cert_node,
            crypto_node,
            finding_node,
            risk_node,
            rec_node
        ]
