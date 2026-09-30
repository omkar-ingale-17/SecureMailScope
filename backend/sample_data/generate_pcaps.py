import struct
import socket
import datetime
from typing import Dict
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def create_pcap_bytes(packets_data) -> bytes:
    """
    Packs a list of (timestamp_float, raw_eth_packet) into a standard libpcap binary format.
    """
    # Global header (24 bytes)
    # magic=0xa1b2c3d4 (little-endian), ver_major=2, ver_minor=4, thiszone=0, sigfigs=0, snaplen=65535, linktype=1 (Ethernet)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body = bytearray(global_hdr)

    for ts, pkt in packets_data:
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1e6)
        pkt_len = len(pkt)
        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)
        body.extend(pkt_hdr)
        body.extend(pkt)

    return bytes(body)

def make_eth_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    # Ethernet header (14 bytes)
    dst_mac = b"\x00\x15\x5d\x12\x34\x56"
    src_mac = b"\x00\x15\x5d\xab\xcd\xef"
    eth_type = struct.pack("!H", 0x0800)  # IPv4
    eth_hdr = dst_mac + src_mac + eth_type

    # TCP header (20 bytes)
    data_offset = 5  # 5 * 4 = 20 bytes
    offset_flags = (data_offset << 12) | flags
    tcp_hdr = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, 64240, 0, 0)

    # IP header (20 bytes)
    total_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version 4, IHL 5
        0,     # DSCP/ECN
        total_len,
        54321, # ID
        0x4000,# Don't Fragment
        64,    # TTL
        6,     # Protocol: TCP
        0,     # Checksum
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )

    return eth_hdr + ip_hdr + tcp_hdr + payload

def generate_test_cert_der(expired: bool = False, weak_key: bool = False, cn: str = "mail.internal.corp") -> bytes:
    key_size = 1024 if weak_key else 2048
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Forensic Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    if expired:
        not_before = now - datetime.timedelta(days=400)
        not_after = now - datetime.timedelta(days=35)
    else:
        not_before = now - datetime.timedelta(days=10)
        not_after = now + datetime.timedelta(days=365)

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_before
    ).not_valid_after(
        not_after
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName(f"mx.{cn}")]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    return cert.public_bytes(serialization.Encoding.DER)

def build_tls_handshake(version_code: int, cipher_code: int, cert_der: bytes) -> bytes:
    # ServerHello body: ver(2), random(32), sess_id_len(1), cs(2), comp(1)
    sh_body = struct.pack("!H32sBHB", version_code, b"\x01"*32, 0, cipher_code, 0)
    sh_msg = struct.pack("!B", 2) + struct.pack("!I", len(sh_body))[1:] + sh_body

    # Certificate body: total_len(3), cert_len(3), cert_bytes
    cert_body = struct.pack("!I", len(cert_der))[1:] + cert_der
    certs_msg_body = struct.pack("!I", len(cert_body))[1:] + cert_body
    certs_msg = struct.pack("!B", 11) + struct.pack("!I", len(certs_msg_body))[1:] + certs_msg_body

    handshake_payload = sh_msg + certs_msg

    # TLS Record Header: type=22 (Handshake), version, length
    record_hdr = struct.pack("!BHH", 22, version_code, len(handshake_payload))
    return record_hdr + handshake_payload

def generate_sample_pcaps() -> Dict[str, bytes]:
    pcaps = {}

    # Sample 1: Enterprise Exchange SMTP with STARTTLS (Modern TLS 1.3 / Valid Cert)
    t0 = 1700000000.0
    cert1 = generate_test_cert_der(expired=False, weak_key=False, cn="mail.enterprise-corp.net")
    tls_hs1 = build_tls_handshake(0x0303, 0xC030, cert1)  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

    pkts1 = [
        (t0 + 0.01, make_eth_tcp_packet("192.168.10.45", "10.0.1.25", 49152, 25, 1, 1, 0x18, b"220 mail.enterprise-corp.net ESMTP Postfix\r\n")),
        (t0 + 0.03, make_eth_tcp_packet("10.0.1.25", "192.168.10.45", 25, 49152, 1, 1, 0x18, b"EHLO client.internal.lan\r\n")),
        (t0 + 0.05, make_eth_tcp_packet("192.168.10.45", "10.0.1.25", 49152, 25, 1, 1, 0x18, b"250-mail.enterprise-corp.net\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")),
        (t0 + 0.07, make_eth_tcp_packet("10.0.1.25", "192.168.10.45", 25, 49152, 1, 1, 0x18, b"STARTTLS\r\n")),
        (t0 + 0.09, make_eth_tcp_packet("192.168.10.45", "10.0.1.25", 49152, 25, 1, 1, 0x18, b"220 2.0.0 Ready to start TLS\r\n")),
        (t0 + 0.12, make_eth_tcp_packet("10.0.1.25", "192.168.10.45", 25, 49152, 1, 1, 0x18, tls_hs1)),
    ]
    pcaps["smtp_starttls_valid_tls12.pcap"] = create_pcap_bytes(pkts1)

    # Sample 2: Vulnerable Legacy IMAP with Deprecated TLS 1.0, 3DES Cipher & Expired Cert
    t1 = 1700001000.0
    cert2 = generate_test_cert_der(expired=True, weak_key=True, cn="imap.legacy-mail.org")
    tls_hs2 = build_tls_handshake(0x0301, 0x000A, cert2)  # TLS 1.0, 3DES cipher (Sweet32)

    pkts2 = [
        (t1 + 0.01, make_eth_tcp_packet("192.168.20.88", "10.0.2.143", 53120, 143, 1, 1, 0x18, b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE STARTTLS LOGINDISABLED] Dovecot ready.\r\n")),
        (t1 + 0.04, make_eth_tcp_packet("10.0.2.143", "192.168.20.88", 143, 53120, 1, 1, 0x18, b". STARTTLS\r\n")),
        (t1 + 0.06, make_eth_tcp_packet("192.168.20.88", "10.0.2.143", 53120, 143, 1, 1, 0x18, b". OK Begin TLS negotiation now.\r\n")),
        (t1 + 0.09, make_eth_tcp_packet("10.0.2.143", "192.168.20.88", 143, 53120, 1, 1, 0x18, tls_hs2)),
    ]
    pcaps["imap_deprecated_tls10_3des_expired.pcap"] = create_pcap_bytes(pkts2)

    # Sample 3: Cleartext Insecure POP3 Session with Plaintext Authentication
    t2 = 1700002000.0
    pkts3 = [
        (t2 + 0.01, make_eth_tcp_packet("172.16.5.12", "10.0.3.110", 41200, 110, 1, 1, 0x18, b"+OK POP3 server ready <1896.69708@mail.unencrypted-lan.org>\r\n")),
        (t2 + 0.03, make_eth_tcp_packet("10.0.3.110", "172.16.5.12", 110, 41200, 1, 1, 0x18, b"USER analyst_jdoe\r\n")),
        (t2 + 0.05, make_eth_tcp_packet("172.16.5.12", "10.0.3.110", 41200, 110, 1, 1, 0x18, b"+OK USER jdoe valid, send password\r\n")),
        (t2 + 0.07, make_eth_tcp_packet("10.0.3.110", "172.16.5.12", 110, 41200, 1, 1, 0x18, b"PASS SuperSecret2026!\r\n")),
        (t2 + 0.09, make_eth_tcp_packet("172.16.5.12", "10.0.3.110", 41200, 110, 1, 1, 0x18, b"+OK Mailbox open, 3 messages\r\n")),
    ]
    pcaps["pop3_insecure_cleartext.pcap"] = create_pcap_bytes(pkts3)

    return pcaps
