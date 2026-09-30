import struct
from typing import Dict, List, Optional, Tuple, Any

CIPHER_SUITES_MAP: Dict[int, Dict[str, Any]] = {
    # TLS 1.3
    0x1301: {"name": "TLS_AES_128_GCM_SHA256", "version": "TLS 1.3", "kex": "ECDHE/X25519", "auth": "ANY", "enc": "AES-128-GCM", "mac": "AEAD", "pfs": True, "weak": False},
    0x1302: {"name": "TLS_AES_256_GCM_SHA384", "version": "TLS 1.3", "kex": "ECDHE/X25519", "auth": "ANY", "enc": "AES-256-GCM", "mac": "AEAD", "pfs": True, "weak": False},
    0x1303: {"name": "TLS_CHACHA20_POLY1305_SHA256", "version": "TLS 1.3", "kex": "ECDHE/X25519", "auth": "ANY", "enc": "CHACHA20-POLY1305", "mac": "AEAD", "pfs": True, "weak": False},
    # TLS 1.2 modern
    0xC02F: {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "version": "TLS 1.2", "kex": "ECDHE", "auth": "RSA", "enc": "AES-128-GCM", "mac": "AEAD", "pfs": True, "weak": False},
    0xC030: {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "version": "TLS 1.2", "kex": "ECDHE", "auth": "RSA", "enc": "AES-256-GCM", "mac": "AEAD", "pfs": True, "weak": False},
    0xC02B: {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "version": "TLS 1.2", "kex": "ECDHE", "auth": "ECDSA", "enc": "AES-128-GCM", "mac": "AEAD", "pfs": True, "weak": False},
    0xC02C: {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "version": "TLS 1.2", "kex": "ECDHE", "auth": "ECDSA", "enc": "AES-256-GCM", "mac": "AEAD", "pfs": True, "weak": False},
    0xCCA8: {"name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "version": "TLS 1.2", "kex": "ECDHE", "auth": "RSA", "enc": "CHACHA20-POLY1305", "mac": "AEAD", "pfs": True, "weak": False},
    0x009E: {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "version": "TLS 1.2", "kex": "DHE", "auth": "RSA", "enc": "AES-128-GCM", "mac": "AEAD", "pfs": True, "weak": False},
    0x009F: {"name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "version": "TLS 1.2", "kex": "DHE", "auth": "RSA", "enc": "AES-256-GCM", "mac": "AEAD", "pfs": True, "weak": False},
    # CBC mode (older / weak forward secrecy or mac-then-encrypt)
    0xC013: {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "version": "TLS 1.2", "kex": "ECDHE", "auth": "RSA", "enc": "AES-128-CBC", "mac": "SHA1", "pfs": True, "weak": True, "weak_reason": "CBC mode with SHA-1 MAC"},
    0xC014: {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "version": "TLS 1.2", "kex": "ECDHE", "auth": "RSA", "enc": "AES-256-CBC", "mac": "SHA1", "pfs": True, "weak": True, "weak_reason": "CBC mode with SHA-1 MAC"},
    0x002F: {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "version": "TLS 1.0", "kex": "RSA", "auth": "RSA", "enc": "AES-128-CBC", "mac": "SHA1", "pfs": False, "weak": True, "weak_reason": "No Forward Secrecy (static RSA key exchange) & SHA-1 MAC"},
    0x0035: {"name": "TLS_RSA_WITH_AES_256_CBC_SHA", "version": "TLS 1.0", "kex": "RSA", "auth": "RSA", "enc": "AES-256-CBC", "mac": "SHA1", "pfs": False, "weak": True, "weak_reason": "No Forward Secrecy & SHA-1 MAC"},
    0x009C: {"name": "TLS_RSA_WITH_AES_128_GCM_SHA256", "version": "TLS 1.2", "kex": "RSA", "auth": "RSA", "enc": "AES-128-GCM", "mac": "AEAD", "pfs": False, "weak": True, "weak_reason": "No Forward Secrecy (static RSA key exchange)"},
    # Severely deprecated / insecure ciphers
    0x000A: {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "version": "SSL 3.0", "kex": "RSA", "auth": "RSA", "enc": "3DES", "mac": "SHA1", "pfs": False, "weak": True, "weak_reason": "Sweet32 vulnerable 64-bit block cipher (3DES) & No Forward Secrecy"},
    0x0004: {"name": "TLS_RSA_WITH_RC4_128_MD5", "version": "SSL 3.0", "kex": "RSA", "auth": "RSA", "enc": "RC4", "mac": "MD5", "pfs": False, "weak": True, "weak_reason": "Prohibited RC4 stream cipher & broken MD5 MAC"},
    0x0005: {"name": "TLS_RSA_WITH_RC4_128_SHA", "version": "SSL 3.0", "kex": "RSA", "auth": "RSA", "enc": "RC4", "mac": "SHA1", "pfs": False, "weak": True, "weak_reason": "Prohibited RC4 stream cipher"},
    0x0009: {"name": "TLS_RSA_WITH_DES_CBC_SHA", "version": "SSL 3.0", "kex": "RSA", "auth": "RSA", "enc": "DES", "mac": "SHA1", "pfs": False, "weak": True, "weak_reason": "56-bit DES cipher easily brute-forced"},
    0x0001: {"name": "TLS_RSA_WITH_NULL_MD5", "version": "SSL 3.0", "kex": "RSA", "auth": "RSA", "enc": "NULL", "mac": "MD5", "pfs": False, "weak": True, "weak_reason": "Unencrypted plaintext NULL cipher"},
}

TLS_VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

class TLSParser:
    @staticmethod
    def parse_tls_stream(payload: bytes) -> Dict[str, Any]:
        """
        Parses TLS records from a TCP stream byte buffer.
        Extracts ClientHello, ServerHello, and Certificate records.
        """
        result = {
            "tls_detected": False,
            "tls_version": "NOT OBSERVABLE",
            "cipher_suite": "NOT OBSERVABLE",
            "cipher_code": None,
            "key_exchange": "NOT OBSERVABLE",
            "forward_secrecy": "NOT OBSERVABLE",
            "handshake_status": "NOT OBSERVABLE",
            "sni": "NOT OBSERVABLE",
            "alpn": "NOT OBSERVABLE",
            "raw_certificates": [],
            "client_offered_ciphers": [],
            "client_supported_versions": [],
            "server_selected_version": None,
        }

        if len(payload) < 5:
            return result

        offset = 0
        total_len = len(payload)

        # Look for TLS record header: content_type(1) version(2) length(2)
        while offset + 5 <= total_len:
            content_type = payload[offset]
            # Valid content types: 20 (ChangeCipherSpec), 21 (Alert), 22 (Handshake), 23 (ApplicationData)
            if content_type not in (20, 21, 22, 23):
                # Search forward for a potential 0x16 0x03 start
                next_pos = -1
                for i in range(offset + 1, min(offset + 1024, total_len - 4)):
                    if payload[i] == 22 and payload[i+1] == 3 and payload[i+2] in (0, 1, 2, 3, 4):
                        next_pos = i
                        break
                if next_pos != -1:
                    offset = next_pos
                    continue
                else:
                    break

            result["tls_detected"] = True
            rec_version = struct.unpack("!H", payload[offset+1:offset+3])[0]
            rec_len = struct.unpack("!H", payload[offset+3:offset+5])[0]
            rec_end = min(offset + 5 + rec_len, total_len)
            rec_payload = payload[offset+5:rec_end]

            if content_type == 22:  # Handshake
                TLSParser._parse_handshake_record(rec_payload, rec_version, result)

            if content_type == 23 and result["handshake_status"] == "NOT OBSERVABLE":
                # Application data after handshake implies handshake was completed
                result["handshake_status"] = "COMPLETED"

            offset = rec_end
            if offset >= total_len:
                break

        # Refine TLS version
        if result["server_selected_version"]:
            result["tls_version"] = TLS_VERSION_NAMES.get(result["server_selected_version"], f"TLS (0x{result['server_selected_version']:04x})")
        elif result["client_supported_versions"]:
            # Highest version client offered
            highest = max(result["client_supported_versions"])
            if result["tls_version"] == "NOT OBSERVABLE":
                result["tls_version"] = f"Client Offered {TLS_VERSION_NAMES.get(highest, 'Unknown')}"

        if result["cipher_code"] is not None:
            c_info = CIPHER_SUITES_MAP.get(result["cipher_code"])
            if c_info:
                result["cipher_suite"] = c_info["name"]
                result["key_exchange"] = c_info["kex"]
                result["forward_secrecy"] = "SUPPORTED" if c_info["pfs"] else "NOT SUPPORTED"
            else:
                result["cipher_suite"] = f"Unknown Cipher (0x{result['cipher_code']:04x})"

        return result

    @staticmethod
    def _parse_handshake_record(data: bytes, rec_version: int, result: Dict[str, Any]):
        pos = 0
        while pos + 4 <= len(data):
            msg_type = data[pos]
            msg_len = (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3]
            body_end = min(pos + 4 + msg_len, len(data))
            msg_body = data[pos+4:body_end]

            if msg_type == 1:  # ClientHello
                TLSParser._parse_client_hello(msg_body, result)
            elif msg_type == 2:  # ServerHello
                TLSParser._parse_server_hello(msg_body, result)
            elif msg_type == 11:  # Certificate
                TLSParser._parse_certificate_msg(msg_body, result)

            pos = body_end

    @staticmethod
    def _parse_client_hello(body: bytes, result: Dict[str, Any]):
        if len(body) < 34:
            return
        client_ver = struct.unpack("!H", body[0:2])[0]
        # Skip random (32 bytes) -> pos = 34
        pos = 34
        if pos >= len(body):
            return
        session_id_len = body[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(body):
            return
        cs_len = struct.unpack("!H", body[pos:pos+2])[0]
        pos += 2
        cipher_codes = []
        for i in range(0, min(cs_len, len(body) - pos), 2):
            if pos + i + 2 <= len(body):
                code = struct.unpack("!H", body[pos+i:pos+i+2])[0]
                cipher_codes.append(code)
        result["client_offered_ciphers"] = cipher_codes
        pos += cs_len
        if pos >= len(body):
            return
        # Comp methods
        comp_len = body[pos]
        pos += 1 + comp_len

        # Extensions
        if pos + 2 <= len(body):
            ext_total_len = struct.unpack("!H", body[pos:pos+2])[0]
            pos += 2
            ext_end = min(pos + ext_total_len, len(body))
            while pos + 4 <= ext_end:
                ext_type = struct.unpack("!H", body[pos:pos+2])[0]
                ext_len = struct.unpack("!H", body[pos+2:pos+4])[0]
                ext_data = body[pos+4:pos+4+ext_len]

                if ext_type == 0x0000:  # SNI
                    if len(ext_data) >= 5:
                        sni_len = struct.unpack("!H", ext_data[3:5])[0]
                        sni_name = ext_data[5:5+sni_len].decode("utf-8", errors="ignore")
                        if sni_name:
                            result["sni"] = sni_name
                elif ext_type == 0x002B:  # Supported Versions
                    if len(ext_data) >= 1:
                        sv_len = ext_data[0]
                        versions = []
                        for v_idx in range(1, min(1 + sv_len, len(ext_data)), 2):
                            if v_idx + 1 < len(ext_data):
                                v = struct.unpack("!H", ext_data[v_idx:v_idx+2])[0]
                                versions.append(v)
                        result["client_supported_versions"] = versions
                elif ext_type == 0x0010:  # ALPN
                    if len(ext_data) >= 2:
                        alpn_list_len = struct.unpack("!H", ext_data[0:2])[0]
                        ap = 2
                        alpns = []
                        while ap < min(2 + alpn_list_len, len(ext_data)):
                            p_len = ext_data[ap]
                            proto = ext_data[ap+1:ap+1+p_len].decode("utf-8", errors="ignore")
                            alpns.append(proto)
                            ap += 1 + p_len
                        if alpns:
                            result["alpn"] = ", ".join(alpns)

                pos += 4 + ext_len

    @staticmethod
    def _parse_server_hello(body: bytes, result: Dict[str, Any]):
        if len(body) < 34:
            return
        server_ver = struct.unpack("!H", body[0:2])[0]
        pos = 34
        if pos >= len(body):
            return
        sess_id_len = body[pos]
        pos += 1 + sess_id_len
        if pos + 2 > len(body):
            return
        cipher_code = struct.unpack("!H", body[pos:pos+2])[0]
        result["cipher_code"] = cipher_code
        pos += 2
        if pos >= len(body):
            return
        pos += 1  # comp method

        # Check extensions for TLS 1.3 supported_versions (0x002B)
        selected_version = server_ver
        if pos + 2 <= len(body):
            ext_total_len = struct.unpack("!H", body[pos:pos+2])[0]
            pos += 2
            ext_end = min(pos + ext_total_len, len(body))
            while pos + 4 <= ext_end:
                ext_type = struct.unpack("!H", body[pos:pos+2])[0]
                ext_len = struct.unpack("!H", body[pos+2:pos+4])[0]
                ext_data = body[pos+4:pos+4+ext_len]
                if ext_type == 0x002B and len(ext_data) >= 2:
                    selected_version = struct.unpack("!H", ext_data[0:2])[0]
                pos += 4 + ext_len

        result["server_selected_version"] = selected_version
        result["handshake_status"] = "HANDSHAKE_IN_PROGRESS"

    @staticmethod
    def _parse_certificate_msg(body: bytes, result: Dict[str, Any]):
        if len(body) < 3:
            return
        certs_len = (body[0] << 16) | (body[1] << 8) | body[2]
        pos = 3
        while pos + 3 <= min(3 + certs_len, len(body)):
            c_len = (body[pos] << 16) | (body[pos+1] << 8) | body[pos+2]
            pos += 3
            if pos + c_len <= len(body):
                der_cert = body[pos:pos+c_len]
                result["raw_certificates"].append(der_cert)
                pos += c_len
            else:
                break
        if result["raw_certificates"]:
            result["handshake_status"] = "CERTIFICATE_EXCHANGED"
