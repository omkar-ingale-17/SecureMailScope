import struct
import socket
import datetime
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict
from .tls_analyzer import TLSParser
from .cert_analyzer import CertificateAnalyzer

PCAP_MAGIC_SAME_ENDIAN = 0xA1B2C3D4
PCAP_MAGIC_SWAP_ENDIAN = 0xD4C3B2A1
PCAP_MAGIC_NANO_SAME   = 0xA1B23C4D
PCAP_MAGIC_NANO_SWAP   = 0x4D3CB2A1

PCAPNG_SHB_MAGIC       = 0x0A0D0D0A
PCAPNG_BYTE_ORDER_MAGIC= 0x1A2B3C4D

class RawPacket:
    def __init__(self, timestamp: float, data: bytes):
        self.timestamp = timestamp
        self.data = data

class PCAPParser:
    @staticmethod
    def parse_file(file_bytes: bytes) -> List[Dict[str, Any]]:
        """
        Parses either a classic PCAP or PCAPNG binary file,
        reconstructs TCP streams, identifies email protocol sessions (SMTP, IMAP, POP3),
        and extracts cryptographic & TLS parameters.
        """
        if len(file_bytes) < 24:
            raise ValueError("File is too small to be a valid PCAP/PCAPNG capture.")

        # Detect format
        magic4 = struct.unpack("!I", file_bytes[0:4])[0]
        packets: List[RawPacket] = []

        if magic4 == PCAPNG_SHB_MAGIC:
            packets = PCAPParser._read_pcapng(file_bytes)
        elif magic4 in (PCAP_MAGIC_SAME_ENDIAN, PCAP_MAGIC_SWAP_ENDIAN, PCAP_MAGIC_NANO_SAME, PCAP_MAGIC_NANO_SWAP):
            packets = PCAPParser._read_classic_pcap(file_bytes)
        else:
            # Try checking little-endian magic
            le_magic = struct.unpack("<I", file_bytes[0:4])[0]
            if le_magic in (PCAP_MAGIC_SAME_ENDIAN, PCAP_MAGIC_SWAP_ENDIAN, PCAP_MAGIC_NANO_SAME, PCAP_MAGIC_NANO_SWAP):
                packets = PCAPParser._read_classic_pcap(file_bytes)
            else:
                raise ValueError("Unrecognized packet capture format. Must be standard PCAP or PCAPNG.")

        # Group packets into TCP streams
        streams = PCAPParser._reassemble_tcp_streams(packets)

        # Classify each stream into email sessions
        sessions = []
        session_idx = 1
        for stream_key, stream_info in streams.items():
            session = PCAPParser._analyze_stream(session_idx, stream_key, stream_info)
            if session:
                sessions.append(session)
                session_idx += 1

        return sessions

    @staticmethod
    def _read_classic_pcap(data: bytes) -> List[RawPacket]:
        magic = struct.unpack("<I", data[0:4])[0]
        if magic in (PCAP_MAGIC_SAME_ENDIAN, PCAP_MAGIC_NANO_SAME):
            endian = "<"
            nano = (magic == PCAP_MAGIC_NANO_SAME)
        elif magic in (PCAP_MAGIC_SWAP_ENDIAN, PCAP_MAGIC_NANO_SWAP):
            endian = ">"
            nano = (magic == PCAP_MAGIC_NANO_SWAP)
        else:
            endian = "<"
            nano = False

        link_type = struct.unpack(f"{endian}I", data[20:24])[0]
        offset = 24
        packets = []

        while offset + 16 <= len(data):
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", data[offset:offset+16])
            offset += 16
            if offset + incl_len > len(data):
                break
            pkt_bytes = data[offset:offset+incl_len]
            offset += incl_len

            ts = ts_sec + (ts_usec / 1e9 if nano else ts_usec / 1e6)
            packets.append(RawPacket(ts, pkt_bytes))

        return packets

    @staticmethod
    def _read_pcapng(data: bytes) -> List[RawPacket]:
        packets = []
        offset = 0
        total_len = len(data)
        endian = "<"

        while offset + 8 <= total_len:
            block_type = struct.unpack("<I", data[offset:offset+4])[0]
            block_len = struct.unpack("<I", data[offset+4:offset+8])[0]

            if block_type == 0x0A0D0D0A:  # SHB
                if offset + 12 <= total_len:
                    bom = struct.unpack("<I", data[offset+8:offset+12])[0]
                    if bom == 0x1A2B3C4D:
                        endian = "<"
                    elif bom == 0x4D3C2B1A:
                        endian = ">"
                block_len = struct.unpack(f"{endian}I", data[offset+4:offset+8])[0]

            if block_len < 12 or offset + block_len > total_len:
                break

            if block_type == 0x00000006:  # Enhanced Packet Block
                if block_len >= 32:
                    ts_high, ts_low, cap_len, orig_len = struct.unpack(f"{endian}IIII", data[offset+12:offset+28])
                    raw_ts = (ts_high << 32) | ts_low
                    ts = raw_ts / 1e6  # standard microsecond resolution
                    pkt_data = data[offset+28:offset+28+cap_len]
                    packets.append(RawPacket(ts, pkt_data))

            elif block_type == 0x00000003:  # Simple Packet Block
                if block_len >= 16:
                    orig_len = struct.unpack(f"{endian}I", data[offset+8:offset+12])[0]
                    cap_len = min(orig_len, block_len - 16)
                    pkt_data = data[offset+12:offset+12+cap_len]
                    packets.append(RawPacket(0.0, pkt_data))

            offset += block_len

        return packets

    @staticmethod
    def _reassemble_tcp_streams(packets: List[RawPacket]) -> Dict[str, Dict[str, Any]]:
        streams = defaultdict(lambda: {
            "packets": 0,
            "start_ts": None,
            "end_ts": None,
            "client_to_server": bytearray(),
            "server_to_client": bytearray(),
            "all_payload": bytearray(),
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
        })

        for pkt in packets:
            data = pkt.data
            ts = pkt.timestamp
            if len(data) < 14:
                continue

            # Check Ethernet framing
            eth_proto = struct.unpack("!H", data[12:14])[0]
            ip_offset = 14

            if eth_proto == 0x8100:  # 802.1Q VLAN
                eth_proto = struct.unpack("!H", data[16:18])[0]
                ip_offset = 18

            src_ip, dst_ip = None, None
            ip_proto = None
            tcp_offset = None

            if eth_proto == 0x0800:  # IPv4
                if len(data) < ip_offset + 20:
                    continue
                ihl = (data[ip_offset] & 0x0F) * 4
                ip_proto = data[ip_offset + 9]
                src_ip = socket.inet_ntoa(data[ip_offset + 12:ip_offset + 16])
                dst_ip = socket.inet_ntoa(data[ip_offset + 16:ip_offset + 20])
                tcp_offset = ip_offset + ihl

            elif eth_proto == 0x86DD:  # IPv6
                if len(data) < ip_offset + 40:
                    continue
                ip_proto = data[ip_offset + 6]
                src_ip = socket.inet_ntop(socket.AF_INET6, data[ip_offset + 8:ip_offset + 24])
                dst_ip = socket.inet_ntop(socket.AF_INET6, data[ip_offset + 24:ip_offset + 40])
                tcp_offset = ip_offset + 40
            else:
                # Raw IP packet fallback
                first_byte = data[0]
                ver = (first_byte >> 4) & 0x0F
                if ver == 4 and len(data) >= 20:
                    ihl = (first_byte & 0x0F) * 4
                    ip_proto = data[9]
                    src_ip = socket.inet_ntoa(data[12:16])
                    dst_ip = socket.inet_ntoa(data[16:20])
                    tcp_offset = ihl
                else:
                    continue

            if ip_proto != 6 or tcp_offset is None or len(data) < tcp_offset + 20:
                continue

            # TCP header
            src_port = struct.unpack("!H", data[tcp_offset:tcp_offset + 2])[0]
            dst_port = struct.unpack("!H", data[tcp_offset + 2:tcp_offset + 4])[0]
            tcp_hdr_len = ((data[tcp_offset + 12] >> 4) & 0x0F) * 4
            payload_offset = tcp_offset + tcp_hdr_len
            tcp_payload = data[payload_offset:]

            # Normalize stream direction (canonical key)
            endpoint_a = (src_ip, src_port)
            endpoint_b = (dst_ip, dst_port)
            is_forward = endpoint_a <= endpoint_b
            stream_key = f"{min(endpoint_a, endpoint_b)}<->{max(endpoint_a, endpoint_b)}"

            s = streams[stream_key]
            s["packets"] += 1
            if s["start_ts"] is None or (ts and ts < s["start_ts"]):
                s["start_ts"] = ts
            if s["end_ts"] is None or (ts and ts > s["end_ts"]):
                s["end_ts"] = ts

            if s["src_ip"] is None:
                s["src_ip"] = src_ip
                s["dst_ip"] = dst_ip
                s["src_port"] = src_port
                s["dst_port"] = dst_port

            if tcp_payload:
                s["all_payload"].extend(tcp_payload)
                if is_forward:
                    s["client_to_server"].extend(tcp_payload)
                else:
                    s["server_to_client"].extend(tcp_payload)

        return streams

    @staticmethod
    def _analyze_stream(idx: int, stream_key: str, s: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        src_port = s["src_port"]
        dst_port = s["dst_port"]
        all_bytes = bytes(s["all_payload"])
        text_sample = all_bytes[:4096].decode("latin-1", errors="ignore").upper()

        # Identify protocol
        protocol = None
        email_ports = {
            25: "SMTP", 587: "SMTP", 465: "SMTP", 2525: "SMTP",
            143: "IMAP", 993: "IMAP",
            110: "POP3", 995: "POP3"
        }

        # Check by known port first
        if src_port in email_ports:
            protocol = email_ports[src_port]
            # When src_port is the server port, client is dst
            server_ip, server_port = s["src_ip"], s["src_port"]
            client_ip, client_port = s["dst_ip"], s["dst_port"]
        elif dst_port in email_ports:
            protocol = email_ports[dst_port]
            client_ip, client_port = s["src_ip"], s["src_port"]
            server_ip, server_port = s["dst_ip"], s["dst_port"]
        else:
            # Check by signature
            if "220 " in text_sample or "EHLO " in text_sample or "HELO " in text_sample:
                protocol = "SMTP"
            elif "* OK " in text_sample or "CAPABILITY " in text_sample:
                protocol = "IMAP"
            elif "+OK " in text_sample or "USER " in text_sample:
                protocol = "POP3"
            else:
                return None  # Non-email stream, ignore in this forensic scope

            client_ip, client_port = s["src_ip"], s["src_port"]
            server_ip, server_port = s["dst_ip"], s["dst_port"]

        # STARTTLS detection
        starttls_detected = False
        starttls_status = "NOT_OFFERED"

        if protocol == "SMTP":
            if "STARTTLS" in text_sample:
                starttls_detected = True
                if "220 " in text_sample and ("2.0.0" in text_sample or "READY" in text_sample or "START TLS" in text_sample):
                    starttls_status = "OFFERED_AND_ACCEPTED"
                else:
                    starttls_status = "OFFERED_NOT_UPGRADED"
        elif protocol == "IMAP":
            if "STARTTLS" in text_sample:
                starttls_detected = True
                if "OK " in text_sample:
                    starttls_status = "OFFERED_AND_ACCEPTED"
                else:
                    starttls_status = "OFFERED_NOT_UPGRADED"
        elif protocol == "POP3":
            if "STLS" in text_sample:
                starttls_detected = True
                if "+OK" in text_sample:
                    starttls_status = "OFFERED_AND_ACCEPTED"
                else:
                    starttls_status = "OFFERED_NOT_UPGRADED"

        # Direct TLS port (465, 993, 995)
        if server_port in (465, 993, 995):
            starttls_status = "DIRECT_TLS_PORT"

        # TLS Analysis
        tls_res = TLSParser.parse_tls_stream(all_bytes)

        # Certificate Analysis
        cert_res = {
            "subject": "NOT OBSERVABLE",
            "issuer": "NOT OBSERVABLE",
            "valid_from": "NOT OBSERVABLE",
            "valid_until": "NOT OBSERVABLE",
            "is_expired": False,
            "is_not_yet_valid": False,
            "is_self_signed": False,
            "public_key_algorithm": "NOT OBSERVABLE",
            "key_length": "NOT OBSERVABLE",
            "signature_algorithm": "NOT OBSERVABLE",
            "certificate_status": "NOT OBSERVABLE",
            "san_list": [],
            "fingerprint_sha256": "NOT OBSERVABLE",
        }

        if tls_res["raw_certificates"]:
            cert_res = CertificateAnalyzer.analyze_der(tls_res["raw_certificates"][0])

        start_ts = s["start_ts"] or 0.0
        end_ts = s["end_ts"] or start_ts
        duration = max(0.0, round(end_ts - start_ts, 4))
        start_time_str = datetime.datetime.fromtimestamp(start_ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if start_ts > 0 else "NOT OBSERVABLE"
        end_time_str = datetime.datetime.fromtimestamp(end_ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if end_ts > 0 else "NOT OBSERVABLE"

        return {
            "session_id": f"SESS-{idx:04d}",
            "protocol": protocol,
            "network": {
                "src_ip": client_ip,
                "dst_ip": server_ip,
                "src_port": client_port,
                "dst_port": server_port,
                "packet_count": s["packets"],
                "session_duration": duration,
                "start_time": start_time_str,
                "end_time": end_time_str,
            },
            "starttls_detected": starttls_detected,
            "starttls_status": starttls_status,
            "tls": {
                "tls_detected": tls_res["tls_detected"],
                "tls_version": tls_res["tls_version"],
                "cipher_suite": tls_res["cipher_suite"],
                "cipher_code": f"0x{tls_res['cipher_code']:04x}" if tls_res["cipher_code"] else None,
                "key_exchange": tls_res["key_exchange"],
                "forward_secrecy": tls_res["forward_secrecy"],
                "handshake_status": tls_res["handshake_status"],
                "alpn": tls_res["alpn"],
                "sni": tls_res["sni"],
            },
            "certificate": cert_res,
        }
