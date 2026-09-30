import datetime
import hashlib
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

class CertificateAnalyzer:
    @staticmethod
    def analyze_der(der_bytes: bytes) -> Dict[str, Any]:
        """
        Parses raw DER certificate bytes and extracts cryptographic properties.
        """
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
        except Exception as e:
            return {
                "subject": "INVALID CERTIFICATE DATA",
                "issuer": "NOT OBSERVABLE",
                "valid_from": "NOT OBSERVABLE",
                "valid_until": "NOT OBSERVABLE",
                "is_expired": False,
                "is_not_yet_valid": False,
                "is_self_signed": False,
                "public_key_algorithm": "NOT OBSERVABLE",
                "key_length": "NOT OBSERVABLE",
                "signature_algorithm": "NOT OBSERVABLE",
                "certificate_status": "INVALID",
                "san_list": [],
                "fingerprint_sha256": hashlib.sha256(der_bytes).hexdigest() if der_bytes else "NOT OBSERVABLE",
            }

        now = datetime.datetime.now(datetime.timezone.utc)

        # Subject & Issuer formatting
        def format_name(name: x509.Name) -> str:
            parts = []
            for attr in name:
                oid_name = attr.oid._name
                parts.append(f"{oid_name}={attr.value}")
            return ", ".join(parts) if parts else "Empty Subject"

        subject = format_name(cert.subject)
        issuer = format_name(cert.issuer)
        is_self_signed = (cert.subject == cert.issuer)

        # Validity period
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        is_expired = now > not_after
        is_not_yet_valid = now < not_before

        valid_from_str = not_before.strftime("%Y-%m-%d %H:%M:%S UTC")
        valid_until_str = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Public key info
        pub_key = cert.public_key()
        pub_key_alg = "Unknown"
        key_length = "NOT OBSERVABLE"
        key_len_int = 0

        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key_alg = "RSA"
            key_len_int = pub_key.key_size
            key_length = f"{key_len_int} bits"
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key_alg = f"ECDSA ({pub_key.curve.name})"
            key_len_int = pub_key.key_size
            key_length = f"{key_len_int} bits"
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pub_key_alg = "DSA"
            key_len_int = pub_key.key_size
            key_length = f"{key_len_int} bits"
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            pub_key_alg = "Ed25519"
            key_length = "256 bits"
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            pub_key_alg = "Ed448"
            key_length = "448 bits"

        # Signature algorithm
        sig_alg = cert.signature_algorithm_oid._name if hasattr(cert, 'signature_algorithm_oid') else "Unknown"

        # SANs
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = [str(name.value) for name in san_ext.value]
        except Exception:
            pass

        # Fingerprint
        fp = cert.fingerprint(hashes.SHA256()).hex().upper()
        formatted_fp = ":".join(fp[i:i+2] for i in range(0, len(fp), 2))

        # Certificate status calculation
        status = "VALID"
        if is_expired:
            status = "EXPIRED"
        elif is_not_yet_valid:
            status = "NOT_YET_VALID"
        elif pub_key_alg == "RSA" and key_len_int > 0 and key_len_int < 2048:
            status = "WEAK_KEY"
        elif "md5" in sig_alg.lower() or "sha1" in sig_alg.lower():
            status = "WEAK_SIGNATURE"
        elif is_self_signed:
            status = "SELF_SIGNED"

        return {
            "subject": subject,
            "issuer": issuer,
            "valid_from": valid_from_str,
            "valid_until": valid_until_str,
            "is_expired": is_expired,
            "is_not_yet_valid": is_not_yet_valid,
            "is_self_signed": is_self_signed,
            "public_key_algorithm": pub_key_alg,
            "key_length": key_length,
            "key_length_int": key_len_int,
            "signature_algorithm": sig_alg,
            "certificate_status": status,
            "san_list": san_list,
            "fingerprint_sha256": formatted_fp,
        }
