"""Lozinke, MFA (TOTP) i ugrađeni certifikacijski autoritet (CA) za OCPP sigurnosne profile 2 i 3."""
from __future__ import annotations

import base64
import hmac
import io
import secrets
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
import pyotp
import qrcode
import qrcode.image.svg
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import config

# ---------------------------------------------------------------- lozinke

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(pw: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except ValueError:
        return False


def generate_station_password() -> str:
    """OCPP AuthorizationKey: 16-40 znakova. Generiramo 32 hex znaka (radi kod svih proizvođača)."""
    return secrets.token_hex(16).upper()


def parse_basic_auth(header: str | None) -> tuple[str, str] | None:
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(header[6:].strip())
    except Exception:
        return None
    user, sep, pw = raw.partition(b":")
    if not sep:
        return None
    # Neki uređaji (spec. OCPP 1.6 Security Whitepaper) šalju ključ kao binarne bajtove
    # zadane hex stringom – prihvaćamo oba oblika.
    try:
        pw_s = pw.decode()
    except UnicodeDecodeError:
        pw_s = pw.hex().upper()
    return user.decode(errors="replace"), pw_s


def verify_station_password(given: str, hashed: str | None) -> bool:
    if verify_password(given, hashed):
        return True
    # binarni oblik ključa (hex -> bajtovi) koji neki uređaji šalju
    try:
        alt = bytes.fromhex(given).decode()
        return verify_password(alt, hashed)
    except (ValueError, UnicodeDecodeError):
        return False


# ---------------------------------------------------------------- MFA (TOTP)

def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="OCPP Charge")


def verify_totp(secret: str | None, code: str) -> bool:
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1)


def qr_svg(data: str) -> str:
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=8)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


def consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------- PKI / CA

PKI_DIR = config.DATA_DIR / "pki"
CA_KEY = PKI_DIR / "ca.key"
CA_CERT = PKI_DIR / "ca.crt"
SRV_KEY = PKI_DIR / "server.key"
SRV_CERT = PKI_DIR / "server.crt"


def _now():
    return datetime.now(timezone.utc)


def _write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    path.chmod(0o600)


def ensure_pki() -> None:
    """Stvori CA i serverski certifikat ako ne postoje."""
    PKI_DIR.mkdir(parents=True, exist_ok=True)
    if not CA_CERT.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OCPP Charge"),
                          x509.NameAttribute(NameOID.COMMON_NAME, "OCPP Charge Root CA")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(_now() - timedelta(days=1))
                .not_valid_after(_now() + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                             content_commitment=False, key_encipherment=False,
                                             data_encipherment=False, key_agreement=False,
                                             encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .sign(key, hashes.SHA256()))
        _write_key(CA_KEY, key)
        CA_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if not SRV_CERT.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _sign(key.public_key(),
                     x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OCPP Charge"),
                                x509.NameAttribute(NameOID.COMMON_NAME, config.PUBLIC_HOSTNAME)]),
                     server=True, days=825)
        _write_key(SRV_KEY, key)
        SRV_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _load_ca():
    key = serialization.load_pem_private_key(CA_KEY.read_bytes(), None)
    cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
    return key, cert


def _sign(public_key, subject: x509.Name, server: bool, days: int):
    ca_key, ca_cert = _load_ca()
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject)
         .public_key(public_key).serial_number(x509.random_serial_number())
         .not_valid_before(_now() - timedelta(minutes=5))
         .not_valid_after(_now() + timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
         .add_extension(x509.ExtendedKeyUsage(
             [ExtendedKeyUsageOID.SERVER_AUTH] if server else [ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
    if server:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(config.PUBLIC_HOSTNAME),
                                                         x509.DNSName("localhost")]), critical=False)
    return b.sign(ca_key, hashes.SHA256())


def sign_station_csr(csr_pem: str, charge_point_id: str, days: int = 730) -> str:
    """Potpiši CSR punionice (SignCertificate). Vraća PEM lanac (cert + CA).

    OCPP zahtijeva da CN = ChargePointId (Security Profile 3), pa to provjeravamo.
    """
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise ValueError("Neispravan potpis CSR-a")
    cns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cns or cns[0].value != charge_point_id:
        raise ValueError(f"CN u CSR-u mora biti '{charge_point_id}'")
    cert = _sign(csr.public_key(), csr.subject, server=False, days=days)
    return (cert.public_bytes(serialization.Encoding.PEM) + CA_CERT.read_bytes()).decode()


def ca_pem() -> str:
    return CA_CERT.read_text()


def cert_info(pem: str) -> dict:
    c = x509.load_pem_x509_certificate(pem.encode())
    return {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
            "not_after": c.not_valid_after_utc.isoformat(), "serial": hex(c.serial_number)}


def server_ssl_context() -> ssl.SSLContext:
    """TLS 1.2+ (OCPP zahtjev). Klijentski certifikat je opcionalan na razini TLS-a,
    a obavezan za punionice sa sigurnosnim profilom 3 (provjera u OCPP serveru)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # OCPP Security Whitepaper preporučeni cipher suiteovi (+ TLS1.3 zadani)
    ctx.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
                    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384")
    if config.TLS_CERT_FILE and config.TLS_KEY_FILE:
        ctx.load_cert_chain(config.TLS_CERT_FILE, config.TLS_KEY_FILE)
    else:
        ctx.load_cert_chain(str(SRV_CERT), str(SRV_KEY))
    ctx.load_verify_locations(str(CA_CERT))
    ctx.verify_mode = ssl.CERT_OPTIONAL
    return ctx
