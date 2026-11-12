"""Obavijesti korisnicima: Web Push na mobitel (PWA) i e-mail.

Web Push je implementiran prema RFC 8291 (šifriranje aes128gcm) i RFC 8292 (VAPID), samo uz `cryptography`.
Slanje ide u pozadinskoj niti da ne usporava OCPP komunikaciju.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import smtplib
import struct
import threading
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config
from .db import PushSubscription, Station, Transaction, User, session_scope
from .timeutil import fmt

log = logging.getLogger("csms.notify")

VAPID_KEY_FILE = config.DATA_DIR / "vapid_private.pem"
_vapid_lock = threading.Lock()
_vapid_key: ec.EllipticCurvePrivateKey | None = None


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _point(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


# ----------------------------------------------------------------- VAPID

def vapid_key() -> ec.EllipticCurvePrivateKey:
    global _vapid_key
    with _vapid_lock:
        if _vapid_key is None:
            if VAPID_KEY_FILE.exists():
                _vapid_key = serialization.load_pem_private_key(VAPID_KEY_FILE.read_bytes(), None)
            else:
                _vapid_key = ec.generate_private_key(ec.SECP256R1())
                VAPID_KEY_FILE.write_bytes(_vapid_key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                os.chmod(VAPID_KEY_FILE, 0o600)
        return _vapid_key


def vapid_public_key() -> str:
    """applicationServerKey za pushManager.subscribe (base64url, nekomprimirana točka)."""
    return b64u(_point(vapid_key().public_key()))


def vapid_header(endpoint: str) -> str:
    u = urlparse(endpoint)
    header = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}).encode())
    claims = b64u(json.dumps({"aud": f"{u.scheme}://{u.netloc}", "exp": int(time.time()) + 12 * 3600,
                              "sub": config.VAPID_SUBJECT}).encode())
    signing_input = f"{header}.{claims}".encode()
    r, s = decode_dss_signature(vapid_key().sign(signing_input, ec.ECDSA(hashes.SHA256())))
    jwt = f"{header}.{claims}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
    return f"vapid t={jwt}, k={vapid_public_key()}"


# ----------------------------------------------------------------- RFC 8291 šifriranje

def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def encrypt_payload(payload: bytes, ua_public_b64: str, auth_b64: str, *, salt: bytes | None = None,
                    as_private: ec.EllipticCurvePrivateKey | None = None) -> bytes:
    ua_public = b64u_decode(ua_public_b64)
    auth_secret = b64u_decode(auth_b64)
    as_private = as_private or ec.generate_private_key(ec.SECP256R1())
    as_public = _point(as_private.public_key())
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    ecdh_secret = as_private.exchange(ec.ECDH(), ua_key)
    prk_key = hmac.new(auth_secret, ecdh_secret, hashlib.sha256).digest()
    ikm = _hkdf_expand(prk_key, b"WebPush: info\x00" + ua_public + as_public, 32)
    salt = salt or os.urandom(16)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    cek = _hkdf_expand(prk, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf_expand(prk, b"Content-Encoding: nonce\x00", 12)
    ciphertext = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)
    return salt + struct.pack("!IB", 4096, len(as_public)) + as_public + ciphertext


def send_push(sub: dict, payload: dict) -> int:
    """Pošalji jednu push poruku. Vraća HTTP status (201 = OK, 404/410 = pretplata više ne vrijedi)."""
    body = encrypt_payload(json.dumps(payload).encode(), sub["p256dh"], sub["auth"])
    req = urllib.request.Request(sub["endpoint"], data=body, method="POST", headers={
        "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", "TTL": "86400",
        "Urgency": "normal", "Authorization": vapid_header(sub["endpoint"])})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


# ----------------------------------------------------------------- e-mail

def send_email(to: str, subject: str, text: str) -> bool:
    if not config.SMTP_HOST:
        return False
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = config.SMTP_FROM, to, subject
    msg.set_content(text)
    if config.SMTP_TLS == "ssl":
        smtp = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=15)
    else:
        smtp = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15)
        if config.SMTP_TLS == "starttls":
            smtp.starttls()
    with smtp:
        if config.SMTP_USER:
            smtp.login(config.SMTP_USER, config.SMTP_PASSWORD)
        smtp.send_message(msg)
    return True


# ----------------------------------------------------------------- slanje korisniku

def notify_user(user_id: int, title: str, body: str, url: str = "/app") -> None:
    """Sinkrono pošalji obavijest korisniku svim kanalima koje ima uključene."""
    with session_scope() as s:
        u = s.get(User, user_id)
        if u is None or not u.active:
            return
        email = u.email if u.notify_email else None
        subs = ([{"id": p.id, "endpoint": p.endpoint, "p256dh": p.p256dh, "auth": p.auth}
                 for p in s.query(PushSubscription).filter_by(user_id=user_id)] if u.notify_push else [])
    dead = []
    for sub in subs:
        try:
            status = send_push(sub, {"title": title, "body": body, "url": url})
            if status in (404, 410):
                dead.append(sub["id"])
        except Exception as e:  # mreža, neispravan ključ...
            log.warning("push %s: %s", sub["endpoint"][:60], e)
    if dead:
        with session_scope() as s:
            s.query(PushSubscription).filter(PushSubscription.id.in_(dead)).delete(synchronize_session=False)
    if email:
        try:
            send_email(email, title, f"{body}\n\n{config.PUBLIC_BASE_URL}{url}")
        except Exception as e:
            log.warning("email %s: %s", email, e)


# Testovi ovo postavljaju na False da se obavijesti šalju odmah (bez niti).
BACKGROUND = True


def _dispatch(fn, *args) -> None:
    if BACKGROUND:
        threading.Thread(target=fn, args=args, daemon=True).start()
    else:
        fn(*args)


def _tx_text(tx_id: int) -> tuple[int | None, str, str]:
    with session_scope() as s:
        tx = s.get(Transaction, tx_id)
        if tx is None:
            return None, "", ""
        st = s.get(Station, tx.station_id)
        name = st.name or st.charge_point_id
        return tx.user_id, name, f"{tx.energy_kwh:.2f} kWh · {tx.cost_eur:.2f} € · {fmt(tx.started_at, '%H:%M')}–" \
                                 f"{fmt(tx.stopped_at, '%H:%M') if tx.stopped_at else 'sada'}"


def session_finished(tx_id: int) -> None:
    def run():
        user_id, name, summary = _tx_text(tx_id)
        if user_id:
            notify_user(user_id, f"Punjenje završeno · {name}", summary)
    _dispatch(run)


def vehicle_full(tx_id: int) -> None:
    def run():
        user_id, name, summary = _tx_text(tx_id)
        if user_id:
            notify_user(user_id, f"Vozilo je napunjeno · {name}",
                        f"Vozilo više ne puni ({summary}). Odspoji kabel i oslobodi mjesto.")
    _dispatch(run)
