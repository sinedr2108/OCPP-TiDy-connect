"""Obavijesti (Web Push, e-mail), mjesečni PDF obračun i lokalno vrijeme."""
import hashlib
import hmac
import json
import re
import struct
from datetime import datetime

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from csms import config, notify, services
from csms.db import (ConnectorStatus, Organization, PushSubscription, RfidCard, Station, StationAccess,
                     Transaction, User, session_scope)
from csms.security import hash_password
from csms.timeutil import fmt, month_bounds
from csms.web import app

PW = "lozinka12345"
IDS = {}


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def login(email):
    c = TestClient(app)
    c.post("/login", data={"email": email, "password": PW, "csrf": csrf(c, "/login")}, follow_redirects=False)
    return c


def setup_module():
    notify.BACKGROUND = False
    with session_scope() as s:
        o1, o2 = Organization(name="PDF Tvrtka"), Organization(name="PDF Druga")
        s.add_all([o1, o2]); s.flush()
        u = User(email="np-user@test.hr", name="Iva Čačić", password_hash=hash_password(PW), organization_id=o1.id)
        boss = User(email="np-boss@test.hr", password_hash=hash_password(PW), organization_id=o1.id, org_role="admin")
        other = User(email="np-other@test.hr", password_hash=hash_password(PW), organization_id=o2.id)
        st = Station(charge_point_id="NP-1", name="Dvorište – Žitnjak", approved=True, organization_id=o1.id)
        s.add_all([u, boss, other, st]); s.flush()
        s.add(StationAccess(station_id=st.id, organization_id=o1.id))
        s.add(Transaction(ocpp_tx_id="np-old", station_id=st.id, user_id=u.id, organization_id=o1.id,
                          started_at=datetime(2026, 9, 30, 22, 30), stopped_at=datetime(2026, 9, 30, 23, 30),
                          energy_wh=5000, cost_eur=1.75, price_per_kwh=0.35, active=False))
        IDS.update(user=u.id, boss=boss.id, other=other.id, st=st.id, o1=o1.id, o2=o2.id)


def teardown_module():
    notify.BACKGROUND = True


# ------------------------------------------------------------ Web Push kriptografija

def _decrypt(body: bytes, ua_private, auth_secret: bytes) -> bytes:
    """Strana preglednika (RFC 8291) za provjeru."""
    salt, rs, idlen = body[:16], *struct.unpack("!IB", body[16:21])
    as_public = body[21:21 + idlen]
    ct = body[21 + idlen:]
    ua_public = ua_private.public_key().public_bytes(serialization.Encoding.X962,
                                                     serialization.PublicFormat.UncompressedPoint)
    secret = ua_private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public))
    prk_key = hmac.new(auth_secret, secret, hashlib.sha256).digest()
    ikm = hmac.new(prk_key, b"WebPush: info\x00" + ua_public + as_public + b"\x01", hashlib.sha256).digest()
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    cek = hmac.new(prk, b"Content-Encoding: aes128gcm\x00\x01", hashlib.sha256).digest()[:16]
    nonce = hmac.new(prk, b"Content-Encoding: nonce\x00\x01", hashlib.sha256).digest()[:12]
    pt = AESGCM(cek).decrypt(nonce, ct, None)
    assert rs == 4096 and pt.endswith(b"\x02")
    return pt[:-1]


def _browser_keys():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    auth = b"0123456789abcdef"
    return priv, notify.b64u(pub), notify.b64u(auth), auth


def test_push_encryption_roundtrip():
    priv, p256dh, auth_b64, auth = _browser_keys()
    body = notify.encrypt_payload(b'{"title":"Bok"}', p256dh, auth_b64)
    assert _decrypt(body, priv, auth) == b'{"title":"Bok"}'


def test_vapid_jwt_signature():
    h = notify.vapid_header("https://fcm.googleapis.com/fcm/send/abc")
    jwt = re.search(r"t=([^,]+)", h).group(1)
    head, claims, sig = jwt.split(".")
    assert json.loads(notify.b64u_decode(claims))["aud"] == "https://fcm.googleapis.com"
    raw = notify.b64u_decode(sig)
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    notify.vapid_key().public_key().verify(der, f"{head}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))


# ------------------------------------------------------------ obavijesti o punjenju

@pytest.fixture
def outbox(monkeypatch):
    box = {"push": [], "mail": []}

    def fake_push(sub, payload):
        box["push"].append((sub["endpoint"], payload))
        return 410 if "dead" in sub["endpoint"] else 201

    monkeypatch.setattr(notify, "send_push", fake_push)
    monkeypatch.setattr(notify, "send_email", lambda to, subj, text: box["mail"].append((to, subj, text)))
    return box


def test_subscribe_and_finished_notification(outbox):
    c = login("np-user@test.hr")
    tok = csrf(c, "/app")
    _, p256dh, auth_b64, _ = _browser_keys()
    for ep in ["https://push.example/live", "https://push.example/dead"]:
        r = c.post("/app/push/subscribe", headers={"X-CSRF": tok},
                   json={"endpoint": ep, "keys": {"p256dh": p256dh, "auth": auth_b64}})
        assert r.status_code == 200
    assert c.post("/app/push/subscribe", json={"endpoint": "x"}, headers={"X-CSRF": "krivo"}).status_code == 403
    tx, auth = services.start_transaction("NP-1", 1, "", 1000.0)
    with session_scope() as s:
        s.get(Transaction, tx.id).user_id = IDS["user"]
    services.set_connector_status("NP-1", 1, "SuspendedEV")
    services.set_connector_status("NP-1", 1, "SuspendedEV")  # druga obavijest se ne šalje
    assert [p["title"] for _, p in outbox["push"]].count("Vozilo je napunjeno · Dvorište – Žitnjak") == 2  # 2 uređaja
    outbox["push"].clear()
    services.stop_transaction(tx.id, 8400.0)
    titles = {ep: p for ep, p in outbox["push"]}
    assert titles["https://push.example/live"]["title"].startswith("Punjenje završeno")
    assert "7.40 kWh" in titles["https://push.example/live"]["body"]
    assert outbox["mail"] and outbox["mail"][-1][0] == "np-user@test.hr"
    with session_scope() as s:  # 410 Gone -> pretplata obrisana
        eps = {p.endpoint for p in s.query(PushSubscription).filter_by(user_id=IDS["user"])}
    assert eps == {"https://push.example/live"}


def test_notification_settings_respected(outbox):
    c = login("np-user@test.hr")
    c.post("/app/notifications", data={"notify_push": "1", "csrf": csrf(c, "/app")})  # e-mail isključen
    notify.notify_user(IDS["user"], "T", "B")
    assert outbox["push"] and not outbox["mail"]


def test_smtp_email(monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent.append(("connect", host, port))
        def starttls(self): sent.append("tls")
        def login(self, u, p): sent.append(("login", u))
        def send_message(self, m): sent.append(("msg", m["To"], m["Subject"]))
        def __enter__(self): return self
        def __exit__(self, *a): pass

    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(config, "SMTP_USER", "u")
    assert notify.send_email("a@b.hr", "Naslov", "Tekst")
    assert ("msg", "a@b.hr", "Naslov") in sent and "tls" in sent
    monkeypatch.setattr(config, "SMTP_HOST", "")
    assert notify.send_email("a@b.hr", "x", "y") is False


# ------------------------------------------------------------ PDF i vrijeme

def test_local_time_and_month_bounds():
    assert fmt(datetime(2026, 9, 30, 22, 30), "%d.%m. %H:%M") == "01.10. 00:30"  # CEST = UTC+2
    start, end = month_bounds(2026, 10)
    assert start == datetime(2026, 9, 30, 22, 0) and end == datetime(2026, 10, 31, 23, 0)


def test_pdf_scopes():
    c = login("np-user@test.hr")
    r = c.get("/reports/pdf?month=2026-10&org_id=%d" % IDS["o2"])  # korisnik dobiva samo svoj obračun
    assert r.status_code == 200 and r.content.startswith(b"%PDF") and r.headers["content-type"] == "application/pdf"
    boss = login("np-boss@test.hr")
    assert boss.get("/reports/pdf?month=2026-10").content.startswith(b"%PDF")
    assert boss.get("/reports/pdf?month=2026-10&user_id=%d" % IDS["other"]).status_code == 404
    assert boss.get("/reports/pdf?month=2026-10&user_id=%d" % IDS["user"]).status_code == 200


def test_pdf_content_has_rows_in_local_month():
    from csms.pdf_report import Row, Statement, build
    from fpdf import FPDF
    pdf = build(Statement("PDF Tvrtka", "Tvrtka", 2026, 10, [
        Row(datetime(2026, 9, 30, 22, 30), "Dvorište – Žitnjak", "Iva Čačić", "04A1", 5.0, 0.35, 1.75)]))
    assert pdf.startswith(b"%PDF") and len(pdf) > 1000
    # punjenje u 00:30 1.10. lokalno ulazi u listopad
    with session_scope() as s:
        start, end = month_bounds(2026, 10)
        assert s.query(Transaction).filter(Transaction.ocpp_tx_id == "np-old", Transaction.started_at >= start,
                                           Transaction.started_at < end).count() == 1


def test_pwa_service_worker_handles_push():
    sw = TestClient(app).get("/sw.js").text
    assert "showNotification" in sw and "notificationclick" in sw
