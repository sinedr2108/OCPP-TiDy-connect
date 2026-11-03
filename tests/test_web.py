import re

import pyotp
from fastapi.testclient import TestClient

from csms.db import RfidCard, Station, Transaction, User, session_scope
from csms.security import hash_password
from csms.web import app


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def login(client, email, pw, code=None):
    r = client.post("/login", data={"email": email, "password": pw, "csrf": csrf(client, "/login")},
                    follow_redirects=False)
    if code is not None:
        r = client.post("/login/mfa", data={"code": code, "csrf": csrf(client, "/login/mfa")},
                        follow_redirects=False)
    return r


def setup_module():
    with session_scope() as s:
        a = User(email="u1@test.hr", name="U1", password_hash=hash_password("lozinka12345"))
        b = User(email="u2@test.hr", name="U2", password_hash=hash_password("lozinka12345"))
        st = Station(charge_point_id="WEB-1", approved=True)
        s.add_all([a, b, st]); s.flush()
        c = RfidCard(uid="AAAA", user_id=a.id); s.add(c); s.flush()
        s.add(Transaction(ocpp_tx_id="x1", station_id=st.id, user_id=a.id, card_id=c.id, id_tag="AAAA",
                          energy_wh=10000, cost_eur=3.5, active=False))


def test_requires_login():
    c = TestClient(app)
    assert c.get("/", follow_redirects=False).headers["location"] == "/login"


def test_csrf_required():
    c = TestClient(app)
    c.get("/login")
    r = c.post("/login", data={"email": "u1@test.hr", "password": "lozinka12345", "csrf": "krivo"})
    assert r.status_code == 403


def test_user_sees_only_own_sessions():
    c1, c2 = TestClient(app), TestClient(app)
    login(c1, "u1@test.hr", "lozinka12345"); login(c2, "u2@test.hr", "lozinka12345")
    assert "10.00 kWh" in c1.get("/sessions").text
    assert "0.00 kWh" in c2.get("/sessions").text
    assert c2.get("/stations").status_code == 403


def test_mfa_enable_and_login():
    c = TestClient(app)
    login(c, "u2@test.hr", "lozinka12345")
    page = c.get("/account").text
    secret = re.search(r'class="mono">([A-Z2-7]{16,})<', page).group(1)
    tok = csrf(c, "/account")
    c.post("/account/mfa/enable", data={"code": pyotp.TOTP(secret).now(), "csrf": tok})
    with session_scope() as s:
        assert s.query(User).filter_by(email="u2@test.hr").one().mfa_enabled
    c2 = TestClient(app)
    r = login(c2, "u2@test.hr", "lozinka12345")
    assert r.headers["location"] == "/login/mfa"
    assert c2.get("/", follow_redirects=False).status_code == 303  # još nije prijavljen
    c2.post("/login/mfa", data={"code": "000000", "csrf": csrf(c2, "/login/mfa")}, follow_redirects=False)
    assert c2.get("/", follow_redirects=False).status_code == 303
    login(c2, "u2@test.hr", "lozinka12345", code=pyotp.TOTP(secret).now())
    assert c2.get("/", follow_redirects=False).status_code == 200


def test_lockout_after_failed_logins():
    c = TestClient(app)
    for _ in range(5):
        login(c, "u1@test.hr", "krivo")
    login(c, "u1@test.hr", "lozinka12345")
    assert c.get("/", follow_redirects=False).status_code == 303
    with session_scope() as s:
        u = s.query(User).filter_by(email="u1@test.hr").one(); u.locked_until = None
