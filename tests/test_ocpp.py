"""End-to-end: pravi OCPP server + simulator za sve tri verzije i sigurnosne profile."""
import asyncio
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from csms import config
from csms.db import Organization, RfidCard, Station, StationAccess, Transaction, User, session_scope
from csms.ocpp_server import run_ocpp_servers
from csms.security import CA_CERT, hash_password

ROOT = Path(__file__).resolve().parents[1]
PW = "0123456789ABCDEF0123"
WS = f"ws://127.0.0.1:{config.OCPP_WS_PORT}/ocpp"
WSS = f"wss://localhost:{config.OCPP_WSS_PORT}/ocpp"


@pytest.fixture(scope="module", autouse=True)
def server():
    with session_scope() as s:
        org = Organization(name="E2E d.o.o."); s.add(org); s.flush()
        u = User(email="e2e@test.hr", password_hash=hash_password("lozinka12345"), organization_id=org.id)
        s.add(u); s.flush()
        s.add(RfidCard(uid="04E2E0001", user_id=u.id))
        for cp, prof in [("E-16", 1), ("E-201", 2), ("E-21", 2), ("E-MTLS", 2), ("E-PRIV", 1)]:
            st = Station(charge_point_id=cp, security_profile=prof, password_hash=hash_password(PW), approved=True)
            s.add(st); s.flush()
            if cp != "E-PRIV":
                s.add(StationAccess(station_id=st.id, organization_id=org.id))
    loop = asyncio.new_event_loop()
    started = threading.Event()

    def run():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_ocpp_servers())
        started.set()
        loop.run_forever()

    threading.Thread(target=run, daemon=True).start()
    assert started.wait(10)
    yield


def sim(*args):
    r = subprocess.run([sys.executable, str(ROOT / "tools/simulator.py"), "--tag", "04e2e0001", *args],
                       capture_output=True, text=True, timeout=60, env=os.environ)
    return r.returncode, r.stdout + r.stderr


def last_tx(cp):
    with session_scope() as s:
        tx = (s.query(Transaction).join(Station).filter(Station.charge_point_id == cp)
              .order_by(Transaction.id.desc()).first())
        return tx.energy_kwh, tx.cost_eur, tx.user_id is not None


def test_v16_profile1():
    code, out = sim("--id", "E-16", "--password", PW, "--url", WS)
    assert code == 0, out
    assert last_tx("E-16") == (11.0, 3.85, True)


def test_wrong_password_rejected():
    code, out = sim("--id", "E-16", "--password", "krivo", "--url", WS)
    assert "401" in out


def test_v201_profile2_tls():
    code, out = sim("--id", "E-201", "--version", "2.0.1", "--password", PW, "--url", WSS, "--ca", str(CA_CERT))
    assert code == 0, out
    assert last_tx("E-201") == (7.4, 2.59, True)


def test_profile2_rejects_plain_ws():
    code, out = sim("--id", "E-201", "--version", "2.0.1", "--password", PW, "--url", WS)
    assert "401" in out


def test_v21():
    code, out = sim("--id", "E-21", "--version", "2.1", "--password", PW, "--url", WSS, "--ca", str(CA_CERT))
    assert code == 0, out
    assert last_tx("E-21")[0] == 7.4


def test_profile3_mtls(tmp_path):
    code, out = sim("--id", "E-MTLS", "--password", PW, "--url", WSS, "--ca", str(CA_CERT), "--csr",
                    "--out", str(tmp_path))
    assert code == 0 and (tmp_path / "E-MTLS.crt").exists(), out
    with session_scope() as s:
        s.query(Station).filter_by(charge_point_id="E-MTLS").one().security_profile = 3
    code, out = sim("--id", "E-MTLS", "--url", WSS, "--ca", str(CA_CERT))
    assert "401" in out
    code, out = sim("--id", "E-MTLS", "--version", "2.0.1", "--url", WSS, "--ca", str(CA_CERT),
                    "--cert", str(tmp_path / "E-MTLS.crt"), "--key", str(tmp_path / "E-MTLS.key"))
    assert code == 0, out


def test_unknown_card_rejected():
    code, out = sim("--id", "E-16", "--password", PW, "--url", WS, "--tag", "FFFF0000")
    assert "Authorize: Invalid" in out


def test_card_without_access_rejected():
    """Kartica je valjana, ali njena organizacija nema dozvolu za ovu punionicu."""
    code, out = sim("--id", "E-PRIV", "--password", PW, "--url", WS)
    assert "Authorize: Invalid" in out


def test_access_price_override():
    with session_scope() as s:
        st = s.query(Station).filter_by(charge_point_id="E-16").one()
        s.query(StationAccess).filter_by(station_id=st.id).one().price_per_kwh = 0.0
    code, out = sim("--id", "E-16", "--password", PW, "--url", WS)
    assert code == 0, out
    assert last_tx("E-16") == (11.0, 0.0, True)
    with session_scope() as s:
        st = s.query(Station).filter_by(charge_point_id="E-16").one()
        s.query(StationAccess).filter_by(station_id=st.id).one().price_per_kwh = None
        tx = s.query(Transaction).filter_by(station_id=st.id).order_by(Transaction.id.desc()).first()
        assert tx.organization_id is not None


def test_proxy_tls_headers(monkeypatch):
    """Iza Caddyja: TLS i klijentski certifikat dolaze kroz zaglavlja proxyja."""
    from types import SimpleNamespace
    from csms import ocpp_server

    conn = SimpleNamespace(transport=SimpleNamespace(get_extra_info=lambda k: None))

    def req(**h):
        return SimpleNamespace(path="/ocpp/E-MTLS", headers=h)

    monkeypatch.setattr(config, "TRUST_PROXY_TLS", False)
    assert not ocpp_server.check_access(conn, req(**{"X-Forwarded-Proto": "https",
                                                     "X-Client-Cert-Subject": "CN=E-MTLS"}))[0]
    monkeypatch.setattr(config, "TRUST_PROXY_TLS", True)
    assert ocpp_server.check_access(conn, req(**{"X-Forwarded-Proto": "https",
                                                 "X-Client-Cert-Subject": "CN=E-MTLS,O=Sim"}))[0]
    assert not ocpp_server.check_access(conn, req(**{"X-Forwarded-Proto": "https",
                                                     "X-Client-Cert-Subject": "CN=E-201"}))[0]
    assert not ocpp_server.check_access(conn, req(**{"X-Forwarded-Proto": "http"}))[0]
