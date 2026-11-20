"""Više organizacija: vidljivost punionica, opseg admina organizacije, mobilna aplikacija."""
import re

from fastapi.testclient import TestClient

from csms import services
from csms.db import (Organization, RfidCard, Station, StationAccess, Transaction, User, session_scope)
from csms.security import hash_password
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
    with session_scope() as s:
        a = Organization(name="Tvrtka A", kind="company")
        h = Organization(name="Kućanstvo H", kind="household")
        s.add_all([a, h]); s.flush()
        users = {
            "admin": User(email="mt-admin@test.hr", password_hash=hash_password(PW), is_admin=True),
            "a_boss": User(email="a-boss@test.hr", password_hash=hash_password(PW), organization_id=a.id,
                           org_role="admin"),
            "a_emp": User(email="a-emp@test.hr", name="Zaposlenik", password_hash=hash_password(PW),
                          organization_id=a.id),
            "h_mom": User(email="h-mom@test.hr", password_hash=hash_password(PW), organization_id=h.id),
            "guest": User(email="guest@test.hr", password_hash=hash_password(PW)),
        }
        s.add_all(users.values()); s.flush()
        st_a = Station(charge_point_id="MT-A", name="Garaža A", approved=True, organization_id=a.id)
        st_h = Station(charge_point_id="MT-H", name="Kućna", approved=True, organization_id=h.id)
        s.add_all([st_a, st_h]); s.flush()
        s.add_all([StationAccess(station_id=st_a.id, organization_id=a.id, price_per_kwh=0.0),
                   StationAccess(station_id=st_a.id, user_id=users["guest"].id, price_per_kwh=0.5),
                   StationAccess(station_id=st_h.id, organization_id=h.id)])
        s.add_all([RfidCard(uid="MTEMP1", user_id=users["a_emp"].id, organization_id=a.id),
                   RfidCard(uid="MTGUEST1", user_id=users["guest"].id),
                   RfidCard(uid="MTMOM1", user_id=users["h_mom"].id, organization_id=h.id)])
        IDS.update({k: u.id for k, u in users.items()}, a=a.id, h=h.id, st_a=st_a.id, st_h=st_h.id)


def test_authorization_respects_access_and_price():
    assert services.authorize_tag("MTEMP1", "MT-A").status == "Accepted"
    assert services.authorize_tag("MTEMP1", "MT-A").price_per_kwh == 0.0
    assert services.authorize_tag("MTEMP1", "MT-H").status == "NotAtThisLocation"
    guest = services.authorize_tag("MTGUEST1", "MT-A")
    assert guest.status == "Accepted" and guest.price_per_kwh == 0.5
    assert services.authorize_tag("MTGUEST1", "MT-H").status == "NotAtThisLocation"
    assert services.authorize_tag("MTMOM1", "MT-H").status == "Accepted"


def test_inactive_org_blocks_cards():
    with session_scope() as s:
        s.get(Organization, IDS["h"]).active = False
    assert services.authorize_tag("MTMOM1", "MT-H").status == "Blocked"
    with session_scope() as s:
        s.get(Organization, IDS["h"]).active = True


def test_member_sees_only_allowed_stations_in_app():
    c = login("a-emp@test.hr")
    page = c.get("/app").text
    assert "Garaža A" in page and "Kućna" not in page
    assert c.get(f"/app/station/{IDS['st_h']}", follow_redirects=False).status_code == 303
    assert c.get("/stations").status_code == 403
    assert c.get("/orgs").status_code == 403
    r = c.post("/app/start", data={"station_id": IDS["st_h"], "connector_id": 1, "csrf": csrf(c, "/app")})
    assert r.status_code == 403


def test_member_login_lands_in_app_and_qr_next():
    c = TestClient(app)
    r = c.get(f"/app/station/{IDS['st_a']}", follow_redirects=False)
    assert r.headers["location"] == f"/login?next=/app/station/{IDS['st_a']}"
    c.get(r.headers["location"])
    r = c.post("/login", data={"email": "a-emp@test.hr", "password": PW, "csrf": csrf(c, "/login")},
               follow_redirects=False)
    assert r.headers["location"] == f"/app/station/{IDS['st_a']}"
    c2 = TestClient(app)
    r = c2.post("/login", data={"email": "guest@test.hr", "password": PW, "csrf": csrf(c2, "/login")},
                follow_redirects=False)
    assert r.headers["location"] == "/app"


def test_org_admin_scope():
    with session_scope() as s:
        s.add_all([
            Transaction(ocpp_tx_id="mt1", station_id=IDS["st_a"], user_id=IDS["guest"], energy_wh=4000,
                        cost_eur=2.0, active=False),  # gost na punionici tvrtke A
            Transaction(ocpp_tx_id="mt2", station_id=IDS["st_h"], user_id=IDS["h_mom"], organization_id=IDS["h"],
                        energy_wh=9000, cost_eur=3.0, active=False),
        ])
    c = login("a-boss@test.hr")
    assert "4.00 kWh" in c.get("/sessions").text  # vidi gosta na svojoj punionici
    assert "9.00" not in c.get("/sessions").text  # ne vidi tuđe kućanstvo
    users = c.get("/users").text
    assert "a-emp@test.hr" in users and "h-mom@test.hr" not in users
    cards = c.get("/cards").text
    assert "MTEMP1" in cards and "MTMOM1" not in cards
    # ne može dirati tuđe korisnike i kartice
    tok = csrf(c, "/users")
    assert c.post(f"/users/{IDS['h_mom']}", data={"action": "toggle_active", "csrf": tok}).status_code == 404
    with session_scope() as s:
        mom_card = s.query(RfidCard).filter_by(uid="MTMOM1").one().id
    assert c.post(f"/cards/{mom_card}", data={"action": "toggle", "csrf": tok}).status_code == 404
    # novi korisnik ide u njegovu organizaciju i ne može biti admin platforme
    c.post("/users", data={"email": "a-new@test.hr", "password": PW, "is_admin": "1", "organization_id": IDS["h"],
                           "csrf": tok})
    with session_scope() as s:
        u = s.query(User).filter_by(email="a-new@test.hr").one()
        assert u.organization_id == IDS["a"] and not u.is_admin
    assert c.get(f"/stations/{IDS['st_a']}").status_code == 403  # tehničke postavke samo admin platforme
    assert "Garaža A" in c.get("/stations").text and "Kućna" not in c.get("/stations").text


def test_user_links_card_in_app():
    c = login("h-mom@test.hr")
    tok = csrf(c, "/app")
    c.post("/app/cards", data={"uid": "aa:bb:cc:01", "csrf": tok})
    c.post("/app/cards", data={"uid": "MTEMP1", "csrf": tok})  # tuđa kartica
    with session_scope() as s:
        assert s.query(RfidCard).filter_by(uid="AABBCC01").one().user_id == IDS["h_mom"]
        assert s.query(RfidCard).filter_by(uid="MTEMP1").one().user_id == IDS["a_emp"]
        cid = s.query(RfidCard).filter_by(uid="AABBCC01").one().id
    c.post(f"/app/cards/{cid}/block", data={"csrf": tok})
    with session_scope() as s:
        assert not s.get(RfidCard, cid).active


def test_admin_pages_render_and_grant():
    c = login("mt-admin@test.hr")
    for url in ["/", "/orgs", f"/orgs/{IDS['a']}", "/stations", f"/stations/{IDS['st_a']}", "/users", "/cards",
                "/reports", "/sessions", "/app", f"/app/station/{IDS['st_a']}", "/settings", "/prices"]:
        assert c.get(url).status_code == 200, url
    tok = csrf(c, "/orgs")
    c.post(f"/orgs/{IDS['h']}/access", data={"station_id": IDS["st_a"], "price_per_kwh": "0,30", "csrf": tok})
    auth = services.authorize_tag("MTMOM1", "MT-A")
    assert auth.status == "Accepted" and auth.price_per_kwh is None  # platform admin ne postavlja cijene
    with session_scope() as s:
        gid = s.query(StationAccess).filter_by(station_id=IDS["st_a"], organization_id=IDS["h"]).one().id
    c.post(f"/access/{gid}/delete", data={"csrf": tok})
    assert services.authorize_tag("MTMOM1", "MT-A").status == "NotAtThisLocation"
    with session_scope() as s:
        tmp = Station(charge_point_id="MT-DEL", approved=False); s.add(tmp); s.flush()
        tmp_id = tmp.id
    c.post(f"/stations/{tmp_id}/delete", data={"csrf": tok})
    c.post(f"/stations/{IDS['st_h']}/delete", data={"csrf": tok})  # ima punjenja -> ostaje
    with session_scope() as s:
        assert s.get(Station, tmp_id) is None and s.get(Station, IDS["st_h"]) is not None
    r = c.post("/orgs", data={"name": "Udruga U", "kind": "association", "csrf": tok}, follow_redirects=False)
    assert r.headers["location"].startswith("/orgs/")


def test_help_and_footer():
    anon = TestClient(app)
    page = anon.get("/help")
    assert page.status_code == 200 and "Upute za korištenje" in page.text
    assert "Za administratora platforme" not in page.text
    assert 'href="https://tid-intel.hr"' in anon.get("/login").text and "Powered by" in anon.get("/login").text
    member = login("a-emp@test.hr").get("/help").text
    assert "Za administratore organizacije" not in member and 'href="/help"' in member
    assert "Za administratora platforme" in login("mt-admin@test.hr").get("/help").text


def test_pwa_assets():
    c = TestClient(app)
    assert c.get("/manifest.webmanifest").json()["start_url"] == "/app"
    assert "serviceWorker" in c.get("/app.js").text
    assert c.get("/sw.js").status_code == 200
    man = c.get("/manifest.webmanifest").json()
    assert man["name"] == "TiDy Charge"
    for icon in man["icons"]:
        r = c.get(icon["src"])
        assert r.status_code == 200 and r.content.startswith(b"\x89PNG")
    assert "TiD</span>y Charge" in c.get("/login").text


def test_card_learning_by_tapping_on_station(monkeypatch):
    from csms import ocpp_server
    monkeypatch.setitem(ocpp_server.CONNECTED, "MT-A", object())
    c = login("a-emp@test.hr")
    tok = csrf(c, "/app")
    # punionica za koju nema dozvolu
    assert c.post("/app/cards/learn", data={"station_id": IDS["st_h"], "csrf": tok}).status_code == 403
    c.post("/app/cards/learn", data={"station_id": IDS["st_a"], "csrf": tok})
    assert "Čekam karticu" in c.get("/app").text
    # tuđa postojeća kartica se ne može preoteti
    assert services.authorize_tag("MTGUEST1", "MT-A").user_id == IDS["guest"]
    # nepoznata kartica prislonjena na tu punionicu veže se na korisnika i odmah je prihvaćena
    res = services.authorize_tag("de:ad:be:ef", "MT-A")
    assert res.status == "Accepted" and res.user_id == IDS["a_emp"]
    assert "DEADBEEF" in c.get("/app").text and "Čekam karticu" not in c.get("/app").text
    # učenje je jednokratno: sljedeća nepoznata kartica se odbija
    assert services.authorize_tag("0BADF00D", "MT-A").status == "Invalid"
    # isteklo učenje ne veže karticu
    c.post("/app/cards/learn", data={"station_id": IDS["st_a"], "csrf": tok})
    services.CARD_LEARN["MT-A"] = (IDS["a_emp"], services.utcnow().replace(year=2000))
    assert services.authorize_tag("0BADF00E", "MT-A").status == "Invalid"
    # odustajanje
    c.post("/app/cards/learn", data={"station_id": IDS["st_a"], "csrf": tok})
    c.post("/app/cards/learn", data={"cancel": "1", "csrf": tok})
    assert services.card_learning_for(IDS["a_emp"]) is None


def test_add_card_on_cards_page():
    c = login("a-emp@test.hr")
    page = c.get("/cards").text
    assert "Dodaj karticu" in page and 'id="nfc-scan"' in page and 'action="/app/cards/learn"' in page
    r = c.post("/app/cards", data={"uid": "CAFE01", "back": "/cards#dodaj", "csrf": csrf(c, "/cards")},
               follow_redirects=False)
    assert r.headers["location"] == "/cards#dodaj" and "CAFE01" in c.get("/cards").text
    boss = login("a-boss@test.hr")
    assert "Dodaj karticu" in boss.get("/cards").text


def test_nfc_scan_ui_present():
    c = login("a-emp@test.hr")
    assert re.search(r'src="/app\.js\?v=[0-9a-f]{10}"', c.get("/app").text)
    assert c.get("/app.js").headers["cache-control"] == "no-cache"
    assert 'id="nfc-scan"' in c.get("/app").text and "NDEFReader" in c.get("/app.js").text


class FakeCP:
    def __init__(self):
        self.calls = []

    async def remote_start(self, tag, cid=1):
        self.calls.append(("start", cid)); return "Accepted"

    async def remote_stop(self, tx):
        self.calls.append(("stop", tx)); return "Accepted"

    async def cancel_start(self, cid=1):
        self.calls.append(("cancel", cid)); return "Accepted"


def test_stop_button_next_to_start(monkeypatch):
    from csms import mobile, ocpp_server
    cp = FakeCP()
    monkeypatch.setitem(ocpp_server.CONNECTED, "MT-A", cp)
    mobile.PENDING_START.clear()
    emp, guest = login("a-emp@test.hr"), login("guest@test.hr")
    page = emp.get(f"/app/station/{IDS['st_a']}").text
    assert 'action="/app/start"' in page and 'action="/app/stop"' in page and ">Stop</button>" in page
    stop = {"station_id": IDS["st_a"], "connector_id": 1}
    # ništa ne čeka i nema punjenja: ništa se ne šalje
    emp.post("/app/stop", data={**stop, "csrf": csrf(emp, "/app")}, follow_redirects=False)
    assert cp.calls == []
    # Start prihvaćen, vozilo nije priključeno: Stop otkazuje Start, ali samo onome tko ga je pokrenuo
    emp.post("/app/start", data={**stop, "csrf": csrf(emp, "/app")}, follow_redirects=False)
    guest.post("/app/stop", data={**stop, "csrf": csrf(guest, "/app")}, follow_redirects=False)
    assert cp.calls == [("start", 1)]
    r = emp.post("/app/stop", data={**stop, "csrf": csrf(emp, "/app")}, follow_redirects=False)
    assert r.headers["location"] == f"/app/station/{IDS['st_a']}"
    assert cp.calls[-1] == ("cancel", 1) and not mobile.PENDING_START
    # aktivno punjenje: svoje smije zaustaviti, tuđe ne; admin organizacije smije
    with session_scope() as s:
        tx = Transaction(ocpp_tx_id="777", station_id=IDS["st_a"], connector_id=1, user_id=IDS["a_emp"],
                         organization_id=IDS["a"], active=True)
        s.add(tx); s.flush(); tx_id = tx.id
    guest.post("/app/stop", data={**stop, "csrf": csrf(guest, "/app")}, follow_redirects=False)
    assert cp.calls[-1] == ("cancel", 1)
    boss = login("a-boss@test.hr")
    boss.post("/app/stop", data={**stop, "csrf": csrf(boss, "/app")}, follow_redirects=False)
    assert cp.calls[-1] == ("stop", "777")
    emp.post("/app/stop", data={"tx_id": tx_id, "csrf": csrf(emp, "/app")}, follow_redirects=False)
    assert cp.calls[-1] == ("stop", "777") and len(cp.calls) == 4
    with session_scope() as s:
        s.get(Transaction, tx_id).active = False


def test_only_station_org_admin_sets_prices():
    with session_scope() as s:
        st_price = s.get(Station, IDS["st_a"]).price_per_kwh
        guest_grant = s.query(StationAccess).filter_by(station_id=IDS["st_a"], user_id=IDS["guest"]).one().id
    admin, boss, emp, mom = (login(e) for e in ("mt-admin@test.hr", "a-boss@test.hr", "a-emp@test.hr",
                                                  "h-mom@test.hr"))
    # platform admin vidi cijene, ali ih ne može mijenjati (ni preko stare forme punionice)
    page = admin.get("/prices").text
    assert "Garaža A" in page and 'action="/prices/station/' not in page
    assert admin.post(f"/prices/station/{IDS['st_a']}", data={"price_per_kwh": "9", "csrf": csrf(admin, "/orgs")}
                      ).status_code == 403
    admin.post(f"/stations/{IDS['st_a']}", data={"name": "Garaža A", "security_profile": 1, "approved": "1",
                                                 "organization_id": IDS["a"], "price_per_kwh": "9",
                                                 "csrf": csrf(admin, "/orgs")})
    with session_scope() as s:
        assert s.get(Station, IDS["st_a"]).price_per_kwh == st_price
    # obični korisnik i admin druge organizacije ne mogu
    assert emp.get("/prices").status_code == 403
    assert mom.post(f"/prices/station/{IDS['st_a']}", data={"price_per_kwh": "1", "csrf": csrf(mom, "/app")}
                    ).status_code == 403
    # admin organizacije punionice može
    page = boss.get("/prices").text
    assert "Garaža A" in page and "Kućna" not in page
    tok = csrf(boss, "/prices")
    boss.post(f"/prices/station/{IDS['st_a']}", data={"price_per_kwh": "0,33", "csrf": tok})
    boss.post(f"/prices/access/{guest_grant}", data={"price_per_kwh": "", "csrf": tok})
    with session_scope() as s:
        assert s.get(Station, IDS["st_a"]).price_per_kwh == 0.33
        assert s.get(StationAccess, guest_grant).price_per_kwh is None
    # osobna dozvola bez cijene ne poništava cijenu organizacije
    with session_scope() as s:
        s.add(StationAccess(station_id=IDS["st_a"], user_id=IDS["a_emp"]))
        s.query(StationAccess).filter_by(station_id=IDS["st_a"], organization_id=IDS["a"]).one().price_per_kwh = 0.2
    assert services.authorize_tag("MTEMP1", "MT-A").price_per_kwh == 0.2
    with session_scope() as s:
        s.query(StationAccess).filter_by(station_id=IDS["st_a"], user_id=IDS["a_emp"]).delete()
        s.query(StationAccess).filter_by(station_id=IDS["st_a"], organization_id=IDS["a"]).one().price_per_kwh = 0.0
        s.get(StationAccess, guest_grant).price_per_kwh = 0.5
