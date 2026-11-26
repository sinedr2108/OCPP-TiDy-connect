"""Administrator uređuje korisnike: podaci, lozinka, uloga, organizacija, kartice; poštuje organizaciju."""
import re

from fastapi.testclient import TestClient

from csms.db import Organization, RfidCard, User, session_scope
from csms.security import hash_password, verify_password
from csms.web import app

PW = "lozinka12345"
IDS = {}


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def login(email, pw=PW):
    c = TestClient(app)
    r = c.post("/login", data={"email": email, "password": pw, "csrf": csrf(c, "/login")}, follow_redirects=False)
    return c, r


def setup_module():
    with session_scope() as s:
        x, y = Organization(name="UE Tvrtka X"), Organization(name="UE Tvrtka Y")
        s.add_all([x, y]); s.flush()
        users = {
            "root": User(email="ue-root@test.hr", password_hash=hash_password(PW), is_admin=True),
            "x_boss": User(email="ue-xboss@test.hr", password_hash=hash_password(PW), organization_id=x.id,
                           org_role="admin"),
            "x_emp": User(email="ue-xemp@test.hr", name="Ivo", password_hash=hash_password(PW), organization_id=x.id),
            "y_emp": User(email="ue-yemp@test.hr", password_hash=hash_password(PW), organization_id=y.id),
        }
        s.add_all(users.values()); s.flush()
        s.add_all([RfidCard(uid="UEX1", user_id=users["x_emp"].id, organization_id=x.id),
                   RfidCard(uid="UEXFREE", organization_id=x.id),
                   RfidCard(uid="UEYFREE", organization_id=y.id)])
        IDS.update({k: u.id for k, u in users.items()}, x=x.id, y=y.id)


def get_user(key):
    with session_scope() as s:
        return s.get(User, IDS[key])


def test_org_admin_edits_own_member():
    c, _ = login("ue-xboss@test.hr")
    assert 'href="/users/%d"' % IDS["x_emp"] in c.get("/users").text
    page = c.get(f"/users/{IDS['x_emp']}").text
    assert "UEX1" in page and "UEXFREE" in page and "UEYFREE" not in page
    tok = csrf(c, f"/users/{IDS['x_emp']}")
    r = c.post(f"/users/{IDS['x_emp']}/edit", follow_redirects=False,
               data={"csrf": tok, "name": "Ivo Ivić", "email": "Ivo.Novi@test.hr", "org_role": "admin",
                     "active": "1", "notify_email": "1", "is_admin": "1", "organization_id": str(IDS["y"])})
    assert r.headers["location"] == f"/users/{IDS['x_emp']}"
    u = get_user("x_emp")
    assert (u.name, u.email, u.org_role, u.notify_email, u.notify_push) == \
        ("Ivo Ivić", "ivo.novi@test.hr", "admin", True, False)
    assert u.organization_id == IDS["x"] and not u.is_admin  # org admin ne mijenja organizaciju ni admina platforme


def test_org_admin_sets_password_and_unlocks():
    with session_scope() as s:
        s.get(User, IDS["x_emp"]).failed_logins = 7
    c, _ = login("ue-xboss@test.hr")
    tok = csrf(c, f"/users/{IDS['x_emp']}")
    c.post(f"/users/{IDS['x_emp']}/password", data={"csrf": tok, "password": "kratka"})
    assert verify_password(PW, get_user("x_emp").password_hash)  # prekratka se odbija
    c.post(f"/users/{IDS['x_emp']}/password", data={"csrf": tok, "password": "NovaLozinka123"})
    u = get_user("x_emp")
    assert verify_password("NovaLozinka123", u.password_hash) and u.failed_logins == 0
    _, r = login(u.email, "NovaLozinka123")
    assert r.headers["location"] != "/login"
    # generirana lozinka prikaže se jednom
    page = c.post(f"/users/{IDS['x_emp']}/password", data={"csrf": tok, "generate": "1"}).text
    new_pw = re.search(r"Nova lozinka za \S+: (\w{20})", page).group(1)
    assert verify_password(new_pw, get_user("x_emp").password_hash)


def test_org_admin_cannot_touch_other_org_or_platform_admin():
    c, _ = login("ue-xboss@test.hr")
    tok = csrf(c, "/users")
    for key in ("y_emp", "root"):
        assert c.get(f"/users/{IDS[key]}").status_code == 404
        assert c.post(f"/users/{IDS[key]}/edit", data={"csrf": tok, "email": "hack@test.hr"}).status_code == 404
        assert c.post(f"/users/{IDS[key]}/password", data={"csrf": tok, "password": "HakiranaLoz1"}).status_code == 404
    assert verify_password(PW, get_user("y_emp").password_hash)
    with session_scope() as s:
        yfree = s.query(RfidCard).filter_by(uid="UEYFREE").one().id
    assert c.post(f"/users/{IDS['x_emp']}/cards", data={"csrf": tok, "card_id": yfree}).status_code == 404


def test_cannot_demote_or_deactivate_self():
    c, _ = login("ue-xboss@test.hr")
    tok = csrf(c, f"/users/{IDS['x_boss']}")
    c.post(f"/users/{IDS['x_boss']}/edit", data={"csrf": tok, "email": "ue-xboss@test.hr", "org_role": "member"})
    u = get_user("x_boss")
    assert u.org_role == "admin" and u.active


def test_duplicate_email_rejected():
    c, _ = login("ue-root@test.hr")
    tok = csrf(c, f"/users/{IDS['y_emp']}")
    page = c.post(f"/users/{IDS['y_emp']}/edit", data={"csrf": tok, "email": "ue-xboss@test.hr", "active": "1"}).text
    assert "već postoji" in page
    assert get_user("y_emp").email == "ue-yemp@test.hr"


def test_cards_managed_from_user_page():
    c, _ = login("ue-xboss@test.hr")
    uid = IDS["x_emp"]
    tok = csrf(c, f"/users/{uid}")
    with session_scope() as s:
        free = s.query(RfidCard).filter_by(uid="UEXFREE").one().id
        own = s.query(RfidCard).filter_by(uid="UEX1").one().id
    r = c.post(f"/users/{uid}/cards", data={"csrf": tok, "card_id": free}, follow_redirects=False)
    assert r.headers["location"] == f"/users/{uid}"
    r = c.post("/cards", data={"csrf": tok, "uid": "ue:new:01", "label": "Auto", "user_id": uid,
                               "back": f"/users/{uid}"}, follow_redirects=False)
    assert r.headers["location"] == f"/users/{uid}"
    c.post(f"/cards/{own}", data={"csrf": tok, "action": "label", "label": "Službena", "back": f"/users/{uid}"})
    c.post(f"/cards/{own}", data={"csrf": tok, "action": "assign", "user_id": "", "back": f"/users/{uid}"})
    with session_scope() as s:
        assert s.get(RfidCard, free).user_id == uid
        assert s.query(RfidCard).filter_by(uid="UENEW01").one().user_id == uid
        o = s.get(RfidCard, own)
        assert o.label == "Službena" and o.user_id is None
    # vanjski back se ignorira
    r = c.post(f"/cards/{own}", data={"csrf": tok, "action": "toggle", "back": "//zlo.hr"}, follow_redirects=False)
    assert r.headers["location"] == "/cards"


def test_platform_admin_moves_user_with_cards_and_promotes():
    c, _ = login("ue-root@test.hr")
    uid = IDS["x_emp"]
    tok = csrf(c, f"/users/{uid}")
    c.post(f"/users/{uid}/edit", data={"csrf": tok, "email": "ivo.novi@test.hr", "name": "Ivo",
                                       "organization_id": str(IDS["y"]), "org_role": "member", "active": "1"})
    u = get_user("x_emp")
    assert u.organization_id == IDS["y"] and u.org_role == "member"
    with session_scope() as s:
        assert {card.organization_id for card in s.query(RfidCard).filter_by(user_id=uid)} == {IDS["y"]}
    c.post(f"/users/{IDS['y_emp']}/edit", data={"csrf": tok, "email": "ue-yemp@test.hr", "is_admin": "1"})
    u = get_user("y_emp")
    assert u.is_admin and not u.active  # bez kvačice "aktivan" postaje neaktivan
    # admin platforme ne može sam sebi oduzeti ovlasti
    c.post(f"/users/{IDS['root']}/edit", data={"csrf": tok, "email": "ue-root@test.hr"})
    u = get_user("root")
    assert u.is_admin and u.active
