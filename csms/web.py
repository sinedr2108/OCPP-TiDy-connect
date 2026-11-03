"""Web sučelje (admin + korisnik): prijava s MFA, punionice, RFID kartice, potrošnja kWh/EUR."""
from __future__ import annotations

import csv
import io
import secrets
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from starlette.middleware.sessions import SessionMiddleware

from . import config, ocpp_server
from .db import (ConnectorStatus, EventLog, RfidCard, Station, Transaction, User, get_setting,
                 log_event, session_scope, set_setting, utcnow)
from .security import (generate_station_password, hash_password, new_totp_secret, qr_svg, totp_uri,
                       verify_password, verify_totp)
from .vendors import VENDOR_PROFILES, normalize_id_tag

app = FastAPI(title="OCPP Charge CSMS", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=config.SECRET_KEY, same_site="strict",
                   https_only=config.COOKIE_SECURE, max_age=8 * 3600, session_cookie="csms_session")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["VENDORS"] = VENDOR_PROFILES

MAX_FAILED = 5
LOCK_MINUTES = 15


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    return resp


# ----------------------------------------------------------------- pomoćne

class Redirect(Exception):
    def __init__(self, url):
        self.url = url


@app.exception_handler(Redirect)
async def _redirect(request, exc: Redirect):
    return RedirectResponse(exc.url, status_code=303)


def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = request.session["csrf"] = secrets.token_urlsafe(32)
    return tok


async def check_csrf(request: Request):
    if request.method == "POST":
        form = await request.form()
        if not secrets.compare_digest(str(form.get("csrf", "")), request.session.get("csrf", "-")):
            raise HTTPException(403, "CSRF provjera nije prošla")


def current_user(request: Request) -> User:
    uid = request.session.get("uid")
    if not uid:
        raise Redirect("/login")
    with session_scope() as s:
        u = s.get(User, uid)
        if not u or not u.active:
            request.session.clear()
            raise Redirect("/login")
        return u


def admin_user(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(403, "Samo za administratore")
    return user


def render(request: Request, name: str, user: User | None = None, **ctx):
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(request, name, {"user": user, "csrf": csrf_token(request),
                                                      "flash": flash, **ctx})


def flash(request: Request, msg: str):
    request.session["flash"] = msg


def month_start(dt: datetime | None = None) -> datetime:
    dt = dt or utcnow()
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def parse_date(v: str | None):
    try:
        return datetime.strptime(v, "%Y-%m-%d") if v else None
    except ValueError:
        return None


def tx_query(s, user: User, user_id=None, card_id=None, date_from=None, date_to=None):
    q = s.query(Transaction)
    if not user.is_admin:
        q = q.filter(Transaction.user_id == user.id)
    elif user_id:
        q = q.filter(Transaction.user_id == user_id)
    if card_id:
        q = q.filter(Transaction.card_id == card_id)
    if date_from:
        q = q.filter(Transaction.started_at >= date_from)
    if date_to:
        q = q.filter(Transaction.started_at < date_to + timedelta(days=1))
    return q


# ----------------------------------------------------------------- prijava + MFA

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return render(request, "login.html")


@app.post("/login", dependencies=[Depends(check_csrf)])
async def login(request: Request, email: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else "?"
    with session_scope() as s:
        u = s.query(User).filter_by(email=email.strip().lower()).one_or_none()
        if u and u.locked_until and u.locked_until > utcnow():
            flash(request, "Račun je privremeno zaključan zbog previše neuspjelih pokušaja.")
            return RedirectResponse("/login", 303)
        if not u or not u.active or not verify_password(password, u.password_hash):
            if u:
                u.failed_logins += 1
                if u.failed_logins >= MAX_FAILED:
                    u.locked_until, u.failed_logins = utcnow() + timedelta(minutes=LOCK_MINUTES), 0
            log_event(s, f"web:{ip}", "login_failed", email)
            flash(request, "Neispravan e-mail ili lozinka.")
            return RedirectResponse("/login", 303)
        u.failed_logins = 0
        request.session.clear()
        if u.mfa_enabled:
            request.session["mfa_uid"] = u.id
            return RedirectResponse("/login/mfa", 303)
        request.session["uid"] = u.id
        log_event(s, f"web:{ip}", "login", u.email)
    return RedirectResponse("/", 303)


@app.get("/login/mfa", response_class=HTMLResponse)
async def mfa_page(request: Request):
    if not request.session.get("mfa_uid"):
        return RedirectResponse("/login", 303)
    return render(request, "mfa.html")


@app.post("/login/mfa", dependencies=[Depends(check_csrf)])
async def mfa_verify(request: Request, code: str = Form(...)):
    uid = request.session.get("mfa_uid")
    if not uid:
        return RedirectResponse("/login", 303)
    with session_scope() as s:
        u = s.get(User, uid)
        if not u or not verify_totp(u.totp_secret, code):
            tries = request.session.get("mfa_tries", 0) + 1
            request.session["mfa_tries"] = tries
            if tries >= MAX_FAILED:
                request.session.clear()
            flash(request, "Neispravan kod.")
            return RedirectResponse("/login/mfa", 303)
        request.session.clear()
        request.session["uid"] = u.id
        log_event(s, "web", "login_mfa", u.email)
    return RedirectResponse("/", 303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", 303)


# ----------------------------------------------------------------- moj račun

@app.get("/account", response_class=HTMLResponse)
async def account(request: Request, user: User = Depends(current_user)):
    qr = secret = None
    if not user.mfa_enabled:
        secret = request.session.get("mfa_setup") or new_totp_secret()
        request.session["mfa_setup"] = secret
        qr = qr_svg(totp_uri(secret, user.email))
    return render(request, "account.html", user, qr=qr, secret=secret)


@app.post("/account/mfa/enable", dependencies=[Depends(check_csrf)])
async def mfa_enable(request: Request, code: str = Form(...), user: User = Depends(current_user)):
    secret = request.session.get("mfa_setup")
    if not secret or not verify_totp(secret, code):
        flash(request, "Kod nije ispravan, pokušaj ponovno.")
    else:
        with session_scope() as s:
            u = s.get(User, user.id)
            u.totp_secret, u.mfa_enabled = secret, True
        request.session.pop("mfa_setup", None)
        flash(request, "Dvofaktorska autentifikacija je uključena.")
    return RedirectResponse("/account", 303)


@app.post("/account/password", dependencies=[Depends(check_csrf)])
async def change_password(request: Request, old: str = Form(...), new: str = Form(...),
                          user: User = Depends(current_user)):
    if len(new) < 10:
        flash(request, "Nova lozinka mora imati barem 10 znakova.")
    elif not verify_password(old, user.password_hash):
        flash(request, "Stara lozinka nije ispravna.")
    else:
        with session_scope() as s:
            s.get(User, user.id).password_hash = hash_password(new)
        flash(request, "Lozinka promijenjena.")
    return RedirectResponse("/account", 303)


# ----------------------------------------------------------------- nadzorna ploča i potrošnja

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: User = Depends(current_user)):
    with session_scope() as s:
        def agg(q):
            e, c, n = q.with_entities(func.coalesce(func.sum(Transaction.energy_wh), 0),
                                      func.coalesce(func.sum(Transaction.cost_eur), 0),
                                      func.count(Transaction.id)).one()
            return {"kwh": round(e / 1000, 2), "eur": round(c, 2), "count": n}
        month = agg(tx_query(s, user, date_from=month_start()))
        total = agg(tx_query(s, user))
        active = tx_query(s, user).filter(Transaction.active.is_(True)).order_by(Transaction.started_at.desc()).all()
        recent = tx_query(s, user).order_by(Transaction.started_at.desc()).limit(10).all()
        for t in active + recent:
            _ = t.station, t.card, t.user
        cards = s.query(RfidCard).filter_by(user_id=user.id).all()
        stations = s.query(Station).order_by(Station.charge_point_id).all() if user.is_admin else []
    return render(request, "dashboard.html", user, month=month, total=total, active=active, recent=recent,
                  cards=cards, stations=stations, online=set(ocpp_server.CONNECTED))


@app.get("/reports", response_class=HTMLResponse)
async def reports(request: Request, user: User = Depends(current_user), date_from: str = "", date_to: str = ""):
    df = parse_date(date_from) or month_start()
    dt = parse_date(date_to)
    with session_scope() as s:
        base = tx_query(s, user, date_from=df, date_to=dt)
        cols = (func.sum(Transaction.energy_wh), func.sum(Transaction.cost_eur), func.count(Transaction.id))
        by_user = (base.outerjoin(User, Transaction.user_id == User.id)
                   .with_entities(User.id, User.name, User.email, *cols).group_by(User.id).all())
        by_card = (base.outerjoin(RfidCard, Transaction.card_id == RfidCard.id)
                   .with_entities(RfidCard.id, RfidCard.uid, RfidCard.label, Transaction.id_tag, *cols)
                   .group_by(RfidCard.id, Transaction.id_tag).all())
    return render(request, "reports.html", user, by_user=by_user, by_card=by_card,
                  date_from=df.strftime("%Y-%m-%d"), date_to=dt.strftime("%Y-%m-%d") if dt else "")


@app.get("/sessions", response_class=HTMLResponse)
async def sessions(request: Request, user: User = Depends(current_user), user_id: int | None = None,
                   card_id: int | None = None, date_from: str = "", date_to: str = ""):
    with session_scope() as s:
        rows = (tx_query(s, user, user_id, card_id, parse_date(date_from), parse_date(date_to))
                .order_by(Transaction.started_at.desc()).limit(500).all())
        for t in rows:
            _ = t.station, t.card, t.user
        users = s.query(User).order_by(User.name).all() if user.is_admin else []
        cards = s.query(RfidCard).order_by(RfidCard.uid).all() if user.is_admin else \
            s.query(RfidCard).filter_by(user_id=user.id).all()
    tot_kwh = round(sum(t.energy_wh for t in rows) / 1000, 2)
    tot_eur = round(sum(t.cost_eur for t in rows), 2)
    qs = str(request.url.query)
    return render(request, "sessions.html", user, rows=rows, users=users, cards=cards, tot_kwh=tot_kwh,
                  tot_eur=tot_eur, f=dict(user_id=user_id, card_id=card_id, date_from=date_from,
                                          date_to=date_to), qs=qs)


@app.get("/sessions.csv")
async def sessions_csv(user: User = Depends(current_user), user_id: int | None = None,
                       card_id: int | None = None, date_from: str = "", date_to: str = ""):
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["ID", "Punionica", "Konektor", "Korisnik", "Kartica", "Početak (UTC)", "Kraj (UTC)",
                "kWh", "Cijena EUR/kWh", "Iznos EUR"])
    with session_scope() as s:
        for t in (tx_query(s, user, user_id, card_id, parse_date(date_from), parse_date(date_to))
                  .order_by(Transaction.started_at)):
            w.writerow([t.id, t.station.charge_point_id, t.connector_id, t.user.email if t.user else "",
                        t.id_tag, t.started_at.strftime("%Y-%m-%d %H:%M"),
                        t.stopped_at.strftime("%Y-%m-%d %H:%M") if t.stopped_at else "",
                        f"{t.energy_kwh:.3f}".replace(".", ","), f"{t.price_per_kwh:.4f}".replace(".", ","),
                        f"{t.cost_eur:.2f}".replace(".", ",")])
    return StreamingResponse(iter(["﻿" + buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=punjenja.csv"})


# ----------------------------------------------------------------- admin: punionice

@app.get("/stations", response_class=HTMLResponse)
async def stations(request: Request, user: User = Depends(admin_user)):
    with session_scope() as s:
        rows = s.query(Station).order_by(Station.charge_point_id).all()
    return render(request, "stations.html", user, rows=rows, online=set(ocpp_server.CONNECTED),
                  ws_port=config.OCPP_WS_PORT, wss_port=config.OCPP_WSS_PORT, host=config.PUBLIC_HOSTNAME)


@app.post("/stations", dependencies=[Depends(check_csrf)])
async def station_add(request: Request, charge_point_id: str = Form(...), name: str = Form(""),
                      vendor_profile: str = Form("generic"), security_profile: int = Form(2),
                      user: User = Depends(admin_user)):
    cp_id = charge_point_id.strip()
    pw = generate_station_password()
    with session_scope() as s:
        if s.query(Station).filter_by(charge_point_id=cp_id).first():
            flash(request, "Punionica s tim ID-em već postoji.")
            return RedirectResponse("/stations", 303)
        st = Station(charge_point_id=cp_id, name=name or cp_id, vendor_profile=vendor_profile,
                     security_profile=security_profile, password_hash=hash_password(pw), approved=True)
        s.add(st)
        s.flush()
        sid = st.id
    request.session["new_pw"] = pw
    return RedirectResponse(f"/stations/{sid}", 303)


@app.get("/stations/{sid}", response_class=HTMLResponse)
async def station_detail(request: Request, sid: int, user: User = Depends(admin_user)):
    with session_scope() as s:
        st = s.get(Station, sid) or (_ for _ in ()).throw(HTTPException(404))
        conns = s.query(ConnectorStatus).filter_by(station_id=sid).order_by(ConnectorStatus.connector_id).all()
        active = s.query(Transaction).filter_by(station_id=sid, active=True).all()
        cards = s.query(RfidCard).filter_by(active=True).order_by(RfidCard.uid).all()
        events = (s.query(EventLog).filter_by(source=st.charge_point_id)
                  .order_by(EventLog.ts.desc()).limit(30).all())
        default_price = get_setting(s, "price_per_kwh")
    return render(request, "station.html", user, st=st, conns=conns, active=active, cards=cards, events=events,
                  online=st.charge_point_id in ocpp_server.CONNECTED, new_pw=request.session.pop("new_pw", None),
                  default_price=default_price, ws_port=config.OCPP_WS_PORT, wss_port=config.OCPP_WSS_PORT,
                  host=config.PUBLIC_HOSTNAME)


@app.post("/stations/{sid}", dependencies=[Depends(check_csrf)])
async def station_update(request: Request, sid: int, name: str = Form(""), location: str = Form(""),
                         vendor_profile: str = Form("generic"), security_profile: int = Form(...),
                         price_per_kwh: str = Form(""), approved: str = Form(""),
                         user: User = Depends(admin_user)):
    with session_scope() as s:
        st = s.get(Station, sid)
        st.name, st.location, st.vendor_profile = name, location, vendor_profile
        st.security_profile = max(0, min(3, security_profile))
        st.price_per_kwh = float(price_per_kwh.replace(",", ".")) if price_per_kwh.strip() else None
        st.approved = bool(approved)
        log_event(s, st.charge_point_id, "station_updated", f"by {user.email}")
    flash(request, "Spremljeno. Promjena odobrenja vrijedi od sljedećeg spajanja punionice.")
    return RedirectResponse(f"/stations/{sid}", 303)


@app.post("/stations/{sid}/password", dependencies=[Depends(check_csrf)])
async def station_password(request: Request, sid: int, push: str = Form(""), user: User = Depends(admin_user)):
    pw = generate_station_password()
    with session_scope() as s:
        st = s.get(Station, sid)
        cp_id = st.charge_point_id
    if push and cp_id in ocpp_server.CONNECTED:
        # prvo pošalji punionici, tek onda spremi (inače bi se zaključala)
        try:
            res = await ocpp_server.send_command(cp_id, "set_password", pw)
        except Exception as e:
            res = f"greška: {e}"
        if res != "Accepted":
            flash(request, f"Punionica nije prihvatila novu lozinku ({res}). Lozinka nije promijenjena.")
            return RedirectResponse(f"/stations/{sid}", 303)
    with session_scope() as s:
        s.get(Station, sid).password_hash = hash_password(pw)
        log_event(s, cp_id, "password_rotated", f"by {user.email}")
    request.session["new_pw"] = pw
    return RedirectResponse(f"/stations/{sid}", 303)


COMMANDS = {"reset": "Soft reset", "reset_hard": "Hard reset", "unlock": "Otključaj konektor",
            "install_ca": "Instaliraj CA certifikat", "request_csr": "Zatraži klijentski certifikat (CSR)",
            "remote_start": "Daljinski start", "remote_stop": "Daljinski stop", "set_profile": "Postavi sigurnosni profil"}


@app.post("/stations/{sid}/command", dependencies=[Depends(check_csrf)])
async def station_command(request: Request, sid: int, cmd: str = Form(...), card_uid: str = Form(""),
                          connector_id: int = Form(1), tx_id: str = Form(""), profile: int = Form(0),
                          user: User = Depends(admin_user)):
    with session_scope() as s:
        cp_id = s.get(Station, sid).charge_point_id
    calls = {
        "reset": ("reset", (False,)), "reset_hard": ("reset", (True,)), "unlock": ("unlock", (connector_id,)),
        "install_ca": ("install_ca", ()), "request_csr": ("request_csr", ()),
        "remote_start": ("remote_start", (card_uid, connector_id)), "remote_stop": ("remote_stop", (tx_id,)),
        "set_profile": ("set_security_profile", (profile,)),
    }
    if cmd not in calls:
        raise HTTPException(400)
    method, args = calls[cmd]
    try:
        res = await ocpp_server.send_command(cp_id, method, *args)
    except Exception as e:
        res = f"greška: {e}"
    with session_scope() as s:
        log_event(s, cp_id, f"command:{cmd}", f"{res} (by {user.email})")
    flash(request, f"{COMMANDS.get(cmd, cmd)}: {res}")
    return RedirectResponse(f"/stations/{sid}", 303)


@app.get("/pki/ca.crt")
async def ca_download(user: User = Depends(admin_user)):
    from .security import ca_pem
    return StreamingResponse(iter([ca_pem()]), media_type="application/x-pem-file",
                             headers={"Content-Disposition": "attachment; filename=ocpp-charge-ca.crt"})


# ----------------------------------------------------------------- admin: kartice

@app.get("/cards", response_class=HTMLResponse)
async def cards(request: Request, user: User = Depends(current_user)):
    with session_scope() as s:
        q = s.query(RfidCard) if user.is_admin else s.query(RfidCard).filter_by(user_id=user.id)
        rows = q.order_by(RfidCard.uid).all()
        for c in rows:
            _ = c.user
        users = s.query(User).order_by(User.name).all() if user.is_admin else []
    return render(request, "cards.html", user, rows=rows, users=users)


@app.post("/cards", dependencies=[Depends(check_csrf)])
async def card_add(request: Request, uid: str = Form(...), label: str = Form(""), user_id: str = Form(""),
                   user: User = Depends(admin_user)):
    tag = normalize_id_tag(uid)
    if not tag or len(tag) > 36:
        flash(request, "Neispravan UID kartice.")
        return RedirectResponse("/cards", 303)
    with session_scope() as s:
        if s.query(RfidCard).filter_by(uid=tag).first():
            flash(request, "Kartica već postoji.")
        else:
            s.add(RfidCard(uid=tag, label=label, user_id=int(user_id) if user_id else None))
            flash(request, f"Kartica {tag} dodana.")
    return RedirectResponse("/cards", 303)


@app.post("/cards/{cid}", dependencies=[Depends(check_csrf)])
async def card_update(request: Request, cid: int, action: str = Form(...), user_id: str = Form(""),
                      user: User = Depends(admin_user)):
    with session_scope() as s:
        c = s.get(RfidCard, cid)
        if action == "toggle":
            c.active = not c.active
        elif action == "assign":
            c.user_id = int(user_id) if user_id else None
        log_event(s, "web", f"card_{action}", f"{c.uid} by {user.email}")
    return RedirectResponse("/cards", 303)


# ----------------------------------------------------------------- admin: korisnici, postavke, događaji

@app.get("/users", response_class=HTMLResponse)
async def users(request: Request, user: User = Depends(admin_user)):
    with session_scope() as s:
        rows = s.query(User).order_by(User.name).all()
    return render(request, "users.html", user, rows=rows)


@app.post("/users", dependencies=[Depends(check_csrf)])
async def user_add(request: Request, email: str = Form(...), name: str = Form(""), password: str = Form(...),
                   is_admin: str = Form(""), user: User = Depends(admin_user)):
    if len(password) < 10:
        flash(request, "Lozinka mora imati barem 10 znakova.")
        return RedirectResponse("/users", 303)
    with session_scope() as s:
        if s.query(User).filter_by(email=email.strip().lower()).first():
            flash(request, "Korisnik s tim e-mailom već postoji.")
        else:
            s.add(User(email=email.strip().lower(), name=name, password_hash=hash_password(password),
                       is_admin=bool(is_admin)))
            flash(request, "Korisnik dodan.")
    return RedirectResponse("/users", 303)


@app.post("/users/{uid}", dependencies=[Depends(check_csrf)])
async def user_update(request: Request, uid: int, action: str = Form(...), user: User = Depends(admin_user)):
    with session_scope() as s:
        u = s.get(User, uid)
        if action == "toggle_active" and u.id != user.id:
            u.active = not u.active
        elif action == "reset_mfa":
            u.mfa_enabled, u.totp_secret = False, None
        elif action == "unlock":
            u.locked_until, u.failed_logins = None, 0
        log_event(s, "web", f"user_{action}", f"{u.email} by {user.email}")
    return RedirectResponse("/users", 303)


@app.get("/settings", response_class=HTMLResponse)
async def settings(request: Request, user: User = Depends(admin_user)):
    with session_scope() as s:
        price = get_setting(s, "price_per_kwh")
        events = s.query(EventLog).order_by(EventLog.ts.desc()).limit(100).all()
    return render(request, "settings.html", user, price=price, events=events)


@app.post("/settings", dependencies=[Depends(check_csrf)])
async def settings_save(request: Request, price_per_kwh: str = Form(...), user: User = Depends(admin_user)):
    try:
        p = float(price_per_kwh.replace(",", "."))
        assert 0 <= p < 100
    except Exception:
        flash(request, "Neispravna cijena.")
        return RedirectResponse("/settings", 303)
    with session_scope() as s:
        set_setting(s, "price_per_kwh", str(p))
        log_event(s, "web", "price_changed", f"{p} by {user.email}")
    flash(request, "Cijena spremljena (vrijedi za nova punjenja).")
    return RedirectResponse("/settings", 303)
