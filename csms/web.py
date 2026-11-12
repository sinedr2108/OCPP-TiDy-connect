"""Web sučelje (admin + korisnik): prijava s MFA, punionice, RFID kartice, potrošnja kWh/EUR."""
from __future__ import annotations

import csv
import io
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
from starlette.middleware.sessions import SessionMiddleware

from . import config, ocpp_server, services
from .db import (ORG_KINDS, ConnectorStatus, EventLog, Organization, RfidCard, Station, StationAccess,
                 Transaction, User, get_setting, log_event, session_scope, set_setting, utcnow)
from .security import (generate_station_password, hash_password, new_totp_secret, qr_svg, totp_uri,
                       verify_password, verify_totp)
from .timeutil import current_month, fmt, local_to_utc, month_bounds, to_local
from .vendors import VENDOR_PROFILES, normalize_id_tag

app = FastAPI(title="TiDy Charge CSMS", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=config.SECRET_KEY, same_site="strict",
                   https_only=config.COOKIE_SECURE, max_age=8 * 3600, session_cookie="csms_session")
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["VENDORS"] = VENDOR_PROFILES
templates.env.globals["ORG_KINDS"] = ORG_KINDS
templates.env.filters["dt"] = fmt  # {{ t.started_at|dt('%d.%m. %H:%M') }} -> lokalno vrijeme

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
        if request.method == "GET" and request.url.path.startswith("/app/"):
            raise Redirect("/login?next=" + quote(request.url.path))
        raise Redirect("/login")
    with session_scope() as s:
        u = s.get(User, uid)
        if not u or not u.active:
            request.session.clear()
            raise Redirect("/login")
        return u


def admin_user(user: User = Depends(current_user)) -> User:
    """Administrator cijele platforme."""
    if not user.is_admin:
        raise HTTPException(403, "Samo za administratore")
    return user


def manager_user(user: User = Depends(current_user)) -> User:
    """Administrator platforme ili administrator svoje organizacije."""
    if not user.is_manager:
        raise HTTPException(403, "Samo za administratore")
    return user


def org_name(s, user: User) -> str:
    org = s.get(Organization, user.organization_id) if user.organization_id else None
    return org.name if org else ""


def users_in_scope(s, user: User):
    q = s.query(User)
    if not user.is_admin:
        q = q.filter(User.organization_id == user.organization_id)
    return q


def cards_in_scope(s, user: User):
    """Kartice koje korisnik smije vidjeti: admin sve, admin organizacije kartice organizacije, ostali svoje."""
    q = s.query(RfidCard)
    if user.is_admin:
        return q
    if user.is_org_admin:
        members = select(User.id).where(User.organization_id == user.organization_id)
        return q.filter(or_(RfidCard.organization_id == user.organization_id, RfidCard.user_id.in_(members)))
    return q.filter(RfidCard.user_id == user.id)


def safe_next(url: str | None) -> str | None:
    return url if url and url.startswith("/") and not url.startswith("//") else None


def render(request: Request, name: str, user: User | None = None, **ctx):
    flash = request.session.pop("flash", None)
    return templates.TemplateResponse(request, name, {"user": user, "csrf": csrf_token(request),
                                                      "flash": flash, **ctx})


def flash(request: Request, msg: str):
    request.session["flash"] = msg


def month_start() -> datetime:
    """Početak tekućeg lokalnog mjeseca (naivni UTC, za upite)."""
    return month_bounds(*current_month())[0]


def utc_from(v: str | None):
    d = parse_date(v)
    return local_to_utc(d) if d else None


def parse_date(v: str | None):
    try:
        return datetime.strptime(v, "%Y-%m-%d") if v else None
    except ValueError:
        return None


def tx_query(s, user: User, user_id=None, card_id=None, date_from=None, date_to=None):
    """date_from/date_to su naivni UTC (month_start) ili lokalni datumi iz forme (parse_date -> pretvoreni)."""
    q = s.query(Transaction)
    if user.is_org_admin and not user.is_admin:
        # punjenja članova organizacije i sva punjenja na punionicama organizacije (npr. gosti)
        org = user.organization_id
        own_stations = select(Station.id).where(Station.organization_id == org)
        q = q.filter(or_(Transaction.organization_id == org, Transaction.station_id.in_(own_stations)))
    elif not user.is_admin:
        q = q.filter(Transaction.user_id == user.id)
    if user_id and user.is_manager:
        q = q.filter(Transaction.user_id == user_id)
    if card_id:
        q = q.filter(Transaction.card_id == card_id)
    if date_from:
        q = q.filter(Transaction.started_at >= date_from)
    if date_to:
        q = q.filter(Transaction.started_at < local_to_utc(date_to + timedelta(days=1)))
    return q


# ----------------------------------------------------------------- prijava + MFA

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = ""):
    if safe_next(next):
        request.session["next"] = next
    return render(request, "login.html")


def after_login(request: Request, u: User) -> str:
    return safe_next(request.session.pop("next", None)) or ("/" if u.is_manager else "/app")


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
        nxt = request.session.get("next")
        request.session.clear()
        if nxt:
            request.session["next"] = nxt
        if u.mfa_enabled:
            request.session["mfa_uid"] = u.id
            return RedirectResponse("/login/mfa", 303)
        request.session["uid"] = u.id
        log_event(s, f"web:{ip}", "login", u.email)
        dest = after_login(request, u)
    return RedirectResponse(dest, 303)


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
        nxt = request.session.get("next")
        request.session.clear()
        if nxt:
            request.session["next"] = nxt
        request.session["uid"] = u.id
        log_event(s, "web", "login_mfa", u.email)
        dest = after_login(request, u)
    return RedirectResponse(dest, 303)


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

def tx_totals(q) -> dict:
    e, c, n = q.with_entities(func.coalesce(func.sum(Transaction.energy_wh), 0),
                              func.coalesce(func.sum(Transaction.cost_eur), 0),
                              func.count(Transaction.id)).one()
    return {"kwh": round(e / 1000, 2), "eur": round(c, 2), "count": n}


def stations_for(s, user: User) -> list[Station]:
    ids = services.allowed_station_ids(s, user)
    q = s.query(Station).filter(Station.approved.is_(True)) if not user.is_admin else s.query(Station)
    if ids is not None:
        q = q.filter(Station.id.in_(ids or [-1]))
    return q.order_by(Station.name, Station.charge_point_id).all()


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: User = Depends(current_user)):
    with session_scope() as s:
        month = tx_totals(tx_query(s, user, date_from=month_start()))
        total = tx_totals(tx_query(s, user))
        active = tx_query(s, user).filter(Transaction.active.is_(True)).order_by(Transaction.started_at.desc()).all()
        recent = tx_query(s, user).order_by(Transaction.started_at.desc()).limit(10).all()
        for t in active + recent:
            _ = t.station, t.card, t.user
        cards = s.query(RfidCard).filter_by(user_id=user.id, app_token=False).all()
        stations = stations_for(s, user) if user.is_manager else []
        org = org_name(s, user)
    return render(request, "dashboard.html", user, month=month, total=total, active=active, recent=recent,
                  cards=cards, stations=stations, online=set(ocpp_server.CONNECTED), org=org)


@app.get("/reports", response_class=HTMLResponse)
async def reports(request: Request, user: User = Depends(current_user), date_from: str = "", date_to: str = ""):
    df = parse_date(date_from) or datetime(*current_month(), 1)  # lokalni datum
    dt = parse_date(date_to)
    with session_scope() as s:
        base = tx_query(s, user, date_from=local_to_utc(df), date_to=dt)
        cols = (func.sum(Transaction.energy_wh), func.sum(Transaction.cost_eur), func.count(Transaction.id))
        by_user = (base.outerjoin(User, Transaction.user_id == User.id)
                   .with_entities(User.id, User.name, User.email, *cols).group_by(User.id).all())
        by_card = (base.outerjoin(RfidCard, Transaction.card_id == RfidCard.id)
                   .with_entities(RfidCard.id, RfidCard.uid, RfidCard.label, Transaction.id_tag, *cols)
                   .group_by(RfidCard.id, Transaction.id_tag).all())
        by_org = (base.outerjoin(Organization, Transaction.organization_id == Organization.id)
                  .with_entities(Organization.id, Organization.name, *cols).group_by(Organization.id).all()
                  if user.is_admin else [])
        by_station = (base.join(Station, Transaction.station_id == Station.id)
                      .with_entities(Station.id, Station.name, Station.charge_point_id, *cols)
                      .group_by(Station.id).all() if user.is_manager else [])
        orgs = s.query(Organization).order_by(Organization.name).all() if user.is_admin else []
        users = users_in_scope(s, user).order_by(User.name).all() if user.is_manager else []
    return render(request, "reports.html", user, by_user=by_user, by_card=by_card, by_org=by_org, orgs=orgs, users=users,
                  by_station=by_station, date_from=df.strftime("%Y-%m-%d"),
                  date_to=dt.strftime("%Y-%m-%d") if dt else "")


@app.get("/sessions", response_class=HTMLResponse)
async def sessions(request: Request, user: User = Depends(current_user), user_id: int | None = None,
                   card_id: int | None = None, date_from: str = "", date_to: str = ""):
    with session_scope() as s:
        rows = (tx_query(s, user, user_id, card_id, utc_from(date_from), parse_date(date_to))
                .order_by(Transaction.started_at.desc()).limit(500).all())
        for t in rows:
            _ = t.station, t.card, t.user
        users = users_in_scope(s, user).order_by(User.name).all() if user.is_manager else []
        cards = cards_in_scope(s, user).order_by(RfidCard.uid).all()
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
    w.writerow(["ID", "Punionica", "Konektor", "Organizacija", "Korisnik", "Kartica", "Početak",
                "Kraj", "kWh", "Cijena EUR/kWh", "Iznos EUR"])
    with session_scope() as s:
        orgs = {o.id: o.name for o in s.query(Organization)}
        for t in (tx_query(s, user, user_id, card_id, utc_from(date_from), parse_date(date_to))
                  .order_by(Transaction.started_at)):
            w.writerow([t.id, t.station.charge_point_id, t.connector_id, orgs.get(t.organization_id, ""),
                        t.user.email if t.user else "", t.id_tag, fmt(t.started_at, "%Y-%m-%d %H:%M"), fmt(t.stopped_at, "%Y-%m-%d %H:%M"),
                        f"{t.energy_kwh:.3f}".replace(".", ","), f"{t.price_per_kwh:.4f}".replace(".", ","),
                        f"{t.cost_eur:.2f}".replace(".", ",")])
    return StreamingResponse(iter(["﻿" + buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=punjenja.csv"})


# ----------------------------------------------------------------- mjesečni PDF obračun

def parse_month(v: str) -> tuple[int, int]:
    try:
        y, m = (int(x) for x in v.split("-"))
        assert 2000 <= y <= 2100 and 1 <= m <= 12
        return y, m
    except Exception:
        return current_month()


@app.get("/reports/pdf")
async def report_pdf(user: User = Depends(current_user), month: str = "", org_id: int | None = None,
                     user_id: int | None = None):
    """Obračun za mjesec: korisnik dobiva svoj, admin organizacije svoju organizaciju (ili člana),
    administrator platforme bilo koju organizaciju, korisnika ili sve."""
    from .pdf_report import Row, Statement, build
    y, m = parse_month(month)
    start, end = month_bounds(y, m)
    with session_scope() as s:
        if not user.is_manager:
            org_id, user_id = None, user.id
        elif not user.is_admin:
            org_id = user.organization_id
            if user_id and (s.get(User, user_id) is None or s.get(User, user_id).organization_id != org_id):
                raise HTTPException(404)
        q = s.query(Transaction).filter(Transaction.started_at >= start, Transaction.started_at < end,
                                        Transaction.active.is_(False))
        if user_id:
            u = get_or_404(s, User, user_id)
            q = q.filter(Transaction.user_id == user_id)
            title, subtitle = u.name or u.email, u.email
        elif org_id:
            o = get_or_404(s, Organization, org_id)
            q = q.filter(Transaction.organization_id == org_id)
            title, subtitle = o.name, " · ".join(x for x in [o.kind_label, o.address] if x)
        else:
            title, subtitle = "Sve organizacije", ""
        rows = [Row(t.started_at, t.station.name or t.station.charge_point_id,
                    (t.user.name or t.user.email) if t.user else "—",
                    (t.card.label if t.card and t.card.app_token else t.id_tag) or "—",
                    t.energy_kwh, t.price_per_kwh, t.cost_eur) for t in q]
    pdf = build(Statement(title, subtitle, y, m, rows))
    fname = f"obracun-{y}-{m:02d}.pdf"
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


# ----------------------------------------------------------------- punionice

def get_or_404(s, model, oid):
    obj = s.get(model, oid)
    if obj is None:
        raise HTTPException(404)
    return obj


def parse_price(v: str) -> float | None:
    v = (v or "").strip().replace(",", ".")
    if not v:
        return None
    p = float(v)
    if not 0 <= p < 100:
        raise ValueError
    return p


@app.get("/stations", response_class=HTMLResponse)
async def stations(request: Request, user: User = Depends(manager_user)):
    with session_scope() as s:
        rows = stations_for(s, user)
        orgs = {o.id: o.name for o in s.query(Organization)}
    return render(request, "stations.html", user, rows=rows, orgs=orgs, online=set(ocpp_server.CONNECTED),
                  ws_url=config.PUBLIC_WS_URL, wss_url=config.PUBLIC_WSS_URL)


@app.post("/stations", dependencies=[Depends(check_csrf)])
async def station_add(request: Request, charge_point_id: str = Form(...), name: str = Form(""),
                      vendor_profile: str = Form("generic"), security_profile: int = Form(2),
                      organization_id: str = Form(""), user: User = Depends(admin_user)):
    cp_id = charge_point_id.strip()
    pw = generate_station_password()
    with session_scope() as s:
        if s.query(Station).filter_by(charge_point_id=cp_id).first():
            flash(request, "Punionica s tim ID-em već postoji.")
            return RedirectResponse("/stations", 303)
        org_id = int(organization_id) if organization_id else None
        st = Station(charge_point_id=cp_id, name=name or cp_id, vendor_profile=vendor_profile,
                     security_profile=security_profile, password_hash=hash_password(pw), approved=True,
                     organization_id=org_id)
        s.add(st)
        s.flush()
        if org_id:  # organizacija na čijoj je lokaciji punionica odmah dobiva pristup (može se ukloniti)
            s.add(StationAccess(station_id=st.id, organization_id=org_id))
        sid = st.id
    request.session["new_pw"] = pw
    return RedirectResponse(f"/stations/{sid}", 303)


@app.get("/stations/{sid}", response_class=HTMLResponse)
async def station_detail(request: Request, sid: int, user: User = Depends(admin_user)):
    with session_scope() as s:
        st = get_or_404(s, Station, sid)
        conns = s.query(ConnectorStatus).filter_by(station_id=sid).order_by(ConnectorStatus.connector_id).all()
        active = s.query(Transaction).filter_by(station_id=sid, active=True).all()
        cards = s.query(RfidCard).filter_by(active=True).order_by(RfidCard.uid).all()
        events = (s.query(EventLog).filter_by(source=st.charge_point_id)
                  .order_by(EventLog.ts.desc()).limit(30).all())
        default_price = get_setting(s, "price_per_kwh")
        grants = s.query(StationAccess).filter_by(station_id=sid).all()
        for g in grants:
            _ = g.organization, g.user
        orgs = s.query(Organization).order_by(Organization.name).all()
        users = s.query(User).filter(User.active.is_(True)).order_by(User.name, User.email).all()
    app_url = str(request.base_url).rstrip("/") + f"/app/station/{sid}"
    return render(request, "station.html", user, st=st, conns=conns, active=active, cards=cards, events=events,
                  online=st.charge_point_id in ocpp_server.CONNECTED, new_pw=request.session.pop("new_pw", None),
                  default_price=default_price, ws_url=config.PUBLIC_WS_URL, wss_url=config.PUBLIC_WSS_URL,
                  grants=grants, orgs=orgs, users=users, app_url=app_url, qr=qr_svg(app_url))


@app.post("/stations/{sid}", dependencies=[Depends(check_csrf)])
async def station_update(request: Request, sid: int, name: str = Form(""), location: str = Form(""),
                         vendor_profile: str = Form("generic"), security_profile: int = Form(...),
                         price_per_kwh: str = Form(""), approved: str = Form(""), organization_id: str = Form(""),
                         user: User = Depends(admin_user)):
    try:
        price = parse_price(price_per_kwh)
    except ValueError:
        flash(request, "Neispravna cijena.")
        return RedirectResponse(f"/stations/{sid}", 303)
    with session_scope() as s:
        st = get_or_404(s, Station, sid)
        st.name, st.location, st.vendor_profile = name, location, vendor_profile
        st.security_profile = max(0, min(3, security_profile))
        st.price_per_kwh = price
        st.approved = bool(approved)
        st.organization_id = int(organization_id) if organization_id else None
        log_event(s, st.charge_point_id, "station_updated", f"by {user.email}")
    flash(request, "Spremljeno. Promjena odobrenja vrijedi od sljedećeg spajanja punionice.")
    return RedirectResponse(f"/stations/{sid}", 303)


@app.post("/orgs/{oid}/access", dependencies=[Depends(check_csrf)])
async def org_access_add(request: Request, oid: int, station_id: int = Form(...), price_per_kwh: str = Form(""),
                         user: User = Depends(admin_user)):
    return await access_add(request, station_id, f"org:{oid}", price_per_kwh, f"/orgs/{oid}", user)


@app.post("/stations/{sid}/access", dependencies=[Depends(check_csrf)])
async def access_add(request: Request, sid: int, target: str = Form(...), price_per_kwh: str = Form(""),
                     back: str = Form(""), user: User = Depends(admin_user)):
    """target = 'org:<id>' ili 'user:<id>'."""
    back = safe_next(back) or f"/stations/{sid}"
    try:
        kind, tid = target.split(":")
        tid = int(tid)
        assert kind in ("org", "user")
        price = parse_price(price_per_kwh)
    except (ValueError, AssertionError):
        flash(request, "Neispravan unos.")
        return RedirectResponse(back, 303)
    with session_scope() as s:
        st = get_or_404(s, Station, sid)
        org_id, user_id = (tid, None) if kind == "org" else (None, tid)
        get_or_404(s, Organization if kind == "org" else User, tid)
        g = s.query(StationAccess).filter_by(station_id=sid, organization_id=org_id, user_id=user_id).first()
        if g:
            g.price_per_kwh = price
        else:
            s.add(StationAccess(station_id=sid, organization_id=org_id, user_id=user_id, price_per_kwh=price))
        log_event(s, st.charge_point_id, "access_granted", f"{target} price={price} by {user.email}")
    flash(request, "Dozvola spremljena.")
    return RedirectResponse(back, 303)


@app.post("/access/{aid}/delete", dependencies=[Depends(check_csrf)])
async def access_delete(request: Request, aid: int, back: str = Form(""), user: User = Depends(admin_user)):
    with session_scope() as s:
        g = get_or_404(s, StationAccess, aid)
        log_event(s, g.station.charge_point_id, "access_revoked",
                  f"org={g.organization_id} user={g.user_id} by {user.email}")
        s.delete(g)
    flash(request, "Dozvola uklonjena.")
    return RedirectResponse(safe_next(back) or "/stations", 303)


@app.post("/stations/{sid}/delete", dependencies=[Depends(check_csrf)])
async def station_delete(request: Request, sid: int, user: User = Depends(admin_user)):
    """Brisanje je dozvoljeno samo za punionicu bez punjenja (npr. testne ili krivo upisane)."""
    with session_scope() as s:
        st = get_or_404(s, Station, sid)
        if s.query(Transaction).filter_by(station_id=sid).count():
            flash(request, "Punionica ima punjenja pa se ne može obrisati. Možeš joj ukloniti odobrenje.")
            return RedirectResponse(f"/stations/{sid}", 303)
        cp_id = st.charge_point_id
        s.query(StationAccess).filter_by(station_id=sid).delete()
        s.query(ConnectorStatus).filter_by(station_id=sid).delete()
        s.delete(st)
        log_event(s, cp_id, "station_deleted", f"by {user.email}")
    flash(request, f"Punionica {cp_id} je obrisana.")
    return RedirectResponse("/stations", 303)


@app.post("/stations/{sid}/password", dependencies=[Depends(check_csrf)])
async def station_password(request: Request, sid: int, push: str = Form(""), user: User = Depends(admin_user)):
    pw = generate_station_password()
    with session_scope() as s:
        st = get_or_404(s, Station, sid)
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
        cp_id = get_or_404(s, Station, sid).charge_point_id
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


# ----------------------------------------------------------------- organizacije (tvrtke, kućanstva...)

@app.get("/orgs", response_class=HTMLResponse)
async def orgs(request: Request, user: User = Depends(admin_user)):
    with session_scope() as s:
        rows = s.query(Organization).order_by(Organization.name).all()
        members = dict(s.query(User.organization_id, func.count(User.id)).group_by(User.organization_id).all())
        owned = dict(s.query(Station.organization_id, func.count(Station.id)).group_by(Station.organization_id).all())
        granted = dict(s.query(StationAccess.organization_id, func.count(StationAccess.id))
                       .group_by(StationAccess.organization_id).all())
        month = dict(s.query(Transaction.organization_id, func.sum(Transaction.energy_wh))
                     .filter(Transaction.started_at >= month_start()).group_by(Transaction.organization_id).all())
    return render(request, "orgs.html", user, rows=rows, members=members, owned=owned, granted=granted,
                  month=month)


@app.post("/orgs", dependencies=[Depends(check_csrf)])
async def org_add(request: Request, name: str = Form(...), kind: str = Form("company"), address: str = Form(""),
                  contact: str = Form(""), user: User = Depends(admin_user)):
    name = name.strip()
    with session_scope() as s:
        if not name or s.query(Organization).filter_by(name=name).first():
            flash(request, "Organizacija s tim nazivom već postoji.")
            return RedirectResponse("/orgs", 303)
        o = Organization(name=name, kind=kind if kind in ORG_KINDS else "company", address=address, contact=contact)
        s.add(o)
        s.flush()
        oid = o.id
        log_event(s, "web", "org_created", f"{name} by {user.email}")
    return RedirectResponse(f"/orgs/{oid}", 303)


@app.get("/orgs/{oid}", response_class=HTMLResponse)
async def org_detail(request: Request, oid: int, user: User = Depends(admin_user)):
    with session_scope() as s:
        o = get_or_404(s, Organization, oid)
        members = s.query(User).filter_by(organization_id=oid).order_by(User.name, User.email).all()
        grants = s.query(StationAccess).filter_by(organization_id=oid, user_id=None).all()
        for g in grants:
            _ = g.station
        owned = s.query(Station).filter_by(organization_id=oid).order_by(Station.charge_point_id).all()
        all_stations = s.query(Station).order_by(Station.charge_point_id).all()
        month = tx_totals(s.query(Transaction).filter(Transaction.organization_id == oid,
                                                      Transaction.started_at >= month_start()))
    return render(request, "org.html", user, o=o, members=members, grants=grants, owned=owned,
                  all_stations=all_stations, month=month, this_month="%d-%02d" % current_month())


@app.post("/orgs/{oid}", dependencies=[Depends(check_csrf)])
async def org_update(request: Request, oid: int, name: str = Form(...), kind: str = Form("company"),
                     address: str = Form(""), contact: str = Form(""), active: str = Form(""),
                     user: User = Depends(admin_user)):
    with session_scope() as s:
        o = get_or_404(s, Organization, oid)
        if s.query(Organization).filter(Organization.name == name.strip(), Organization.id != oid).first():
            flash(request, "Organizacija s tim nazivom već postoji.")
            return RedirectResponse(f"/orgs/{oid}", 303)
        o.name, o.address, o.contact, o.active = name.strip(), address, contact, bool(active)
        o.kind = kind if kind in ORG_KINDS else o.kind
        log_event(s, "web", "org_updated", f"{o.name} by {user.email}")
    flash(request, "Spremljeno.")
    return RedirectResponse(f"/orgs/{oid}", 303)


# ----------------------------------------------------------------- kartice

@app.get("/cards", response_class=HTMLResponse)
async def cards(request: Request, user: User = Depends(current_user)):
    with session_scope() as s:
        rows = cards_in_scope(s, user).filter(RfidCard.app_token.is_(False)).order_by(RfidCard.uid).all()
        for c in rows:
            _ = c.user
        users = users_in_scope(s, user).order_by(User.name).all() if user.is_manager else []
        orgs = {o.id: o.name for o in s.query(Organization)} if user.is_admin else {}
        extra = mobile.add_card_context(s, user) if not user.is_admin else {}
    return render(request, "cards.html", user, rows=rows, users=users, orgs=orgs, **extra)


def _card_owner_ok(s, user: User, user_id: int | None) -> bool:
    if user_id is None or user.is_admin:
        return True
    u = s.get(User, user_id)
    return u is not None and u.organization_id == user.organization_id


@app.post("/cards", dependencies=[Depends(check_csrf)])
async def card_add(request: Request, uid: str = Form(...), label: str = Form(""), user_id: str = Form(""),
                   user: User = Depends(manager_user)):
    tag = normalize_id_tag(uid)
    if not tag or len(tag) > 36:
        flash(request, "Neispravan UID kartice.")
        return RedirectResponse("/cards", 303)
    uid_int = int(user_id) if user_id else None
    with session_scope() as s:
        if not _card_owner_ok(s, user, uid_int):
            raise HTTPException(403)
        if s.query(RfidCard).filter_by(uid=tag).first():
            flash(request, "Kartica već postoji.")
        else:
            owner = s.get(User, uid_int) if uid_int else None
            org_id = owner.organization_id if owner else (None if user.is_admin else user.organization_id)
            s.add(RfidCard(uid=tag, label=label, user_id=uid_int, organization_id=org_id))
            log_event(s, "web", "card_added", f"{tag} by {user.email}")
            flash(request, f"Kartica {tag} dodana.")
    return RedirectResponse("/cards", 303)


@app.post("/cards/{cid}", dependencies=[Depends(check_csrf)])
async def card_update(request: Request, cid: int, action: str = Form(...), user_id: str = Form(""),
                      user: User = Depends(manager_user)):
    with session_scope() as s:
        c = cards_in_scope(s, user).filter(RfidCard.id == cid).one_or_none()
        if c is None:
            raise HTTPException(404)
        if action == "toggle":
            c.active = not c.active
        elif action == "assign":
            uid_int = int(user_id) if user_id else None
            if not _card_owner_ok(s, user, uid_int):
                raise HTTPException(403)
            c.user_id = uid_int
            owner = s.get(User, uid_int) if uid_int else None
            if owner and owner.organization_id:
                c.organization_id = owner.organization_id
        log_event(s, "web", f"card_{action}", f"{c.uid} by {user.email}")
    return RedirectResponse("/cards", 303)


# ----------------------------------------------------------------- korisnici, postavke, događaji

@app.get("/users", response_class=HTMLResponse)
async def users(request: Request, user: User = Depends(manager_user)):
    with session_scope() as s:
        rows = users_in_scope(s, user).order_by(User.name).all()
        orgs = s.query(Organization).order_by(Organization.name).all() if user.is_admin else []
        org_names = {o.id: o.name for o in s.query(Organization)}
    return render(request, "users.html", user, rows=rows, orgs=orgs, org_names=org_names)


@app.post("/users", dependencies=[Depends(check_csrf)])
async def user_add(request: Request, email: str = Form(...), name: str = Form(""), password: str = Form(...),
                   is_admin: str = Form(""), organization_id: str = Form(""), org_role: str = Form("member"),
                   user: User = Depends(manager_user)):
    if len(password) < 10:
        flash(request, "Lozinka mora imati barem 10 znakova.")
        return RedirectResponse("/users", 303)
    if user.is_admin:
        org_id = int(organization_id) if organization_id else None
    else:
        org_id, is_admin = user.organization_id, ""
    with session_scope() as s:
        if s.query(User).filter_by(email=email.strip().lower()).first():
            flash(request, "Korisnik s tim e-mailom već postoji.")
        else:
            s.add(User(email=email.strip().lower(), name=name, password_hash=hash_password(password),
                       is_admin=bool(is_admin), organization_id=org_id,
                       org_role="admin" if org_role == "admin" and org_id else "member"))
            log_event(s, "web", "user_added", f"{email} by {user.email}")
            flash(request, "Korisnik dodan.")
    return RedirectResponse("/users", 303)


@app.post("/users/{uid}", dependencies=[Depends(check_csrf)])
async def user_update(request: Request, uid: int, action: str = Form(...), organization_id: str = Form(""),
                      org_role: str = Form("member"), user: User = Depends(manager_user)):
    with session_scope() as s:
        u = users_in_scope(s, user).filter(User.id == uid).one_or_none()
        if u is None or (u.is_admin and not user.is_admin):
            raise HTTPException(404)
        if action == "toggle_active" and u.id != user.id:
            u.active = not u.active
        elif action == "reset_mfa":
            u.mfa_enabled, u.totp_secret = False, None
        elif action == "unlock":
            u.locked_until, u.failed_logins = None, 0
        elif action == "membership":
            if user.is_admin:
                u.organization_id = int(organization_id) if organization_id else None
            if u.id != user.id:
                u.org_role = "admin" if org_role == "admin" and u.organization_id else "member"
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


from . import mobile  # noqa: E402,F401  (rute mobilne aplikacije /app)
