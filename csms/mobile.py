"""Mobilna web aplikacija za korisnike (PWA): moje punionice, start/stop, kartice, potrošnja.

Instalira se s početnog zaslona mobitela (bez App Storea / Google Playa).
"""
from __future__ import annotations

from fastapi import Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from . import ocpp_server, services
from .db import ConnectorStatus, RfidCard, Station, Transaction, User, log_event, session_scope
from .vendors import normalize_id_tag
from .web import (app, check_csrf, current_user, flash, month_start, org_name, render, stations_for,
                  tx_totals)


def _station_view(s, user: User) -> list[dict]:
    online = set(ocpp_server.CONNECTED)
    out = []
    for st in stations_for(s, user):
        conns = (s.query(ConnectorStatus).filter_by(station_id=st.id)
                 .filter(ConnectorStatus.connector_id > 0).order_by(ConnectorStatus.connector_id).all())
        out.append({"st": st, "online": st.charge_point_id in online,
                    "conns": [(c.connector_id, c.status) for c in conns] or [(1, "Unknown")]})
    return out


@app.get("/app", response_class=HTMLResponse)
async def app_home(request: Request, user: User = Depends(current_user)):
    with session_scope() as s:
        active = (s.query(Transaction).filter_by(user_id=user.id, active=True)
                  .order_by(Transaction.started_at.desc()).all())
        for t in active:
            _ = t.station
        month = tx_totals(s.query(Transaction).filter(Transaction.user_id == user.id,
                                                      Transaction.started_at >= month_start()))
        recent = (s.query(Transaction).filter_by(user_id=user.id).order_by(Transaction.started_at.desc())
                  .limit(5).all())
        for t in recent:
            _ = t.station
        stations = _station_view(s, user)
        cards = s.query(RfidCard).filter_by(user_id=user.id, app_token=False).order_by(RfidCard.uid).all()
        org = org_name(s, user)
    return render(request, "app.html", user, active=active, month=month, recent=recent, stations=stations,
                  cards=cards, org=org)


@app.get("/app/station/{sid}", response_class=HTMLResponse)
async def app_station(request: Request, sid: int, user: User = Depends(current_user)):
    """Stranica punionice (otvara se i skeniranjem QR koda na punionici)."""
    with session_scope() as s:
        if not services.user_can_use(s, sid, user):
            flash(request, "Nemaš dozvolu za tu punionicu.")
            return RedirectResponse("/app", 303)
        view = [v for v in _station_view(s, user) if v["st"].id == sid]
        if not view:
            raise HTTPException(404)
        active = s.query(Transaction).filter_by(user_id=user.id, station_id=sid, active=True).all()
    return render(request, "app_station.html", user, v=view[0], active=active)


@app.post("/app/start", dependencies=[Depends(check_csrf)])
async def app_start(request: Request, station_id: int = Form(...), connector_id: int = Form(1),
                    user: User = Depends(current_user)):
    with session_scope() as s:
        st = s.get(Station, station_id)
        if st is None or not services.user_can_use(s, station_id, user):
            raise HTTPException(403)
        cp_id = st.charge_point_id
    if cp_id not in ocpp_server.CONNECTED:
        flash(request, "Punionica trenutno nije spojena na sustav.")
        return RedirectResponse(f"/app/station/{station_id}", 303)
    tag = services.app_token(user.id)
    try:
        res = await ocpp_server.send_command(cp_id, "remote_start", tag, connector_id)
    except Exception as e:
        res = f"greška: {e}"
    with session_scope() as s:
        log_event(s, cp_id, "app_start", f"{res} (by {user.email}, connector {connector_id})")
    flash(request, "Punjenje se pokreće. Priključi kabel ako već nije." if res == "Accepted"
          else f"Punionica nije prihvatila start ({res}).")
    return RedirectResponse("/app", 303)


@app.post("/app/stop", dependencies=[Depends(check_csrf)])
async def app_stop(request: Request, tx_id: int = Form(...), user: User = Depends(current_user)):
    with session_scope() as s:
        tx = s.get(Transaction, tx_id)
        if tx is None or tx.user_id != user.id or not tx.active:
            raise HTTPException(404)
        cp_id, ocpp_tx = tx.station.charge_point_id, tx.ocpp_tx_id
    try:
        res = await ocpp_server.send_command(cp_id, "remote_stop", ocpp_tx)
    except Exception as e:
        res = f"greška: {e}"
    with session_scope() as s:
        log_event(s, cp_id, "app_stop", f"{res} (by {user.email})")
    flash(request, "Punjenje se zaustavlja." if res == "Accepted" else f"Punionica nije prihvatila stop ({res}).")
    return RedirectResponse("/app", 303)


@app.post("/app/cards", dependencies=[Depends(check_csrf)])
async def app_card_link(request: Request, uid: str = Form(...), label: str = Form(""),
                        user: User = Depends(current_user)):
    """Korisnik sam veže svoju RFID karticu na račun (UID je otisnut na kartici ili ga vidi admin)."""
    tag = normalize_id_tag(uid)
    if not tag or len(tag) > 36 or tag.startswith("APP"):
        flash(request, "Neispravan broj kartice.")
        return RedirectResponse("/app#kartice", 303)
    with session_scope() as s:
        card = s.query(RfidCard).filter_by(uid=tag).one_or_none()
        if card is None:
            s.add(RfidCard(uid=tag, label=label or "Moja kartica", user_id=user.id,
                           organization_id=user.organization_id))
            msg = f"Kartica {tag} je vezana na tvoj račun."
        elif card.user_id is None and card.organization_id in (None, user.organization_id) and card.active:
            card.user_id = user.id
            card.organization_id = card.organization_id or user.organization_id
            msg = f"Kartica {tag} je vezana na tvoj račun."
        elif card.user_id == user.id:
            msg = "Ta kartica je već tvoja."
        else:
            msg = "Tu karticu nije moguće vezati. Javi se administratoru."
        log_event(s, "app", "card_link", f"{tag} by {user.email}: {msg}")
    flash(request, msg)
    return RedirectResponse("/app#kartice", 303)


@app.post("/app/cards/{cid}/block", dependencies=[Depends(check_csrf)])
async def app_card_block(request: Request, cid: int, user: User = Depends(current_user)):
    """Izgubljena kartica: korisnik je sam blokira."""
    with session_scope() as s:
        card = s.get(RfidCard, cid)
        if card is None or card.user_id != user.id:
            raise HTTPException(404)
        card.active = False
        log_event(s, "app", "card_blocked", f"{card.uid} by {user.email}")
    flash(request, "Kartica je blokirana. Za ponovno aktiviranje javi se administratoru.")
    return RedirectResponse("/app#kartice", 303)


# ----------------------------------------------------------------- PWA

MANIFEST = """{
  "name": "OCPP Charge",
  "short_name": "Punjenje",
  "start_url": "/app",
  "scope": "/",
  "display": "standalone",
  "background_color": "#f6f7f9",
  "theme_color": "#0b7a53",
  "icons": [{"src": "/app-icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable"}]
}"""

ICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="96" fill="#0b7a53"/>
<path d="M290 64 140 288h96l-24 160 160-232h-100z" fill="#fff"/></svg>"""

# Minimalni service worker: potreban da bi se aplikacija mogla instalirati; podaci se uvijek čitaju s mreže.
SW = """self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => self.clients.claim());
self.addEventListener('fetch', () => {});
"""

APP_JS = """if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
document.querySelectorAll('[data-confirm]').forEach(f => f.addEventListener('submit', e => {
  if (!confirm(f.dataset.confirm)) e.preventDefault();
}));
document.querySelectorAll('select[data-autosubmit]').forEach(s => s.addEventListener('change', () => s.form.submit()));
"""


@app.get("/manifest.webmanifest")
async def manifest():
    return Response(MANIFEST, media_type="application/manifest+json")


@app.get("/app-icon.svg")
async def app_icon():
    return Response(ICON, media_type="image/svg+xml", headers={"Cache-Control": "max-age=86400"})


@app.get("/sw.js")
async def service_worker():
    return Response(SW, media_type="application/javascript", headers={"Cache-Control": "no-cache"})


@app.get("/app.js")
async def app_js():
    return Response(APP_JS, media_type="application/javascript")
