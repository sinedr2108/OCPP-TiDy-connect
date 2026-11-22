"""OCPP WebSocket server: pregovaranje verzije (1.6J / 2.0.1 / 2.1) i sigurnosni profili 0-3.

Sigurnosni profili (OCPP Security Whitepaper / OCPP 2.x A00):
  0 – bez autentifikacije (samo za razvoj/test)
  1 – HTTP Basic Auth preko ws://
  2 – HTTP Basic Auth preko TLS-a (wss://), server se autentificira certifikatom
  3 – obostrani TLS (mTLS): punionica ima klijentski certifikat s CN = ChargePointId
"""
from __future__ import annotations

import asyncio
import logging
from http import HTTPStatus
from urllib.parse import unquote

from websockets.asyncio.server import serve

from . import config, services
from .db import Station, log_event, session_scope
from .handlers.v16 import ChargePoint16
from .handlers.v2x import ChargePoint201, ChargePoint21
from .security import parse_basic_auth, server_ssl_context, verify_station_password

log = logging.getLogger("csms.ocpp")

SUBPROTOCOLS = ["ocpp2.1", "ocpp2.0.1", "ocpp1.6"]
HANDLERS = {"ocpp1.6": ChargePoint16, "ocpp2.0.1": ChargePoint201, "ocpp2.1": ChargePoint21}

# cp_id -> aktivna instanca ChargePoint (za slanje naredbi iz web sučelja)
CONNECTED: dict[str, object] = {}
LOOP: asyncio.AbstractEventLoop | None = None


def _cp_id_from_path(path: str) -> str:
    return unquote(path.split("?")[0].rstrip("/").rsplit("/", 1)[-1])


def _cn_from_subject(subject: str) -> str | None:
    """'CN=SIM-01,O=Firma' -> 'SIM-01' (format koji šalje Caddy)."""
    for part in subject.split(","):
        k, _, v = part.strip().partition("=")
        if k.upper() == "CN":
            return v
    return None


def _peer_cn(connection, request=None) -> str | None:
    if config.TRUST_PROXY_TLS and config.TRUST_PROXY_CLIENT_CERT and request is not None:
        subj = request.headers.get("X-Client-Cert-Subject", "")
        return _cn_from_subject(subj) if subj else None
    sslobj = connection.transport.get_extra_info("ssl_object")
    if not sslobj:
        return None
    cert = sslobj.getpeercert()  # popunjeno samo ako je cert verificiran našim CA
    if not cert:
        return None
    for rdn in cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                return v
    return None


def check_access(connection, request) -> tuple[bool, str, bool]:
    """Vraća (dozvoljeno, razlog, odobrena_punionica)."""
    cp_id = _cp_id_from_path(request.path)
    if not cp_id or cp_id == "ocpp":
        return False, "nedostaje ChargePointId u URL-u", False
    is_tls = connection.transport.get_extra_info("ssl_object") is not None
    if config.TRUST_PROXY_TLS and request.headers.get("X-Forwarded-Proto", "").lower() == "https":
        is_tls = True
    creds = parse_basic_auth(request.headers.get("Authorization"))

    with session_scope() as s:
        st = s.query(Station).filter_by(charge_point_id=cp_id).one_or_none()
        if st is None:
            if not config.AUTO_REGISTER_UNKNOWN:
                return False, "nepoznata punionica", False
            st = Station(charge_point_id=cp_id, name=cp_id, approved=False,
                         security_profile=2 if is_tls else 1)
            s.add(st)
            log_event(s, cp_id, "station_registered", f"nova punionica (tls={is_tls}) čeka odobrenje")
            return True, "pending", False

        profile = st.security_profile
        if profile >= 2 and not is_tls:
            return False, f"profil {profile} zahtijeva wss:// (TLS)", st.approved
        if profile == 3:
            cn = _peer_cn(connection, request)
            if cn != cp_id:
                return False, f"profil 3: klijentski certifikat nedostaje ili CN≠{cp_id}", st.approved
            return True, "mTLS ok", st.approved
        if profile in (1, 2):
            if st.password_hash is None:
                # punionica bez lozinke smije se spojiti samo dok čeka odobrenje
                return (not st.approved), "lozinka nije postavljena", st.approved
            if not creds or creds[0] != cp_id or not verify_station_password(creds[1], st.password_hash):
                return False, "neispravna Basic Auth prijava", st.approved
            return True, "basic auth ok", st.approved
        return True, "profil 0 (bez autentifikacije)", st.approved


async def process_request(connection, request):
    ok, reason, _ = check_access(connection, request)
    if not ok:
        cp_id = _cp_id_from_path(request.path)
        services.event(cp_id, "connection_rejected", reason)
        log.warning("Odbijena konekcija %s: %s", cp_id, reason)
        return connection.respond(HTTPStatus.UNAUTHORIZED, f"Unauthorized: {reason}\n")
    return None


async def on_connect(ws):
    cp_id = _cp_id_from_path(ws.request.path)
    proto = ws.subprotocol or "ocpp1.6"  # neki stariji uređaji ne šalju subprotocol
    with session_scope() as s:
        approved = bool(s.query(Station.approved).filter_by(charge_point_id=cp_id).scalar())
    cp = HANDLERS[proto](cp_id, ws, approved=approved)
    old = CONNECTED.get(cp_id)
    CONNECTED[cp_id] = cp
    if old is not None:
        try:
            await old._connection.close()
        except Exception:
            pass
    services.touch_station(cp_id, status="Online", ocpp_version={"ocpp1.6": "1.6J", "ocpp2.0.1": "2.0.1",
                                                                 "ocpp2.1": "2.1"}[proto])
    services.event(cp_id, "connected", f"{proto}, approved={approved}")
    log.info("Spojena punionica %s (%s)", cp_id, proto)
    try:
        await cp.start()
    except Exception as e:
        log.info("Punionica %s odspojena: %s", cp_id, e)
    finally:
        if CONNECTED.get(cp_id) is cp:
            CONNECTED.pop(cp_id, None)
            services.touch_station(cp_id, status="Offline")


async def run_ocpp_servers():
    global LOOP
    LOOP = asyncio.get_running_loop()
    common = dict(subprotocols=SUBPROTOCOLS, process_request=process_request,
                  ping_interval=60, ping_timeout=60, max_size=2**22)
    plain = await serve(on_connect, config.OCPP_HOST, config.OCPP_WS_PORT, **common)
    tls = await serve(on_connect, config.OCPP_HOST, config.OCPP_WSS_PORT, ssl=server_ssl_context(), **common)
    log.info("OCPP ws://%s:%s/ocpp/<id>  i  wss://%s:%s/ocpp/<id>", config.OCPP_HOST, config.OCPP_WS_PORT,
             config.OCPP_HOST, config.OCPP_WSS_PORT)
    return plain, tls


async def send_command(cp_id: str, method: str, *args, **kwargs):
    cp = CONNECTED.get(cp_id)
    if cp is None:
        raise RuntimeError("Punionica nije spojena")
    return await getattr(cp, method)(*args, **kwargs)
