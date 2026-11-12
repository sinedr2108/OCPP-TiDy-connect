"""Poslovna logika neovisna o verziji OCPP-a: autorizacija, transakcije, mjerenja, cijena."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .db import (ConnectorStatus, Organization, RfidCard, Station, StationAccess, Transaction, User,
                 get_setting, log_event, session_scope, utcnow)
from .vendors import normalize_id_tag


@dataclass
class AuthResult:
    # Accepted | Blocked | Expired | Invalid | NotAtThisLocation (2.x; u 1.6 se šalje kao Invalid)
    status: str
    card_id: int | None = None
    user_id: int | None = None
    organization_id: int | None = None
    price_per_kwh: float | None = None  # cijena iz dozvole, ako je zadana


def find_access(s, station_id: int, user: User | None, org_id: int | None) -> StationAccess | None:
    """Dozvola za punionicu: najprije osobna dozvola korisnika, zatim dozvola njegove organizacije."""
    q = s.query(StationAccess).filter_by(station_id=station_id)
    if user is not None:
        a = q.filter(StationAccess.user_id == user.id).first()
        if a:
            return a
    if org_id:
        return q.filter(StationAccess.organization_id == org_id, StationAccess.user_id.is_(None)).first()
    return None


def user_can_use(s, station_id: int, user: User) -> bool:
    return user.is_admin or find_access(s, station_id, user, user.organization_id) is not None


def allowed_station_ids(s, user: User) -> set[int] | None:
    """ID-evi punionica koje korisnik vidi i smije koristiti; None = sve (administrator platforme)."""
    if user.is_admin:
        return None
    q = s.query(StationAccess.station_id).filter(StationAccess.user_id == user.id)
    ids = {r[0] for r in q}
    if user.organization_id:
        ids |= {r[0] for r in s.query(StationAccess.station_id)
                .filter(StationAccess.organization_id == user.organization_id, StationAccess.user_id.is_(None))}
        if user.is_org_admin:
            ids |= {r[0] for r in s.query(Station.id).filter(Station.organization_id == user.organization_id)}
    return ids


def authorize_tag(raw_tag: str, cp_id: str | None = None) -> AuthResult:
    """Provjeri karticu; ako je zadana punionica, provjeri i dozvolu za nju."""
    tag = normalize_id_tag(raw_tag)
    with session_scope() as s:
        card = s.query(RfidCard).filter_by(uid=tag).one_or_none()
        if card is None:
            log_event(s, cp_id or "rfid", "unknown_card", tag)
            return AuthResult("Invalid")
        user = s.get(User, card.user_id) if card.user_id else None
        org_id = (user.organization_id if user else None) or card.organization_id
        res = AuthResult("Accepted", card.id, card.user_id, org_id)
        if not card.active:
            res.status = "Blocked"
            return res
        if card.expires_at and card.expires_at < utcnow():
            res.status = "Expired"
            return res
        if user and not user.active:
            res.status = "Blocked"
            return res
        if org_id:
            org = s.get(Organization, org_id)
            if org and not org.active:
                res.status = "Blocked"
                return res
        if cp_id:
            st = s.query(Station).filter_by(charge_point_id=cp_id).one_or_none()
            if st and not (user and user.is_admin):
                access = find_access(s, st.id, user, org_id)
                if access is None:
                    log_event(s, cp_id, "card_not_allowed", tag)
                    res.status = "NotAtThisLocation"
                    return res
                res.price_per_kwh = access.price_per_kwh
        return res


def parse_ts(value) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo:
            from datetime import timezone
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return utcnow()


def extract_meter(meter_values: list | None) -> tuple[float | None, float | None]:
    """Iz OCPP meterValue liste (1.6 ili 2.x) izvuci (energija_Wh, snaga_W).

    Uzima se ukupna vrijednost (bez faze); jedinice kWh/kW se pretvaraju u Wh/W.
    """
    energy = power = None
    for mv in meter_values or []:
        for sv in mv.get("sampled_value", []) or []:
            measurand = sv.get("measurand") or "Energy.Active.Import.Register"
            if sv.get("phase"):
                continue
            try:
                val = float(sv.get("value"))
            except (TypeError, ValueError):
                continue
            unit = sv.get("unit")
            multiplier = 0
            uom = sv.get("unit_of_measure")
            if isinstance(uom, dict):
                unit = uom.get("unit", unit)
                multiplier = int(uom.get("multiplier", 0) or 0)
            val = val * (10 ** multiplier)
            if measurand == "Energy.Active.Import.Register":
                energy = val * 1000 if unit == "kWh" else val
            elif measurand == "Power.Active.Import":
                power = val * 1000 if unit == "kW" else val
    return energy, power


def station_price(s, station: Station) -> float:
    if station.price_per_kwh is not None:
        return station.price_per_kwh
    return float(get_setting(s, "price_per_kwh", "0") or 0)


def _recalc(tx: Transaction) -> None:
    last = tx.meter_stop_wh if tx.meter_stop_wh is not None else tx.meter_last_wh
    if last is not None:
        tx.energy_wh = max(0.0, last - tx.meter_start_wh)
    tx.cost_eur = round(tx.energy_wh / 1000.0 * tx.price_per_kwh, 2)


def start_transaction(cp_id: str, connector_id: int, id_tag: str, meter_start_wh: float | None,
                      ts=None, ocpp_tx_id: str | None = None) -> tuple[Transaction, AuthResult]:
    auth = authorize_tag(id_tag, cp_id) if id_tag else AuthResult("Accepted")
    with session_scope() as s:
        st = s.query(Station).filter_by(charge_point_id=cp_id).one()
        tx = Transaction(station_id=st.id, connector_id=connector_id, id_tag=normalize_id_tag(id_tag),
                         card_id=auth.card_id, user_id=auth.user_id, organization_id=auth.organization_id,
                         started_at=parse_ts(ts) if ts else utcnow(),
                         meter_start_wh=meter_start_wh or 0.0, meter_last_wh=meter_start_wh,
                         price_per_kwh=auth.price_per_kwh if auth.price_per_kwh is not None
                         else station_price(s, st), ocpp_tx_id=ocpp_tx_id or "")
        s.add(tx)
        s.flush()
        if not ocpp_tx_id:
            tx.ocpp_tx_id = str(tx.id)
        return tx, auth


def find_tx(cp_id: str, ocpp_tx_id: str) -> Transaction | None:
    with session_scope() as s:
        return (s.query(Transaction).join(Station)
                .filter(Station.charge_point_id == cp_id, Transaction.ocpp_tx_id == str(ocpp_tx_id))
                .order_by(Transaction.id.desc()).first())


def update_transaction(tx_id: int, energy_wh: float | None, power_w: float | None,
                       id_tag: str | None = None) -> None:
    with session_scope() as s:
        tx = s.get(Transaction, tx_id)
        if not tx:
            return
        if energy_wh is not None:
            if tx.meter_last_wh is None:
                # 2.x: početno stanje brojila stiže s prvim mjerenjem
                tx.meter_start_wh = energy_wh
            tx.meter_last_wh = energy_wh
        if power_w is not None:
            tx.power_w = power_w
        if id_tag and not tx.id_tag:
            auth = authorize_tag(id_tag, tx.station.charge_point_id)
            tx.id_tag, tx.card_id, tx.user_id = normalize_id_tag(id_tag), auth.card_id, auth.user_id
            tx.organization_id = auth.organization_id
            if auth.price_per_kwh is not None:
                tx.price_per_kwh = auth.price_per_kwh
        _recalc(tx)


def stop_transaction(tx_id: int, meter_stop_wh: float | None, ts=None, reason: str = "") -> Transaction | None:
    with session_scope() as s:
        tx = s.get(Transaction, tx_id)
        if not tx:
            return None
        if meter_stop_wh is not None:
            tx.meter_stop_wh = meter_stop_wh
        tx.stopped_at = parse_ts(ts) if ts else utcnow()
        tx.stop_reason = reason or ""
        tx.active = False
        tx.power_w = None
        _recalc(tx)
        return tx


def set_connector_status(cp_id: str, connector_id: int, status: str, error_code: str = "") -> None:
    with session_scope() as s:
        st = s.query(Station).filter_by(charge_point_id=cp_id).one_or_none()
        if not st:
            return
        row = s.query(ConnectorStatus).filter_by(station_id=st.id, connector_id=connector_id).one_or_none()
        if not row:
            row = ConnectorStatus(station_id=st.id, connector_id=connector_id)
            s.add(row)
        row.status, row.error_code, row.updated_at = status, error_code or "", utcnow()
        if connector_id == 0:
            st.status = status


def touch_station(cp_id: str, **fields) -> None:
    with session_scope() as s:
        st = s.query(Station).filter_by(charge_point_id=cp_id).one_or_none()
        if st:
            st.last_seen = utcnow()
            for k, v in fields.items():
                setattr(st, k, v)


def event(source: str, kind: str, detail: str = "") -> None:
    with session_scope() as s:
        log_event(s, source, kind, detail)


def app_token(user_id: int) -> str:
    """Virtualna "kartica" korisnika za start iz aplikacije (RemoteStart idTag, max 20 znakova)."""
    import secrets
    with session_scope() as s:
        card = s.query(RfidCard).filter_by(user_id=user_id, app_token=True).first()
        if card is None:
            card = RfidCard(uid="APP" + secrets.token_hex(6).upper(), label="Aplikacija", user_id=user_id,
                            app_token=True)
            s.add(card)
        elif not card.active:
            card.active = True
        return card.uid
