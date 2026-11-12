"""Baza podataka: organizacije, korisnici, RFID kartice, punionice, dozvole, transakcije (punjenja)."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import (Boolean, DateTime, Float, ForeignKey, Integer, String, Text,
                        UniqueConstraint, create_engine, inspect, text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from . import config


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


ORG_KINDS = {"company": "Tvrtka", "household": "Kućanstvo", "association": "Udruga", "public": "Javno mjesto"}


class Organization(Base):
    """Tvrtka, kućanstvo, udruga ili javno mjesto gdje su montirane punionice / kojoj pripadaju korisnici."""
    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    kind: Mapped[str] = mapped_column(String(20), default="company")
    address: Mapped[str] = mapped_column(String(300), default="")
    contact: Mapped[str] = mapped_column(String(200), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    @property
    def kind_label(self) -> str:
        return ORG_KINDS.get(self.kind, self.kind)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(200))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)  # administrator cijele platforme
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    org_role: Mapped[str] = mapped_column(String(20), default="member", server_default="member")  # member|admin
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_email: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    notify_push: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    cards: Mapped[list["RfidCard"]] = relationship(back_populates="user")

    @property
    def is_org_admin(self) -> bool:
        return bool(self.organization_id) and self.org_role == "admin"

    @property
    def is_manager(self) -> bool:
        """Platformski admin ili administrator svoje organizacije."""
        return self.is_admin or self.is_org_admin


class RfidCard(Base):
    __tablename__ = "rfid_cards"
    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # normaliziran: HEX, velika slova
    label: Mapped[str] = mapped_column(String(200), default="")
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    # kartica organizacije bez korisnika (npr. službeno vozilo); inače vrijedi organizacija korisnika
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    app_token: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")  # virtualna "kartica" za start iz aplikacije
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    user: Mapped[User | None] = relationship(back_populates="cards")


class Station(Base):
    __tablename__ = "stations"
    id: Mapped[int] = mapped_column(primary_key=True)
    charge_point_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    location: Mapped[str] = mapped_column(String(300), default="")
    # organizacija na čijoj je lokaciji punionica montirana (vidi punjenja na njoj)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    vendor_profile: Mapped[str] = mapped_column(String(50), default="generic")
    # podaci iz BootNotification
    vendor: Mapped[str] = mapped_column(String(100), default="")
    model: Mapped[str] = mapped_column(String(100), default="")
    serial: Mapped[str] = mapped_column(String(100), default="")
    firmware: Mapped[str] = mapped_column(String(100), default="")
    ocpp_version: Mapped[str] = mapped_column(String(20), default="")
    # sigurnost
    security_profile: Mapped[int] = mapped_column(Integer, default=1)  # 0..3
    password_hash: Mapped[str | None] = mapped_column(String(200), nullable=True)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    # cijena (EUR/kWh); None = zadana cijena sustava
    price_per_kwh: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="Offline")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class StationAccess(Base):
    """Dozvola: koja organizacija ili koji korisnik smije vidjeti i koristiti punionicu, uz opcionalnu cijenu."""
    __tablename__ = "station_access"
    __table_args__ = (UniqueConstraint("station_id", "organization_id", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    station_id: Mapped[int] = mapped_column(ForeignKey("stations.id"), index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    # EUR/kWh za ovu dozvolu (npr. zaposlenici 0, gosti 0.45); None = cijena punionice
    price_per_kwh: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    station: Mapped[Station] = relationship()
    organization: Mapped[Organization | None] = relationship()
    user: Mapped[User | None] = relationship()


class ConnectorStatus(Base):
    __tablename__ = "connector_status"
    __table_args__ = (UniqueConstraint("station_id", "connector_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    station_id: Mapped[int] = mapped_column(ForeignKey("stations.id"))
    connector_id: Mapped[int] = mapped_column(Integer)  # 1.6: connectorId, 2.x: evseId
    status: Mapped[str] = mapped_column(String(30), default="Unknown")
    error_code: Mapped[str] = mapped_column(String(50), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Transaction(Base):
    __tablename__ = "transactions"
    id: Mapped[int] = mapped_column(primary_key=True)  # = transactionId za OCPP 1.6
    ocpp_tx_id: Mapped[str] = mapped_column(String(64), index=True)  # string ID (2.0.1/2.1) ili str(id)
    station_id: Mapped[int] = mapped_column(ForeignKey("stations.id"), index=True)
    connector_id: Mapped[int] = mapped_column(Integer, default=1)
    id_tag: Mapped[str] = mapped_column(String(64), default="")
    card_id: Mapped[int | None] = mapped_column(ForeignKey("rfid_cards.id"), nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    # organizacija korisnika/kartice u trenutku punjenja (za obračun po organizaciji)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    meter_start_wh: Mapped[float] = mapped_column(Float, default=0)
    meter_last_wh: Mapped[float | None] = mapped_column(Float, nullable=True)
    meter_stop_wh: Mapped[float | None] = mapped_column(Float, nullable=True)
    energy_wh: Mapped[float] = mapped_column(Float, default=0)
    power_w: Mapped[float | None] = mapped_column(Float, nullable=True)
    price_per_kwh: Mapped[float] = mapped_column(Float, default=0)
    cost_eur: Mapped[float] = mapped_column(Float, default=0)
    stop_reason: Mapped[str] = mapped_column(String(50), default="")
    notified_full: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")  # "vozilo napunjeno" poslano
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    station: Mapped[Station] = relationship()
    card: Mapped[RfidCard | None] = relationship()
    user: Mapped[User | None] = relationship()

    @property
    def energy_kwh(self) -> float:
        return round(self.energy_wh / 1000.0, 3)


class PushSubscription(Base):
    """Web Push pretplata preglednika/mobitela korisnika."""
    __tablename__ = "push_subscriptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    endpoint: Mapped[str] = mapped_column(String(1000), unique=True)
    p256dh: Mapped[str] = mapped_column(String(200))
    auth: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class EventLog(Base):
    """Sigurnosni i sistemski događaji (SecurityEventNotification, odbijene prijave...)."""
    __tablename__ = "event_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    source: Mapped[str] = mapped_column(String(100), default="")
    kind: Mapped[str] = mapped_column(String(100), default="")
    detail: Mapped[str] = mapped_column(Text, default="")


engine = create_engine(
    config.DATABASE_URL,
    connect_args={"check_same_thread": False} if config.DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def session_scope():
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_setting(s, key: str, default: str | None = None) -> str | None:
    row = s.get(Setting, key)
    return row.value if row else default


def set_setting(s, key: str, value: str) -> None:
    row = s.get(Setting, key)
    if row:
        row.value = value
    else:
        s.add(Setting(key=key, value=value))


def log_event(s, source: str, kind: str, detail: str = "") -> None:
    s.add(EventLog(source=source, kind=kind, detail=detail[:4000]))


def _add_missing_columns() -> None:
    """Jednostavna migracija: postojećim tablicama dodaj stupce koji su kasnije dodani u modele."""
    insp = inspect(engine)
    for table in Base.metadata.sorted_tables:
        if not insp.has_table(table.name):
            continue
        existing = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing:
                continue
            ddl = f"ALTER TABLE {table.name} ADD COLUMN {col.name} {col.type.compile(engine.dialect)}"
            if col.server_default is not None:
                ddl += f" DEFAULT '{col.server_default.arg}'"
            with engine.begin() as c:
                c.execute(text(ddl))


def _migrate_to_multitenant(s) -> None:
    """Prelazak na više organizacija: postojeći korisnici i punionice zadrže pristup kao prije."""
    if get_setting(s, "schema_version", "1") != "1":
        return
    set_setting(s, "schema_version", "2")
    stations = s.query(Station).all()
    if not stations or s.query(Organization).count():
        return
    org = Organization(name="Postojeći korisnici", kind="company")
    s.add(org)
    s.flush()
    for u in s.query(User).filter(User.is_admin.is_(False), User.organization_id.is_(None)):
        u.organization_id = org.id
    for st in stations:
        s.add(StationAccess(station_id=st.id, organization_id=org.id))


def init_db() -> None:
    from .security import hash_password

    Base.metadata.create_all(engine)
    _add_missing_columns()
    with session_scope() as s:
        if s.query(User).count() == 0:
            s.add(User(email=config.ADMIN_EMAIL.lower(), name="Administrator",
                       password_hash=hash_password(config.ADMIN_PASSWORD), is_admin=True))
        if get_setting(s, "price_per_kwh") is None:
            set_setting(s, "price_per_kwh", str(config.DEFAULT_PRICE_EUR_PER_KWH))
        s.flush()
        _migrate_to_multitenant(s)
