"""Baza podataka: korisnici, RFID kartice, punionice, transakcije (punjenja)."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import (Boolean, DateTime, Float, ForeignKey, Integer, String, Text,
                        UniqueConstraint, create_engine)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from . import config


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(200))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    cards: Mapped[list["RfidCard"]] = relationship(back_populates="user")


class RfidCard(Base):
    __tablename__ = "rfid_cards"
    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # normaliziran: HEX, velika slova
    label: Mapped[str] = mapped_column(String(200), default="")
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
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
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    station: Mapped[Station] = relationship()
    card: Mapped[RfidCard | None] = relationship()
    user: Mapped[User | None] = relationship()

    @property
    def energy_kwh(self) -> float:
        return round(self.energy_wh / 1000.0, 3)


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


def init_db() -> None:
    from .security import hash_password

    Base.metadata.create_all(engine)
    with session_scope() as s:
        if s.query(User).count() == 0:
            s.add(User(email=config.ADMIN_EMAIL.lower(), name="Administrator",
                       password_hash=hash_password(config.ADMIN_PASSWORD), is_admin=True))
        if get_setting(s, "price_per_kwh") is None:
            set_setting(s, "price_per_kwh", str(config.DEFAULT_PRICE_EUR_PER_KWH))
