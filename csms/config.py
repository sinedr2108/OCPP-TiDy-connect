"""Konfiguracija iz varijabli okruženja (s razumnim zadanim vrijednostima)."""
import os
from pathlib import Path

DATA_DIR = Path(os.getenv("CSMS_DATA_DIR", "./data")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv("CSMS_DATABASE_URL", f"sqlite:///{DATA_DIR / 'csms.db'}")

# Web sučelje / API
HTTP_HOST = os.getenv("CSMS_HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("CSMS_HTTP_PORT", "8000"))
SECRET_KEY = os.getenv("CSMS_SECRET_KEY", "promijeni-me-u-produkciji")
COOKIE_SECURE = os.getenv("CSMS_COOKIE_SECURE", "0") == "1"

# OCPP WebSocket
OCPP_HOST = os.getenv("CSMS_OCPP_HOST", "0.0.0.0")
OCPP_WS_PORT = int(os.getenv("CSMS_OCPP_WS_PORT", "9000"))     # ws://  -> sigurnosni profil 0/1
OCPP_WSS_PORT = int(os.getenv("CSMS_OCPP_WSS_PORT", "9443"))   # wss:// -> sigurnosni profil 2/3
# Ime (DNS) pod kojim su punionice spajaju – ulazi u serverski TLS certifikat
PUBLIC_HOSTNAME = os.getenv("CSMS_PUBLIC_HOSTNAME", "localhost")
# Vlastiti certifikat (npr. Let's Encrypt). Ako nije zadan, koristi se ugrađeni CA.
TLS_CERT_FILE = os.getenv("CSMS_TLS_CERT_FILE")
TLS_KEY_FILE = os.getenv("CSMS_TLS_KEY_FILE")

# Nepoznate punionice: automatski ih upiši kao "pending" (admin ih odobrava)
AUTO_REGISTER_UNKNOWN = os.getenv("CSMS_AUTO_REGISTER", "1") == "1"

HEARTBEAT_INTERVAL = int(os.getenv("CSMS_HEARTBEAT_INTERVAL", "300"))
DEFAULT_PRICE_EUR_PER_KWH = float(os.getenv("CSMS_DEFAULT_PRICE", "0.35"))

# Prvi administrator (kreira se samo ako nema korisnika)
ADMIN_EMAIL = os.getenv("CSMS_ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.getenv("CSMS_ADMIN_PASSWORD", "admin12345")
