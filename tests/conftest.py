import os, socket, tempfile

def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

os.environ["CSMS_DATA_DIR"] = tempfile.mkdtemp(prefix="csms-test-")
os.environ["CSMS_OCPP_WS_PORT"] = str(_free_port())
os.environ["CSMS_OCPP_WSS_PORT"] = str(_free_port())
os.environ["CSMS_OCPP_HOST"] = "127.0.0.1"

from csms.db import init_db  # noqa: E402
from csms.security import ensure_pki  # noqa: E402

init_db()
ensure_pki()
