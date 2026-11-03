"""Pokretanje: web sučelje (HTTP) + OCPP serveri (ws/wss) u istoj asyncio petlji."""
import asyncio
import logging

import uvicorn

from . import config
from .db import init_db
from .ocpp_server import run_ocpp_servers
from .security import ensure_pki
from .web import app


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("websockets").setLevel(logging.WARNING)
    init_db()
    ensure_pki()
    await run_ocpp_servers()
    server = uvicorn.Server(uvicorn.Config(app, host=config.HTTP_HOST, port=config.HTTP_PORT,
                                           proxy_headers=True, log_level="info"))
    await server.serve()


def run():
    asyncio.run(main())


if __name__ == "__main__":
    run()
