"""Simulator punionice za testiranje (OCPP 1.6J, 2.0.1, 2.1).

Primjeri:
  python tools/simulator.py --id SIM-01 --password <ključ> --tag 04A1B2C3D4
  python tools/simulator.py --version 2.0.1 --url wss://localhost:9443/ocpp --ca data/pki/ca.crt ...
  python tools/simulator.py --csr --out certs/   # zatraži klijentski certifikat (za profil 3)
  python tools/simulator.py --url wss://localhost:9443/ocpp --ca data/pki/ca.crt --cert certs/SIM-01.crt --key certs/SIM-01.key
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import ssl
import uuid
from datetime import datetime, timezone
from pathlib import Path

import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from ocpp.routing import on


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_csr(cp_id: str, out: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Simulator"),
                                    x509.NameAttribute(NameOID.COMMON_NAME, cp_id)]))
           .sign(key, hashes.SHA256()))
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{cp_id}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                         serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def build(version: str, args):
    if version == "1.6":
        from ocpp.v16 import ChargePoint as Base
        from ocpp.v16 import call, call_result as R
    elif version == "2.0.1":
        from ocpp.v201 import ChargePoint as Base
        from ocpp.v201 import call, call_result as R
    else:
        from ocpp.v21 import ChargePoint as Base
        from ocpp.v21 import call, call_result as R

    class Sim(Base):
        got_cert = asyncio.Event()

        # --- odgovori na naredbe CSMS-a
        @on("ChangeConfiguration")
        def _cc(self, key, value, **kw):
            print(f"  <- ChangeConfiguration {key}={value}")
            return R.ChangeConfiguration(status="Accepted")

        @on("SetVariables")
        def _sv(self, set_variable_data, **kw):
            return R.SetVariables(set_variable_result=[{
                "attribute_status": "Accepted", "component": d["component"], "variable": d["variable"]}
                for d in set_variable_data])

        @on("InstallCertificate")
        def _ic(self, certificate_type, certificate, **kw):
            print(f"  <- InstallCertificate {certificate_type}")
            return R.InstallCertificate(status="Accepted")

        @on("CertificateSigned")
        def _cs(self, certificate_chain, **kw):
            Path(args.out).mkdir(parents=True, exist_ok=True)
            (Path(args.out) / f"{self.id}.crt").write_text(certificate_chain)
            print(f"  <- CertificateSigned: spremljeno u {args.out}/{self.id}.crt")
            self.got_cert.set()
            return R.CertificateSigned(status="Accepted")

        @on("RemoteStartTransaction")
        def _rs(self, id_tag, **kw):
            return R.RemoteStartTransaction(status="Accepted")

        @on("RemoteStopTransaction")
        def _rst(self, transaction_id, **kw):
            return R.RemoteStopTransaction(status="Accepted")

        @on("RequestStartTransaction")
        def _rs2(self, id_token, remote_start_id, **kw):
            return R.RequestStartTransaction(status="Accepted")

        @on("RequestStopTransaction")
        def _rst2(self, transaction_id, **kw):
            return R.RequestStopTransaction(status="Accepted")

        @on("Reset")
        def _reset(self, type, **kw):
            return R.Reset(status="Accepted")

        @on("TriggerMessage")
        def _tm(self, requested_message, **kw):
            return R.TriggerMessage(status="Accepted")

        @on("ExtendedTriggerMessage")
        def _etm(self, requested_message, **kw):
            return R.ExtendedTriggerMessage(status="Accepted")

        # --- scenarij
        async def scenario16(self):
            r = await self.call(call.BootNotification(charge_point_vendor=args.vendor, charge_point_model="SIM-AC22"))
            print("BootNotification:", r.status)
            if r.status != "Accepted":
                return
            await self.call(call.StatusNotification(connector_id=1, error_code="NoError", status="Available"))
            if args.csr:
                await self.call(call.SignCertificate(csr=make_csr(self.id, Path(args.out))))
                await asyncio.wait_for(self.got_cert.wait(), 15)
                return
            a = await self.call(call.Authorize(id_tag=args.tag))
            print("Authorize:", a.id_tag_info["status"])
            if a.id_tag_info["status"] != "Accepted":
                return
            meter = 1_000_000
            st = await self.call(call.StartTransaction(connector_id=1, id_tag=args.tag, meter_start=meter,
                                                       timestamp=now()))
            print("StartTransaction id:", st.transaction_id)
            await self.call(call.StatusNotification(connector_id=1, error_code="NoError", status="Charging"))
            for _ in range(args.steps):
                await asyncio.sleep(args.interval)
                meter += 2750  # ~11 kW kroz 15 min po koraku
                await self.call(call.MeterValues(connector_id=1, transaction_id=st.transaction_id, meter_value=[{
                    "timestamp": now(), "sampled_value": [
                        {"value": str(meter), "measurand": "Energy.Active.Import.Register", "unit": "Wh"},
                        {"value": "11000", "measurand": "Power.Active.Import", "unit": "W"}]}]))
            await self.call(call.StopTransaction(meter_stop=meter, timestamp=now(),
                                                 transaction_id=st.transaction_id, reason="Local", id_tag=args.tag))
            await self.call(call.StatusNotification(connector_id=1, error_code="NoError", status="Available"))
            print(f"StopTransaction: {(meter - 1_000_000) / 1000:.2f} kWh")

        async def scenario2x(self):
            r = await self.call(call.BootNotification(
                charging_station={"vendor_name": args.vendor, "model": "SIM-AC22"}, reason="PowerUp"))
            print("BootNotification:", r.status)
            if r.status != "Accepted":
                return
            await self.call(call.StatusNotification(timestamp=now(), connector_status="Available",
                                                    evse_id=1, connector_id=1))
            if args.csr:
                await self.call(call.SignCertificate(csr=make_csr(self.id, Path(args.out)),
                                                     certificate_type="ChargingStationCertificate"))
                await asyncio.wait_for(self.got_cert.wait(), 15)
                return
            tok = {"id_token": args.tag, "type": "ISO14443"}
            a = await self.call(call.Authorize(id_token=tok))
            print("Authorize:", a.id_token_info["status"])
            if a.id_token_info["status"] != "Accepted":
                return
            tx = str(uuid.uuid4())
            meter, seq = 500_000.0, 0

            def mv(ctx):
                return [{"timestamp": now(), "sampled_value": [
                    {"value": meter / 1000, "measurand": "Energy.Active.Import.Register", "context": ctx,
                     "unit_of_measure": {"unit": "kWh"}},
                    {"value": 7.4, "measurand": "Power.Active.Import", "context": ctx,
                     "unit_of_measure": {"unit": "kW"}}]}]

            await self.call(call.TransactionEvent(event_type="Started", timestamp=now(), trigger_reason="Authorized",
                                                  seq_no=seq, transaction_info={"transaction_id": tx},
                                                  id_token=tok, evse={"id": 1, "connector_id": 1},
                                                  meter_value=mv("Transaction.Begin")))
            for _ in range(args.steps):
                await asyncio.sleep(args.interval)
                meter += 1850
                seq += 1
                r = await self.call(call.TransactionEvent(event_type="Updated", timestamp=now(),
                                                          trigger_reason="MeterValuePeriodic", seq_no=seq,
                                                          transaction_info={"transaction_id": tx,
                                                                            "charging_state": "Charging"},
                                                          meter_value=mv("Sample.Periodic")))
            seq += 1
            r = await self.call(call.TransactionEvent(event_type="Ended", timestamp=now(), trigger_reason="StopAuthorized",
                                                      seq_no=seq, transaction_info={"transaction_id": tx,
                                                                                    "stopped_reason": "Local"},
                                                      id_token=tok, meter_value=mv("Transaction.End")))
            print(f"TransactionEvent Ended: {(meter - 500_000) / 1000:.2f} kWh, ukupno {r.total_cost} EUR")

        async def scenario(self):
            if version == "1.6":
                await self.scenario16()
            else:
                await self.scenario2x()
            if args.stay:
                await asyncio.sleep(10**9)

    return Sim


async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="ws://localhost:9000/ocpp")
    p.add_argument("--id", default="SIM-01")
    p.add_argument("--version", choices=["1.6", "2.0.1", "2.1"], default="1.6")
    p.add_argument("--password")
    p.add_argument("--tag", default="04A1B2C3D4")
    p.add_argument("--vendor", default="Simulator")
    p.add_argument("--steps", type=int, default=4)
    p.add_argument("--interval", type=float, default=0.2)
    p.add_argument("--ca", help="CA certifikat za provjeru servera (wss)")
    p.add_argument("--cert", help="klijentski certifikat (profil 3)")
    p.add_argument("--key", help="klijentski ključ (profil 3)")
    p.add_argument("--csr", action="store_true", help="zatraži klijentski certifikat preko SignCertificate")
    p.add_argument("--out", default="certs")
    p.add_argument("--stay", action="store_true", help="ostani spojen (za daljinske naredbe)")
    args = p.parse_args()

    headers = {}
    if args.password:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{args.id}:{args.password}".encode()).decode()
    ssl_ctx = None
    if args.url.startswith("wss://"):
        ssl_ctx = ssl.create_default_context(cafile=args.ca)
        if args.cert:
            ssl_ctx.load_cert_chain(args.cert, args.key)
    proto = {"1.6": "ocpp1.6", "2.0.1": "ocpp2.0.1", "2.1": "ocpp2.1"}[args.version]
    async with websockets.connect(f"{args.url.rstrip('/')}/{args.id}", subprotocols=[proto],
                                  additional_headers=headers, ssl=ssl_ctx) as ws:
        cp = build(args.version, args)(args.id, ws)
        task = asyncio.create_task(cp.start())
        try:
            await cp.scenario()
        finally:
            task.cancel()


if __name__ == "__main__":
    asyncio.run(main())
