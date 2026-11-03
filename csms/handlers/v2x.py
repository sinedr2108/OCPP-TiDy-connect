"""OCPP 2.0.1 i OCPP 2.1 – zajednička logika (poruke su za naše potrebe kompatibilne)."""
from __future__ import annotations

import asyncio
import itertools

from ocpp.routing import on
from ocpp.v201 import ChargePoint as CP201
from ocpp.v201 import call as call201
from ocpp.v201 import call_result as cr201
from ocpp.v21 import ChargePoint as CP21
from ocpp.v21 import call as call21
from ocpp.v21 import call_result as cr21

from .. import config, services
from ..db import Station, session_scope
from ..security import ca_pem, sign_station_csr
from ..vendors import guess_profile
from .v16 import now_iso

_remote_ids = itertools.count(1)


class V2xMixin:
    CALL = None
    RESULT = None
    version = ""

    def _init(self, approved: bool):
        self.approved = approved

    def _id_token_info(self, id_token: dict | None) -> dict | None:
        if not id_token or not id_token.get("id_token"):
            return None
        if id_token.get("type") in ("NoAuthorization",):
            return {"status": "Accepted"}
        status = services.authorize_tag(id_token["id_token"]).status if self.approved else "Invalid"
        return {"status": status}

    @on("BootNotification")
    async def on_boot(self, charging_station, reason, **kw):
        vendor = charging_station.get("vendor_name", "")
        fields = dict(vendor=vendor, model=charging_station.get("model", ""),
                      serial=charging_station.get("serial_number", "") or "",
                      firmware=charging_station.get("firmware_version", "") or "",
                      ocpp_version=self.version)
        with session_scope() as s:
            st = s.query(Station).filter_by(charge_point_id=self.id).one()
            if st.vendor_profile == "generic":
                fields["vendor_profile"] = guess_profile(vendor)
        services.touch_station(self.id, **fields)
        return self.RESULT.BootNotification(current_time=now_iso(), interval=config.HEARTBEAT_INTERVAL,
                                            status="Accepted" if self.approved else "Pending")

    @on("Heartbeat")
    async def on_heartbeat(self, **kw):
        services.touch_station(self.id)
        return self.RESULT.Heartbeat(current_time=now_iso())

    @on("StatusNotification")
    async def on_status(self, timestamp, connector_status, evse_id, connector_id, **kw):
        services.set_connector_status(self.id, evse_id, connector_status)
        services.touch_station(self.id)
        return self.RESULT.StatusNotification()

    @on("Authorize")
    async def on_authorize(self, id_token, **kw):
        return self.RESULT.Authorize(id_token_info=self._id_token_info(id_token))

    @on("TransactionEvent")
    async def on_transaction_event(self, event_type, timestamp, trigger_reason, seq_no, transaction_info, **kw):
        tx_id = transaction_info["transaction_id"]
        id_token = kw.get("id_token")
        tag = id_token.get("id_token", "") if id_token and id_token.get("type") != "NoAuthorization" else ""
        energy, power = services.extract_meter(kw.get("meter_value"))
        tx = services.find_tx(self.id, tx_id)
        if tx is None or (event_type == "Started" and not tx.active):
            evse = (kw.get("evse") or {}).get("id", 1)
            tx, _ = services.start_transaction(self.id, evse, tag, energy, timestamp, ocpp_tx_id=tx_id)
        services.update_transaction(tx.id, energy, power, tag or None)
        if event_type == "Ended":
            tx = services.stop_transaction(tx.id, energy, timestamp, transaction_info.get("stopped_reason", ""))
        else:
            tx = services.find_tx(self.id, tx_id)
        return self.RESULT.TransactionEvent(total_cost=tx.cost_eur if tx else None,
                                            id_token_info=self._id_token_info(id_token))

    @on("MeterValues")
    async def on_meter(self, evse_id, meter_value, **kw):
        services.touch_station(self.id)
        return self.RESULT.MeterValues()

    @on("NotifyReport")
    async def on_notify_report(self, request_id, generated_at, seq_no, **kw):
        return self.RESULT.NotifyReport()

    @on("NotifyEvent")
    async def on_notify_event(self, generated_at, seq_no, event_data, **kw):
        return self.RESULT.NotifyEvent()

    @on("SecurityEventNotification")
    async def on_security_event(self, type, timestamp, **kw):
        services.event(self.id, "security:" + type, kw.get("tech_info", "") or "")
        return self.RESULT.SecurityEventNotification()

    @on("SignCertificate")
    async def on_sign_certificate(self, csr, **kw):
        asyncio.ensure_future(self._sign_and_send(csr, kw.get("certificate_type") or "ChargingStationCertificate"))
        return self.RESULT.SignCertificate(status="Accepted")

    async def _sign_and_send(self, csr, cert_type):
        await asyncio.sleep(0.5)
        try:
            chain = sign_station_csr(csr, self.id)
            res = await self.call(self.CALL.CertificateSigned(certificate_chain=chain, certificate_type=cert_type))
            services.event(self.id, "certificate_signed", res.status)
        except Exception as e:
            services.event(self.id, "certificate_error", str(e))

    @on("FirmwareStatusNotification")
    async def on_fw(self, status, **kw):
        services.event(self.id, "firmware", status)
        return self.RESULT.FirmwareStatusNotification()

    @on("LogStatusNotification")
    async def on_log(self, status, **kw):
        return self.RESULT.LogStatusNotification()

    @on("DataTransfer")
    async def on_data_transfer(self, vendor_id, **kw):
        services.event(self.id, "data_transfer", f"{vendor_id}: {kw}")
        return self.RESULT.DataTransfer(status="UnknownVendorId")

    # ------------------------------------------------ naredbe
    async def remote_start(self, id_tag: str, connector_id: int = 1):
        r = await self.call(self.CALL.RequestStartTransaction(
            id_token={"id_token": id_tag, "type": "ISO14443"}, remote_start_id=next(_remote_ids),
            evse_id=connector_id))
        return r.status

    async def remote_stop(self, ocpp_tx_id: str):
        return (await self.call(self.CALL.RequestStopTransaction(transaction_id=ocpp_tx_id))).status

    async def reset(self, hard: bool = False):
        return (await self.call(self.CALL.Reset(type="Immediate" if hard else "OnIdle"))).status

    async def unlock(self, connector_id: int = 1):
        return (await self.call(self.CALL.UnlockConnector(evse_id=connector_id, connector_id=1))).status

    async def set_variable(self, component: str, variable: str, value: str):
        r = await self.call(self.CALL.SetVariables(set_variable_data=[{
            "attribute_value": value, "component": {"name": component}, "variable": {"name": variable}}]))
        return r.set_variable_result[0]["attribute_status"]

    async def set_config(self, key: str, value: str):
        # Pojednostavljeno: "Komponenta.Varijabla" ili samo varijabla (OCPPCommCtrlr)
        comp, _, var = key.rpartition(".")
        return await self.set_variable(comp or "OCPPCommCtrlr", var, value)

    async def install_ca(self):
        return (await self.call(self.CALL.InstallCertificate(certificate_type="CSMSRootCertificate",
                                                             certificate=ca_pem()))).status

    async def request_csr(self):
        return (await self.call(self.CALL.TriggerMessage(
            requested_message="SignChargingStationCertificate"))).status

    async def set_password(self, password: str):
        return await self.set_variable("SecurityCtrlr", "BasicAuthPassword", password)

    async def set_security_profile(self, profile: int):
        # U 2.x se profil mijenja preko NetworkConnectionProfile (SetNetworkProfile) – vidi README.
        return "NotSupported"


class ChargePoint201(V2xMixin, CP201):
    CALL, RESULT, version = call201, cr201, "2.0.1"

    def __init__(self, cp_id, connection, approved: bool):
        CP201.__init__(self, cp_id, connection, response_timeout=30)
        self._init(approved)


class ChargePoint21(V2xMixin, CP21):
    CALL, RESULT, version = call21, cr21, "2.1"

    def __init__(self, cp_id, connection, approved: bool):
        CP21.__init__(self, cp_id, connection, response_timeout=30)
        self._init(approved)
