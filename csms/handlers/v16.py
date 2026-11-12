"""OCPP 1.6J (uključujući 'Security Extension' / Improved Security for OCPP 1.6-J)."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from ocpp.routing import on
from ocpp.v16 import ChargePoint as CP16
from ocpp.v16 import call, call_result

from .. import config, services
from ..db import Station, session_scope
from ..security import ca_pem, sign_station_csr
from ..vendors import VENDOR_PROFILES, guess_profile


def v16_status(status: str) -> str:
    """OCPP 1.6 nema statusa NotAtThisLocation (kartica bez dozvole za punionicu)."""
    return status if status in ("Accepted", "Blocked", "Expired", "Invalid", "ConcurrentTx") else "Invalid"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ChargePoint16(CP16):
    version = "1.6"

    def __init__(self, cp_id, connection, approved: bool):
        super().__init__(cp_id, connection, response_timeout=30)
        self.approved = approved

    # ------------------------------------------------ poruke od punionice
    @on("BootNotification")
    async def on_boot(self, charge_point_vendor, charge_point_model, **kw):
        fields = dict(vendor=charge_point_vendor, model=charge_point_model,
                      serial=kw.get("charge_point_serial_number") or kw.get("charge_box_serial_number") or "",
                      firmware=kw.get("firmware_version", ""), ocpp_version="1.6J")
        with session_scope() as s:
            st = s.query(Station).filter_by(charge_point_id=self.id).one()
            if st.vendor_profile == "generic":
                fields["vendor_profile"] = guess_profile(charge_point_vendor)
        services.touch_station(self.id, **fields)
        if self.approved:
            asyncio.get_running_loop().call_later(2, lambda: asyncio.ensure_future(self._post_boot()))
        return call_result.BootNotification(current_time=now_iso(), interval=config.HEARTBEAT_INTERVAL,
                                            status="Accepted" if self.approved else "Pending")

    async def _post_boot(self):
        """Nakon spajanja pošalji preporučene postavke iz profila proizvođača."""
        with session_scope() as s:
            prof = s.query(Station).filter_by(charge_point_id=self.id).one().vendor_profile
        for key, value in VENDOR_PROFILES.get(prof, {}).get("post_boot_config_16", {}).items():
            try:
                await self.call(call.ChangeConfiguration(key=key, value=value))
            except Exception as e:  # uređaj ne podržava ključ – nije kritično
                services.event(self.id, "config_warning", f"{key}: {e}")

    @on("Heartbeat")
    async def on_heartbeat(self, **kw):
        services.touch_station(self.id)
        return call_result.Heartbeat(current_time=now_iso())

    @on("StatusNotification")
    async def on_status(self, connector_id, error_code, status, **kw):
        services.set_connector_status(self.id, connector_id, status, error_code if error_code != "NoError" else "")
        services.touch_station(self.id)
        return call_result.StatusNotification()

    @on("Authorize")
    async def on_authorize(self, id_tag, **kw):
        res = services.authorize_tag(id_tag, self.id) if self.approved else services.AuthResult("Invalid")
        return call_result.Authorize(id_tag_info={"status": v16_status(res.status)})

    @on("StartTransaction")
    async def on_start(self, connector_id, id_tag, meter_start, timestamp, **kw):
        tx, auth = services.start_transaction(self.id, connector_id, id_tag, float(meter_start), timestamp)
        status = v16_status(auth.status) if self.approved else "Invalid"
        return call_result.StartTransaction(transaction_id=tx.id, id_tag_info={"status": status})

    @on("MeterValues")
    async def on_meter(self, connector_id, meter_value, transaction_id=None, **kw):
        if transaction_id is not None:
            tx = services.find_tx(self.id, str(transaction_id))
            if tx:
                e, p = services.extract_meter(meter_value)
                services.update_transaction(tx.id, e, p)
        services.touch_station(self.id)
        return call_result.MeterValues()

    @on("StopTransaction")
    async def on_stop(self, meter_stop, timestamp, transaction_id, **kw):
        tx = services.find_tx(self.id, str(transaction_id))
        if tx:
            if kw.get("transaction_data"):
                e, p = services.extract_meter(kw["transaction_data"])
                services.update_transaction(tx.id, e, p)
            services.stop_transaction(tx.id, float(meter_stop), timestamp, kw.get("reason", ""))
        id_tag = kw.get("id_tag")
        info = {"status": v16_status(services.authorize_tag(id_tag).status)} if id_tag else None
        return call_result.StopTransaction(id_tag_info=info)

    @on("DataTransfer")
    async def on_data_transfer(self, vendor_id, **kw):
        services.event(self.id, "data_transfer", f"{vendor_id}: {kw}")
        return call_result.DataTransfer(status="UnknownVendorId")

    @on("DiagnosticsStatusNotification")
    async def on_diag(self, status, **kw):
        return call_result.DiagnosticsStatusNotification()

    @on("FirmwareStatusNotification")
    async def on_fw(self, status, **kw):
        services.event(self.id, "firmware", status)
        return call_result.FirmwareStatusNotification()

    # --- Security extension
    @on("SecurityEventNotification")
    async def on_security_event(self, type, timestamp, **kw):
        services.event(self.id, "security:" + type, kw.get("tech_info", ""))
        return call_result.SecurityEventNotification()

    @on("SignCertificate")
    async def on_sign_certificate(self, csr, **kw):
        asyncio.ensure_future(self._sign_and_send(csr))
        return call_result.SignCertificate(status="Accepted")

    async def _sign_and_send(self, csr):
        await asyncio.sleep(0.5)
        try:
            chain = sign_station_csr(csr, self.id)
            res = await self.call(call.CertificateSigned(certificate_chain=chain))
            services.event(self.id, "certificate_signed", res.status)
        except Exception as e:
            services.event(self.id, "certificate_error", str(e))

    @on("LogStatusNotification")
    async def on_log_status(self, status, **kw):
        return call_result.LogStatusNotification()

    @on("SignedFirmwareStatusNotification")
    async def on_signed_fw(self, status, **kw):
        services.event(self.id, "firmware", status)
        return call_result.SignedFirmwareStatusNotification()

    # ------------------------------------------------ naredbe prema punionici
    async def remote_start(self, id_tag: str, connector_id: int = 1):
        return (await self.call(call.RemoteStartTransaction(id_tag=id_tag, connector_id=connector_id))).status

    async def remote_stop(self, ocpp_tx_id: str):
        return (await self.call(call.RemoteStopTransaction(transaction_id=int(ocpp_tx_id)))).status

    async def reset(self, hard: bool = False):
        return (await self.call(call.Reset(type="Hard" if hard else "Soft"))).status

    async def unlock(self, connector_id: int = 1):
        return (await self.call(call.UnlockConnector(connector_id=connector_id))).status

    async def set_config(self, key: str, value: str):
        return (await self.call(call.ChangeConfiguration(key=key, value=value))).status

    async def install_ca(self):
        return (await self.call(call.InstallCertificate(certificate_type="CentralSystemRootCertificate",
                                                        certificate=ca_pem()))).status

    async def request_csr(self):
        return (await self.call(call.ExtendedTriggerMessage(
            requested_message="SignChargePointCertificate"))).status

    async def set_password(self, password: str):
        return await self.set_config("AuthorizationKey", password)

    async def set_security_profile(self, profile: int):
        return await self.set_config("SecurityProfile", str(profile))
