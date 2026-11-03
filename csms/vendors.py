"""Profili proizvođača.

Svi navedeni proizvođači govore standardni OCPP, pa jezgra sustava ne ovisi o profilu.
Profil služi za: (1) upute za konfiguraciju u sučelju, (2) sitne razlike u ponašanju
(npr. format RFID UID-a, potrebne konfiguracijske ključeve nakon spajanja).

Napomena: ponašanje je usklađeno s javnom dokumentacijom proizvođača; prije produkcije
svaki model treba provjeriti na stvarnom uređaju (vidi README, poglavlje "Testiranje").
"""

VENDOR_PROFILES: dict[str, dict] = {
    "generic": {
        "label": "Generički OCPP",
        "ocpp": ["1.6J", "2.0.1", "2.1"],
        "notes": "Standardni OCPP uređaj.",
        "post_boot_config_16": {},
    },
    "gewiss": {
        "label": "Gewiss (JOINON I-CON / Easy / Pro)",
        "ocpp": ["1.6J"],
        "notes": "OCPP se uključuje kroz Gewiss aplikaciju/web sučelje punionice: unesi URL "
                 "ws(s)://<server>:<port>/ocpp/ i Charge Point ID. Basic Auth lozinka = ključ iz ovog sustava.",
        "post_boot_config_16": {"MeterValueSampleInterval": "60"},
    },
    "schneider": {
        "label": "Schneider Electric (EVlink Pro AC/DC, EVlink Smart Wallbox)",
        "ocpp": ["1.6J", "2.0.1"],
        "notes": "Konfiguracija kroz eSetup aplikaciju. EVlink Pro podržava sigurnosne profile 1-3 "
                 "i SignCertificate (instalacija CA certifikata prije prelaska na wss).",
        "post_boot_config_16": {"MeterValueSampleInterval": "60",
                                "MeterValuesSampledData": "Energy.Active.Import.Register,Power.Active.Import"},
    },
    "sma": {
        "label": "SMA (EV Charger Business)",
        "ocpp": ["1.6J"],
        "notes": "U web sučelju punionice: Konfiguracija > OCPP. Charge Point ID mora biti jednak ID-u "
                 "u ovom sustavu.",
        "post_boot_config_16": {"MeterValueSampleInterval": "60"},
    },
    "huawei": {
        "label": "Huawei (SCharger / FusionCharge AC)",
        "ocpp": ["1.6J"],
        "notes": "Konfiguracija kroz FusionSolar aplikaciju (Commissioning > OCPP). Huawei RFID UID "
                 "ponekad šalje malim slovima – sustav ga normalizira u velika slova.",
        "post_boot_config_16": {"MeterValueSampleInterval": "60"},
    },
    "fronius": {
        "label": "Fronius (Wattpilot)",
        "ocpp": ["1.6J"],
        "notes": "U Solar.wattpilot aplikaciji: Internet > OCPP. Uključi OCPP, upiši URL i ID.",
        "post_boot_config_16": {"MeterValueSampleInterval": "60"},
    },
}


def guess_profile(vendor: str) -> str:
    v = (vendor or "").lower()
    for key in ("gewiss", "schneider", "sma", "huawei", "fronius"):
        if key in v:
            return key
    if "evlink" in v:
        return "schneider"
    return "generic"


def normalize_id_tag(tag: str) -> str:
    """RFID UID normaliziramo: bez razmaka/dvotočki, velika slova (različiti čitači šalju različito)."""
    return (tag or "").strip().replace(" ", "").replace(":", "").replace("-", "").upper()
