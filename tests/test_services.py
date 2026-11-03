from csms import services
from csms.vendors import normalize_id_tag


def test_normalize_tag():
    assert normalize_id_tag(" 04:a1:b2 c3-d4 ") == "04A1B2C3D4"


def test_extract_meter_16_wh_and_kwh():
    mv = [{"sampled_value": [{"value": "1234.5", "measurand": "Energy.Active.Import.Register", "unit": "Wh"},
                             {"value": "11", "measurand": "Power.Active.Import", "unit": "kW"},
                             {"value": "400", "measurand": "Energy.Active.Import.Register", "phase": "L1"}]}]
    assert services.extract_meter(mv) == (1234.5, 11000.0)
    mv = [{"sampled_value": [{"value": "12.5", "unit": "kWh"}]}]  # zadani measurand = energija
    assert services.extract_meter(mv)[0] == 12500.0


def test_extract_meter_2x_unit_of_measure():
    mv = [{"sampled_value": [{"value": 3.2, "measurand": "Energy.Active.Import.Register",
                              "unit_of_measure": {"unit": "kWh"}},
                             {"value": 7, "measurand": "Power.Active.Import",
                              "unit_of_measure": {"unit": "W", "multiplier": 3}}]}]
    assert services.extract_meter(mv) == (3200.0, 7000.0)
