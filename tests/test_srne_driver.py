from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from custom_components.eybond_local.drivers.srne import SrneModbusDriver  # noqa: E402
from custom_components.eybond_local.drivers.read_result import (  # noqa: E402
    DriverReadMode,
    DriverReadResult,
)
from custom_components.eybond_local.fixtures.transport import FixtureTransport  # noqa: E402
from custom_components.eybond_local.models import ProbeTarget  # noqa: E402
from custom_components.eybond_local.payload.modbus import (  # noqa: E402
    ModbusError,
    crc16_modbus,
    decode_read_request,
)
from custom_components.eybond_local.support.package import export_support_package  # noqa: E402
from custom_components.eybond_local.support.runtime_projection import build_support_fixture  # noqa: E402
from custom_components.eybond_local.metadata.register_schema_loader import (  # noqa: E402
    load_register_schema,
)
from custom_components.eybond_local.drivers.write_confirmation import (  # noqa: E402
    WRITE_CONFIRMATION_DIAGNOSTIC_KEY,
    load_write_confirmation,
)


def _full_values(result: DriverReadResult) -> dict[str, object]:
    if type(result) is not DriverReadResult or result.mode is not DriverReadMode.FULL:
        raise AssertionError("SRNE runtime read must be an exact FULL result")
    return result.values


def _low_byte_ascii_words(text: str, count: int) -> list[int]:
    padded = text[:count].ljust(count)
    return [ord(char) for char in padded]


def _srne_registers(*, include_phase: bool = True, product_info: str = "SR-2206260036-300917") -> dict[int, int]:
    registers: dict[int, int] = {}
    schema_name = (
        "srne_modbus/smx_ii_24v.json"
        if product_info == "SR-2206260036-300917"
        else "srne_modbus/base.json"
    )
    for block in load_register_schema(schema_name).blocks:
        if block.key == "phase" and not include_phase:
            continue
        for offset in range(block.count):
            registers[block.start + offset] = 0

    for offset, word in enumerate(_low_byte_ascii_words(product_info, 20)):
        registers[53 + offset] = word

    registers.update(
        {
            256: 85,
            257: 512 if product_info == "SR-EOV24" else 287,
            258: 123,
            263: 3561,
            264: 42,
            265: 680,
            267: 2,
            270: 900,
            271: 3482,
            272: 38,
            273: 620,
            516: 7,
            524: 0x3808,
            525: 0x160C,
            526: 0x2238,
            528: 5,
            531: 2301,
            533: 5002,
            534: 2298,
            536: 4998,
            537: 56,
            539: 1200,
            540: 1300,
            542: 101,
            543: 64,
            544: 425,
            545: 392,
            57345: 600,
            57346: 280,
            57348: 0,
            57353: 142,
            57371: 110,
            57378: 144,
            57624: 36000,
            57860: 2,
            57861: 200,
            57865: 5000,
            57866: 800,
            57871: 3,
            61487: 126,
            61488: 94,
            61496: 34464,
            61497: 1,
            61498: 9876,
            61499: 0,
            61514: 1234,
            61515: 567,
        }
    )

    if include_phase:
        registers.update(
            {
                554: 2310,
                555: 2320,
                556: 2280,
                557: 2270,
                560: 25,
                561: 26,
                562: 510,
                563: 520,
                564: 610,
                565: 620,
                566: 31,
                567: 32,
            }
        )
    return registers


class _RecordingFixtureTransport(FixtureTransport):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.holding_reads: list[tuple[int, int]] = []
        self.write_functions: list[int] = []

    def _handle_read_holding(self, payload: bytes) -> bytes:
        self.holding_reads.append(
            (
                int.from_bytes(payload[2:4], "big"),
                int.from_bytes(payload[4:6], "big"),
            )
        )
        return super()._handle_read_holding(payload)

    def _handle_write_single(self, payload: bytes) -> bytes:
        self.write_functions.append(6)
        return super()._handle_write_single(payload)

    def _handle_write_multiple(self, payload: bytes) -> bytes:
        self.write_functions.append(16)
        return super()._handle_write_multiple(payload)


class _PasswordProtectedTransport(_RecordingFixtureTransport):
    """A device that rejects setting writes until its user login is accepted."""

    def __init__(
        self, *, denied_register=0xE008, denial_code=11,
        login_error=None, permanently_locked=False, **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.denied_register = denied_register
        self.denial_code = denial_code
        self.login_error = login_error
        self.permanently_locked = permanently_locked
        self.authenticated = False
        self.wire_writes: list[tuple[int, int, int]] = []

    @staticmethod
    def _exception(payload: bytes, code: int) -> bytes:
        response = bytes((payload[0], payload[1] | 0x80, code))
        return response + crc16_modbus(response).to_bytes(2, "little")

    def _handle_write_single(self, payload: bytes) -> bytes:
        address = int.from_bytes(payload[2:4], "big")
        value = int.from_bytes(payload[4:6], "big")
        self.wire_writes.append((6, address, value))
        if address == self.denied_register and (
            not self.authenticated or self.permanently_locked
        ):
            return self._exception(payload, self.denial_code)
        return super()._handle_write_single(payload)

    def _handle_write_multiple(self, payload: bytes) -> bytes:
        address = int.from_bytes(payload[2:4], "big")
        value = int.from_bytes(payload[7:9], "big")
        self.wire_writes.append((16, address, value))
        if address == 0xE203:
            if payload[4:7] != b"\x00\x01\x02" or value != 0:
                raise AssertionError("Expected exactly one default user login word")
            if self.login_error is not None:
                return self._exception(payload, self.login_error)
            self.authenticated = True
        return super()._handle_write_multiple(payload)


class SrneModbusDriverTests(unittest.IsolatedAsyncioTestCase):
    async def test_other_and_unidentified_srne_units_remain_read_only(self) -> None:
        driver = SrneModbusDriver()
        target = ProbeTarget(1, 255, 1)
        identified = await driver.async_probe(
            FixtureTransport(
                registers=_srne_registers(), command_responses=None, probe_target=target,
            ),
            target,
        )
        self.assertTrue(identified.capabilities)
        for product_info in ("SR-EOV24", "SR-EOV48", "SR-UNKNOWN",
                             "SR-2206260036-300918", "SR-2206260036-30091X"):
            with self.subTest(product_info=product_info):
                # Even matching live voltage and power do not establish identity.
                registers = _srne_registers(product_info=product_info)
                registers[257] = 287
                transport = _RecordingFixtureTransport(
                    registers=registers, command_responses=None, probe_target=target,
                )
                inverter = await driver.async_probe(transport, target)
                self.assertIsNotNone(inverter)
                self.assertEqual(inverter.profile_name, "")
                self.assertEqual(inverter.register_schema_name, "srne_modbus/base.json")
                self.assertEqual(inverter.capabilities, ())
                self.assertEqual(driver.write_capabilities, ())
                with self.assertRaises(ValueError):
                    await driver.async_write_capability(
                        transport, inverter, "battery_float_voltage", 28.4,
                    )
                self.assertEqual(transport.write_functions, [])

    async def test_detected_read_only_family_has_restorable_catalog_proof(self):
        from dataclasses import replace
        from custom_components.eybond_local.metadata.effective_metadata_snapshot import (
            build_effective_metadata_snapshot_from_runtime,
            effective_metadata_snapshot_from_dict,
        )

        driver = SrneModbusDriver()
        target = ProbeTarget(1, 255, 1)
        link = FixtureTransport(registers=_srne_registers(product_info="SR-EOV24"), command_responses=None, probe_target=target)
        inverter = await driver.async_probe(link, target)
        proof = inverter.details["catalog_detection"]
        self.assertEqual(proof["resolution"], "family")
        self.assertEqual(proof["confidence"], "medium")
        snapshot = build_effective_metadata_snapshot_from_runtime(
            inverter=inverter, confidence=proof["confidence"],
        )
        self.assertTrue(snapshot.is_valid)
        self.assertTrue(effective_metadata_snapshot_from_dict(snapshot.as_dict()).is_valid)
        self.assertFalse(snapshot.profile_name)
        self.assertFalse(inverter.capabilities)
        for delta in (
            {"catalog_version": ""}, {"catalog_version": "stale"},
            {"candidate_keys": ()}, {"evidence_fingerprint": ""},
            {"descriptor_revisions": ("srne_modbus_family:stale",)},
        ):
            self.assertFalse(replace(snapshot, **delta).is_valid, delta)
    async def _protected_case(self, **options):
        driver = SrneModbusDriver()
        target = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
        registers = _srne_registers()
        registers[0xE008] = 143  # Captured 28.6 V before the user's write.
        transport = _PasswordProtectedTransport(
            registers=registers, command_responses=None, probe_target=target,
            **options,
        )
        inverter = await driver.async_probe(transport, target)
        assert inverter is not None
        return driver, transport, inverter

    async def test_denied_boost_write_authorizes_then_confirms_28_4_volts(self) -> None:
        driver, transport, inverter = await self._protected_case()
        state = {}
        result = await driver.async_write_capability(
            transport, inverter, "battery_boost_voltage", 28.4, runtime_state=state,
        )
        self.assertAlmostEqual(result, 28.4)
        self.assertEqual(transport.wire_writes, [
            (6, 0xE008, 142), (16, 0xE203, 0), (6, 0xE008, 142),
        ])
        self.assertEqual(transport._registers[0xE008], 142)
        self.assertNotIn(0xE202, transport._registers)
        self.assertEqual(transport.holding_reads[-1], (0xE008, 1))
        self.assertEqual(load_write_confirmation(state).immediate_status, "matched")
        poll = await driver.async_read_values(transport, inverter, runtime_state=state)
        self.assertEqual(
            poll.diagnostics[WRITE_CONFIRMATION_DIAGNOSTIC_KEY]["convergence"],
            "requested_value_observed",
        )

    async def test_nonzero_password_status_does_not_try_default_password(self) -> None:
        driver, transport, inverter = await self._protected_case()
        transport._registers[0x0211] = 1
        with self.assertRaisesRegex(ModbusError, "exception_code:11"):
            await driver.async_write_capability(
                transport, inverter, "battery_boost_voltage", 28.4,
            )
        self.assertEqual(transport.wire_writes, [(6, 0xE008, 142)])

    async def test_failed_login_does_not_retry_setting(self) -> None:
        driver, transport, inverter = await self._protected_case(login_error=11)
        with self.assertRaisesRegex(ModbusError, "exception_code:11"):
            await driver.async_write_capability(
                transport, inverter, "battery_boost_voltage", 28.4,
            )
        self.assertEqual(transport.wire_writes, [(6, 0xE008, 142), (16, 0xE203, 0)])
        self.assertEqual(transport._registers[0xE008], 143)

    async def test_firmware_lock_does_not_repeat_login_or_report_success(self) -> None:
        driver, transport, inverter = await self._protected_case(permanently_locked=True)
        state = {}
        with self.assertRaisesRegex(ModbusError, "exception_code:11"):
            await driver.async_write_capability(
                transport, inverter, "battery_boost_voltage", 28.4, runtime_state=state,
            )
        self.assertEqual(len(transport.wire_writes), 3)
        self.assertEqual(transport._registers[0xE008], 143)
        self.assertIsNone(load_write_confirmation(state))

    async def test_other_exception_does_not_authorize_or_retry(self) -> None:
        driver, transport, inverter = await self._protected_case(denial_code=3)
        with self.assertRaisesRegex(ModbusError, "exception_code:3"):
            await driver.async_write_capability(
                transport, inverter, "battery_boost_voltage", 28.4,
            )
        self.assertEqual(transport.wire_writes, [(6, 0xE008, 142)])

    async def test_setting_timeout_does_not_authorize_or_retry(self) -> None:
        driver, transport, inverter = await self._protected_case()

        def no_reply(payload):
            transport.wire_writes.append((6, 0xE008, 142))
            raise asyncio.TimeoutError

        transport._handle_write_single = no_reply
        with self.assertRaisesRegex(ModbusError, "request_timeout"):
            await driver.async_write_capability(
                transport, inverter, "battery_boost_voltage", 28.4,
            )
        self.assertEqual(transport.wire_writes, [(6, 0xE008, 142)])

    async def test_full_poll_still_rejects_a_different_register_value(self) -> None:
        driver, transport, inverter = await self._protected_case()
        state = {}
        await driver.async_write_capability(
            transport, inverter, "battery_boost_voltage", 28.4, runtime_state=state,
        )
        transport._registers[0xE008] = 143
        poll = await driver.async_read_values(transport, inverter, runtime_state=state)
        self.assertEqual(
            poll.diagnostics[WRITE_CONFIRMATION_DIAGNOSTIC_KEY]["convergence"],
            "requested_value_not_observed",
        )

    async def test_equalization_command_is_not_authorized_or_repeated(self) -> None:
        driver, transport, inverter = await self._protected_case(denied_register=0xDF0D)
        with self.assertRaisesRegex(ModbusError, "exception_code:11"):
            await driver.async_write_capability(
                transport, inverter, "battery_equalize_now", True,
            )
        self.assertEqual(transport.wire_writes, [(6, 0xDF0D, 1)])

    async def test_probe_detects_srne_product_info_on_slave_one(self) -> None:
        driver = SrneModbusDriver()
        target = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
        transport = FixtureTransport(
            registers=_srne_registers(),
            command_responses=None,
            probe_target=target,
        )

        inverter = await driver.async_probe(transport, target)

        self.assertIsNotNone(inverter)
        assert inverter is not None
        self.assertEqual(inverter.driver_key, "srne_modbus")
        self.assertEqual(inverter.protocol_family, "srne_modbus")
        self.assertEqual(inverter.model_name, "SRNE SR-2206260036-300917")
        self.assertEqual(inverter.variant_key, "smx_ii_24v")
        self.assertEqual(inverter.profile_name, "srne_modbus/smx_ii.json")
        self.assertEqual(inverter.register_schema_name, "srne_modbus/smx_ii_24v.json")
        self.assertGreater(len(inverter.capabilities), 20)
        self.assertEqual(inverter.probe_target.device_addr, 1)
        self.assertEqual(inverter.details["product_info"], "SR-2206260036-300917")
        proof = inverter.details["catalog_detection"]
        self.assertEqual(proof["resolution"], "exact")
        self.assertEqual(proof["candidate_keys"], ["easun_smx_ii_24v_owner_unit"])
        self.assertEqual(driver.profile_name, "")
        self.assertEqual(driver.register_schema_name, "srne_modbus/base.json")
        self.assertEqual(driver.write_capabilities, ())
        from custom_components.eybond_local.metadata.effective_metadata_snapshot import (
            build_effective_metadata_snapshot_from_runtime,
            effective_metadata_snapshot_from_dict,
        )

        snapshot = build_effective_metadata_snapshot_from_runtime(
            inverter=inverter, confidence=proof["confidence"],
        )
        self.assertTrue(snapshot.is_valid)
        self.assertTrue(effective_metadata_snapshot_from_dict(snapshot.as_dict()).is_valid)

    async def test_probe_rejects_non_srne_product_info(self) -> None:
        driver = SrneModbusDriver()
        target = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
        registers = _srne_registers()
        for offset, word in enumerate(_low_byte_ascii_words("INV-0001", 20)):
            registers[53 + offset] = word
        transport = FixtureTransport(
            registers=registers,
            command_responses=None,
            probe_target=target,
        )

        inverter = await driver.async_probe(transport, target)

        self.assertIsNone(inverter)

    async def test_read_values_decodes_srne_register_map(self) -> None:
        driver = SrneModbusDriver()
        target = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
        transport = FixtureTransport(
            registers=_srne_registers(),
            command_responses=None,
            probe_target=target,
        )
        inverter = await driver.async_probe(transport, target)
        assert inverter is not None

        values = _full_values(await driver.async_read_values(transport, inverter))

        self.assertEqual(values["product_info"], "SR-2206260036-300917")
        self.assertEqual(values["battery_percent"], 85)
        self.assertEqual(values["battery_voltage"], 28.7)
        self.assertEqual(values["battery_current"], 12.3)
        self.assertEqual(values["pv1_input_voltage"], 356.1)
        self.assertEqual(values["pv1_input_current"], 4.2)
        self.assertEqual(values["pv1_input_power"], 680)
        self.assertEqual(values["inverter_charge_state"], "Constant voltage")
        self.assertEqual(values["charge_power"], 900)
        self.assertEqual(values["pv2_input_voltage"], 348.2)
        self.assertEqual(values["pv2_input_current"], 3.8)
        self.assertEqual(values["pv2_input_power"], 620)
        self.assertEqual(values["fault_code"], 7)
        self.assertEqual(values["system_datetime"], "2026-09-22 12:34:56")
        self.assertEqual(values["inverter_operation_mode"], "Running on inverter")
        self.assertEqual(values["grid_voltage"], 230.1)
        self.assertEqual(values["grid_frequency"], 50.02)
        self.assertEqual(values["output_voltage"], 229.8)
        self.assertEqual(values["output_frequency"], 49.98)
        self.assertEqual(values["output_current"], 5.6)
        self.assertEqual(values["output_power"], 1200)
        self.assertEqual(values["output_va"], 1300)
        self.assertEqual(values["battery_charge_current"], 10.1)
        self.assertEqual(values["load_percent"], 64)
        self.assertEqual(values["dcdc_temperature"], 42.5)
        self.assertEqual(values["inverter_temperature"], 39.2)
        self.assertEqual(values["max_pv_charge_current"], 60.0)
        self.assertEqual(values["battery_capacity"], 280)
        self.assertEqual(values["battery_float_voltage"], 28.4)
        self.assertEqual(values["turn_to_utility_voltage"], 22.0)
        self.assertEqual(values["turn_to_inverter_voltage"], 28.8)
        self.assertEqual(values["rated_power"], 3600.0)
        self.assertEqual(values["output_priority"], "Battery First")
        self.assertEqual(values["charger_source_priority"], "PV Only")
        self.assertEqual(values["pv_energy_today"], 12.6)
        self.assertEqual(values["load_energy_today"], 9.4)
        self.assertEqual(values["pv_energy_total"], 10000.0)
        self.assertEqual(values["load_energy_total"], 987.6)
        self.assertEqual(values["inverter_runtime_total"], 1234)
        self.assertEqual(values["grid_voltage_l2"], 231.0)
        self.assertEqual(values["output_power_l3"], 520)
        self.assertEqual(values["load_percent_l3"], 32)

    async def test_runtime_avoids_wide_controller_read_with_unsupported_holes(self) -> None:
        driver = SrneModbusDriver()
        target = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
        registers = _srne_registers()
        # Real SMX-II firmware may reject 256..273 as one range even though the
        # documented sub-ranges answer independently.
        transport = _RecordingFixtureTransport(
            registers=registers,
            command_responses=None,
            probe_target=target,
        )
        inverter = await driver.async_probe(transport, target)
        assert inverter is not None

        values = _full_values(await driver.async_read_values(transport, inverter))

        self.assertEqual(values["battery_percent"], 85)
        self.assertEqual(values["pv1_input_power"], 680)
        self.assertNotIn((256, 18), transport.holding_reads)
        self.assertIn((256, 3), transport.holding_reads)
        self.assertIn((263, 3), transport.holding_reads)

    async def test_write_uses_fc06_and_immediately_reads_back_exact_register(self) -> None:
        driver = SrneModbusDriver()
        target = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
        registers = _srne_registers()
        registers[0xE20A] = 300
        transport = _RecordingFixtureTransport(
            registers=registers,
            command_responses=None,
            probe_target=target,
        )
        inverter = await driver.async_probe(transport, target)
        assert inverter is not None
        runtime_state: dict[str, object] = {}

        result = await driver.async_write_capability(
            transport,
            inverter,
            "max_charge_current",
            35.0,
            runtime_state=runtime_state,
        )

        self.assertEqual(result, 35.0)
        self.assertEqual(transport.write_functions, [6])
        self.assertEqual(transport._registers[0xE20A], 350)
        self.assertEqual(transport.holding_reads[-1], (0xE20A, 1))
        trace = load_write_confirmation(runtime_state)
        assert trace is not None
        self.assertEqual(trace.immediate_status, "matched")
        self.assertEqual(trace.immediate_words, (350,))

        poll = await driver.async_read_values(
            transport,
            inverter,
            runtime_state=runtime_state,
        )
        confirmation = poll.diagnostics[WRITE_CONFIRMATION_DIAGNOSTIC_KEY]
        self.assertEqual(confirmation["latest_full_poll_status"], "matched")
        self.assertEqual(confirmation["latest_full_poll_value"], 35.0)
        self.assertEqual(confirmation["convergence"], "requested_value_observed")

    async def test_smx_ii_24v_battery_thresholds_use_pack_voltage_scale(self) -> None:
        """SMX-II stores 24 V thresholds in 0.2 V wire increments."""

        driver = SrneModbusDriver()
        target = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
        registers = _srne_registers()
        registers[57353] = 142  # 28.4 V float voltage on a 24 V unit
        transport = _RecordingFixtureTransport(
            registers=registers,
            command_responses=None,
            probe_target=target,
        )
        inverter = await driver.async_probe(transport, target)
        assert inverter is not None

        values = _full_values(await driver.async_read_values(transport, inverter))
        self.assertEqual(values["battery_float_voltage"], 28.4)

        result = await driver.async_write_capability(
            transport,
            inverter,
            "battery_float_voltage",
            28.8,
            runtime_state={},
        )

        self.assertEqual(result, 28.8)
        self.assertEqual(transport._registers[57353], 144)
        self.assertEqual(transport.write_functions, [6])
        self.assertEqual(transport.holding_reads[-1], (57353, 1))

    async def test_fc16_bitmask_write_preserves_unrelated_bits(self) -> None:
        driver = SrneModbusDriver()
        target = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
        registers = _srne_registers()
        registers[0xDF00] = 0xA5A4
        transport = _RecordingFixtureTransport(
            registers=registers,
            command_responses=None,
            probe_target=target,
        )
        inverter = await driver.async_probe(transport, target)
        assert inverter is not None

        result = await driver.async_write_capability(
            transport,
            inverter,
            "inverter_power",
            True,
            runtime_state={},
        )

        self.assertIs(result, True)
        self.assertEqual(transport.write_functions, [16])
        self.assertEqual(transport._registers[0xDF00], 0xA5A5)
        self.assertEqual(transport.holding_reads[-1], (0xDF00, 1))

    def test_every_runtime_spec_is_covered_by_a_read_block(self) -> None:
        schema = load_register_schema("srne_modbus/smx_ii_24v.json")

        uncovered = [
            spec.key
            for spec in schema.spec_set("runtime")
            if not any(
                block.start <= spec.register
                and spec.register + spec.word_count <= block.start + block.count
                for block in schema.blocks
            )
        ]

        self.assertEqual(uncovered, [])

    def test_every_runtime_value_has_an_entity_description(self) -> None:
        schema = load_register_schema("srne_modbus/smx_ii_24v.json")
        described = {item.key for item in schema.measurement_descriptions}

        self.assertEqual(
            [spec.key for spec in schema.spec_set("runtime") if spec.key not in described],
            [],
        )

    async def test_read_values_tolerates_missing_optional_phase_block(self) -> None:
        driver = SrneModbusDriver()
        target = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
        transport = FixtureTransport(
            registers=_srne_registers(include_phase=False),
            command_responses=None,
            probe_target=target,
        )
        inverter = await driver.async_probe(transport, target)
        assert inverter is not None

        values = _full_values(await driver.async_read_values(transport, inverter))

        self.assertEqual(values["product_info"], "SR-2206260036-300917")
        self.assertEqual(values["output_power"], 1200)
        self.assertNotIn("grid_voltage_l2", values)

    async def test_read_values_keeps_core_telemetry_when_high_blocks_are_unsupported(self) -> None:
        driver = SrneModbusDriver()
        target = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
        registers = {
            address: value
            for address, value in _srne_registers().items()
            if address < 57000
        }
        transport = FixtureTransport(
            registers=registers,
            command_responses=None,
            probe_target=target,
        )
        inverter = await driver.async_probe(transport, target)
        assert inverter is not None

        values = _full_values(await driver.async_read_values(transport, inverter))

        self.assertEqual(values["battery_voltage"], 28.7)
        self.assertEqual(values["output_power"], 1200)
        self.assertNotIn("max_charge_current", values)
        self.assertNotIn("pv_energy_total", values)

    async def test_support_evidence_captures_planned_ranges(self) -> None:
        driver = SrneModbusDriver()
        target = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
        transport = FixtureTransport(
            registers=_srne_registers(),
            command_responses=None,
            probe_target=target,
        )
        inverter = await driver.async_probe(transport, target)
        assert inverter is not None

        evidence = await driver.async_capture_support_evidence(transport, inverter)

        self.assertEqual(evidence["capture_kind"], "srne_modbus_register_dump")
        self.assertEqual(evidence["range_failures"], [])
        planned = [(item["start"], item["count"]) for item in evidence["planned_ranges"]]
        self.assertIn((53, 20), planned)
        self.assertIn((528, 19), planned)
        self.assertIn((554, 14), planned)
        self.assertEqual(len(evidence["fixture_ranges"]), len(planned))


class _ReadOnlySrneTransport(FixtureTransport):
    """Replay an inverter rejecting reads that include undocumented holes."""

    def __init__(self, registers: dict[int, int], target: ProbeTarget) -> None:
        super().__init__(registers=registers, command_responses=None, probe_target=target)
        self.requests: list[tuple[int, int]] = []

    async def async_send_payload(self, payload, *, route):
        request = decode_read_request(payload)
        if request is None or request.function_code != 3:
            raise AssertionError("Support capture must only issue FC3 reads")
        self.requests.append((request.address, request.count))
        if any(
            address not in self._registers
            for address in range(request.address, request.address + request.count)
        ):
            response = bytes((request.slave_id, 0x83, 2))
            return response + crc16_modbus(response).to_bytes(2, "little")
        return await super().async_send_payload(payload, route=route)


class SrneSupportDiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.driver = SrneModbusDriver()
        target = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
        registers = _srne_registers(include_phase=False, product_info="SR-EOV24")
        del registers[269]  # 0x010D: reserved; never read it separately.
        self.transport = _ReadOnlySrneTransport(registers, target)
        self.inverter = await self.driver.async_probe(self.transport, target)
        assert self.inverter is not None
        self.transport.requests.clear()

    async def test_rejected_dc_block_gets_only_fixed_support_subranges(self) -> None:
        evidence = await self.driver.async_capture_support_evidence(
            self.transport, self.inverter
        )

        normal = [(53, 20), (256, 18), (516, 4), (528, 18), (554, 14)]
        extra = [(256, 3), (263, 3), (267, 1), (270, 1), (271, 3)]
        self.assertEqual(self.transport.requests, normal + extra)
        self.assertEqual(
            [(item["start"], item["count"]) for item in evidence["planned_ranges"]],
            normal,
        )
        self.assertEqual(
            evidence["range_failures"],
            [
                {"start": 256, "count": 18, "error": "exception_code:2"},
                {"start": 554, "count": 14, "error": "exception_code:2"},
            ],
        )
        diagnostics = evidence["dc_subrange_diagnostics"]
        self.assertEqual(diagnostics["status"], "completed")
        self.assertEqual(diagnostics["range_failures"], [])
        self.assertEqual(diagnostics["trigger_range"], {"start": 256, "count": 18})
        self.assertEqual(diagnostics["time_budget_seconds"], 15.0)
        captured = diagnostics["captured_ranges"]
        self.assertEqual([(item["start"], item["count"]) for item in captured], extra)
        self.assertEqual(captured[0]["words"], [85, 512, 123])
        self.assertEqual(len(evidence["captured_ranges"]), 3)
        self.assertEqual(len(evidence["fixture_ranges"]), 8)

        # Runtime fallback is based on its own live rejection, not archive state.
        self.transport.requests.clear()
        values = _full_values(
            await self.driver.async_read_values(self.transport, self.inverter)
        )
        self.assertEqual(self.transport.requests, normal[:2] + extra + normal[2:])
        self.assertEqual(values["output_power"], 1200)
        self.assertEqual(values["battery_voltage"], 51.2)
        self.assertEqual(
            [(plan.start, plan.count) for plan in self.driver.local_register_read_plans(self.inverter)],
            normal[:1] + extra + normal[2:],
        )

    async def test_runtime_fallback_exposes_battery_without_inventing_missing_pv2(self) -> None:
        for register in (271, 272, 273):
            del self.transport._registers[register]
        self.transport._registers.update({256: 93, 257: 287, 258: 65430})
        values = _full_values(await self.driver.async_read_values(self.transport, self.inverter))
        self.assertEqual(values["battery_percent"], 93)
        self.assertEqual(values["battery_voltage"], 28.7)
        self.assertEqual(values["battery_current"], -10.6)
        self.assertEqual(values["pv1_input_power"], 680)
        self.assertNotIn("pv2_input_power", values)
        self.assertNotIn("grid_voltage_l2", values)
        snapshot = await self.driver.async_capture_local_register_snapshot(
            self.transport, self.inverter, collector_pn="E50000200000000001"
        )
        battery = next(block for block in snapshot.blocks if block.plan.start == 256)
        self.assertEqual(battery.values, (93, 287, 65430))
        self.assertEqual(snapshot.failed_block_count, 2)  # PV2 and optional phases

    async def test_runtime_does_not_split_timeouts_or_malformed_parent(self) -> None:
        for error in (TimeoutError(), ModbusError("crc_error"),
                      ModbusError("unexpected_slave_id:0"), ModbusError("exception_code:3")):
            with self.subTest(error=str(error)):
                session = self.driver._session(self.transport, self.inverter.probe_target)
                original = session.read_registers
                calls = []

                async def read(start, count, *, function=3):
                    calls.append((start, count))
                    if (start, count) == (256, 18):
                        raise error
                    return await original(start, count, function=function)

                session.read_registers = read
                with patch.object(self.driver, "_session", return_value=session):
                    values = _full_values(await self.driver.async_read_values(self.transport, self.inverter))
                self.assertNotIn((256, 3), calls)
                self.assertNotIn("battery_voltage", values)
                self.assertEqual(values["output_power"], 1200)

    async def test_runtime_subread_timeout_stops_fallback_without_stale_battery(self) -> None:
        session = self.driver._session(self.transport, self.inverter.probe_target)
        original = session.read_registers
        calls = []

        async def read(start, count, *, function=3):
            calls.append((start, count))
            if (start, count) == (256, 3):
                raise TimeoutError()
            return await original(start, count, function=function)

        session.read_registers = read
        with patch.object(self.driver, "_session", return_value=session):
            values = _full_values(await self.driver.async_read_values(self.transport, self.inverter))
        self.assertIn((256, 3), calls)
        self.assertNotIn((263, 3), calls)
        self.assertNotIn("battery_voltage", values)
        self.assertEqual(values["output_power"], 1200)

    async def test_supported_parent_stays_one_read_and_has_no_cross_device_state(self) -> None:
        await self.driver.async_read_values(self.transport, self.inverter)
        other = _ReadOnlySrneTransport(_srne_registers(product_info="SR-EOV24"), self.inverter.probe_target)
        values = _full_values(await self.driver.async_read_values(other, self.inverter))
        self.assertNotIn((256, 3), other.requests)
        self.assertEqual(other.requests.count((256, 18)), 1)
        self.assertEqual(values["pv2_input_power"], 620)

    async def test_runtime_fallback_propagates_disconnect_and_cancellation(self) -> None:
        for error in (ConnectionError("gone"), asyncio.CancelledError()):
            with self.subTest(error=type(error).__name__):
                session = self.driver._session(self.transport, self.inverter.probe_target)
                original = session.read_registers
                calls = []

                async def read(start, count, *, function=3):
                    calls.append((start, count))
                    if (start, count) == (256, 3):
                        raise error
                    return await original(start, count, function=function)

                session.read_registers = read
                with patch.object(self.driver, "_session", return_value=session):
                    with self.assertRaises(type(error)):
                        await self.driver.async_read_values(self.transport, self.inverter)
                self.assertNotIn((263, 3), calls)
                self.assertNotIn((528, 18), calls)

    async def test_rejected_subrange_does_not_expand_the_probe(self) -> None:
        del self.transport._registers[257]
        evidence = await self.driver.async_capture_support_evidence(
            self.transport, self.inverter
        )
        diagnostics = evidence["dc_subrange_diagnostics"]
        self.assertEqual(diagnostics["status"], "completed")
        self.assertEqual(len(self.transport.requests), 10)
        self.assertEqual(
            diagnostics["range_failures"],
            [{"start": 256, "count": 3, "error": "exception_code:2"}],
        )
        self.assertEqual(len(diagnostics["captured_ranges"]), 4)

    async def test_export_preserves_parent_failure_and_subrange_evidence(self) -> None:
        evidence = await self.driver.async_capture_support_evidence(
            self.transport, self.inverter
        )
        fixture = build_support_fixture(
            evidence, inverter=self.inverter, collector_payload=None
        )
        with tempfile.TemporaryDirectory() as config_dir:
            exported = export_support_package(
                config_dir=Path(config_dir),
                entry_id="srne_test",
                entry_title="SRNE diagnostics",
                support_bundle={},
                raw_capture=evidence,
                fixture=fixture,
                anonymized_fixture=None,
            )
            with zipfile.ZipFile(exported.path) as archive:
                self.assertIsNone(archive.testzip())
                raw = json.loads(archive.read("raw_capture.json"))
                saved_fixture = json.loads(archive.read("fixture/raw_fixture.json"))
        self.assertEqual(raw["dc_subrange_diagnostics"], evidence["dc_subrange_diagnostics"])
        self.assertEqual(raw["range_failures"], evidence["range_failures"])
        self.assertEqual(saved_fixture["ranges"], evidence["fixture_ranges"])
        self.assertEqual(saved_fixture["probe_target"]["device_addr"], 1)

    async def test_no_subranges_after_success_or_non_address_failure(self) -> None:
        for failure in (
            None,
            ModbusError("request_timeout"),
            ModbusError("exception_code:3"),
            ModbusError("crc_mismatch"),
            OSError("offline"),
        ):
            with self.subTest(failure=failure):
                async def read(start, count):
                    if (start, count) == (256, 18) and failure is not None:
                        raise failure
                    return [0] * count

                session = type("Session", (), {"read_holding": AsyncMock(side_effect=read)})()
                with patch.object(self.driver, "_session", return_value=session):
                    evidence = await self.driver.async_capture_support_evidence(
                        self.transport, self.inverter
                    )
                self.assertNotIn("dc_subrange_diagnostics", evidence)
                self.assertEqual(session.read_holding.await_count, 5)

    async def test_extra_reads_stop_at_first_non_address_failure(self) -> None:
        for failure in (
            ModbusError("request_timeout"),
            ModbusError("exception_code:3"),
            ModbusError("crc_mismatch"),
            OSError("offline"),
        ):
            with self.subTest(failure=failure):
                async def read(start, count):
                    if (start, count) == (256, 18):
                        raise ModbusError("exception_code:2")
                    if (start, count) == (263, 3):
                        raise failure
                    return [0] * count

                session = type("Session", (), {"read_holding": AsyncMock(side_effect=read)})()
                with patch.object(self.driver, "_session", return_value=session):
                    evidence = await self.driver.async_capture_support_evidence(
                        self.transport, self.inverter
                    )
                diagnostics = evidence["dc_subrange_diagnostics"]
                self.assertEqual(diagnostics["status"], "stopped_on_error")
                self.assertEqual(session.read_holding.await_count, 7)
                self.assertEqual(len(evidence["captured_ranges"]), 4)
                self.assertEqual(len(diagnostics["captured_ranges"]), 1)
                self.assertEqual(diagnostics["range_failures"][0]["error"], str(failure))

    async def test_extra_read_budget_keeps_prior_successes(self) -> None:
        entered = asyncio.Event()
        cancelled = asyncio.Event()

        async def read(start, count):
            if (start, count) == (256, 18):
                raise ModbusError("exception_code:2")
            if (start, count) == (263, 3):
                entered.set()
                try:
                    await asyncio.Future()
                finally:
                    cancelled.set()
            return [0] * count

        session = type("Session", (), {"read_holding": AsyncMock(side_effect=read)})()
        with patch.object(self.driver, "_session", return_value=session), patch(
            "custom_components.eybond_local.drivers.srne._DC_DIAGNOSTIC_TIMEOUT", 0.01
        ):
            evidence = await self.driver.async_capture_support_evidence(
                self.transport, self.inverter
            )
        self.assertTrue(entered.is_set())
        self.assertTrue(cancelled.is_set())
        diagnostics = evidence["dc_subrange_diagnostics"]
        self.assertEqual(diagnostics["status"], "budget_exhausted")
        self.assertEqual(session.read_holding.await_count, 7)
        self.assertEqual(len(evidence["fixture_ranges"]), 5)
        self.assertEqual(diagnostics["range_failures"][0]["error"], "diagnostic_budget_exhausted")

    async def test_external_cancellation_is_not_a_partial_success(self) -> None:
        entered = asyncio.Event()

        async def read(start, count):
            if (start, count) == (256, 18):
                raise ModbusError("exception_code:2")
            if (start, count) == (256, 3):
                entered.set()
                await asyncio.Future()
            return [0] * count

        session = type("Session", (), {"read_holding": AsyncMock(side_effect=read)})()
        with patch.object(self.driver, "_session", return_value=session):
            task = asyncio.create_task(self.driver.async_capture_support_evidence(
                self.transport, self.inverter
            ))
            try:
                await asyncio.wait_for(entered.wait(), 1)
            finally:
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
        self.assertEqual(session.read_holding.await_count, 6)


if __name__ == "__main__":
    unittest.main()
