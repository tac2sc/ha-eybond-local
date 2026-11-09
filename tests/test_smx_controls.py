"""Exact-model SMX-II control regression tests, with no live inverter writes."""

from __future__ import annotations

from dataclasses import replace
import unittest

from custom_components.eybond_local.control_policy import (
    can_expose_capability,
    controls_enabled,
)
from custom_components.eybond_local.drivers.capability_codec import (
    CapabilityPostWriteReadError,
)
from custom_components.eybond_local.drivers.srne import SrneModbusDriver
from custom_components.eybond_local.fixtures.transport import FixtureTransport
from custom_components.eybond_local.metadata.register_schema_loader import load_register_schema
from custom_components.eybond_local.models import ProbeTarget
from custom_components.eybond_local.payload.modbus import ModbusError, crc16_modbus


TARGET = ProbeTarget(devcode=1, collector_addr=255, device_addr=1)
OWNER = "SR-2206260036-300917"
SCHEMA = "srne_modbus/smx_ii_24v.json"


class _WriteTraceTransport(FixtureTransport):
    def __init__(self, *, identity=OWNER):
        schema = load_register_schema(SCHEMA)
        registers = {
            block.start + offset: 0
            for block in schema.blocks
            for offset in range(block.count)
        }
        registers.update({
            53 + offset: ord(character)
            for offset, character in enumerate(identity[:20].ljust(20))
        })
        registers[57088] = 0b1010  # Experimental power bitmask.
        registers[0x0211] = 0  # Legacy default password status.
        super().__init__(registers=registers, command_responses=None, probe_target=TARGET)
        self.requests: list[tuple[int, int, int]] = []
        self.deny_once_at: int | None = None
        self.ignore_write_at: int | None = None
        self.fail_readback_at: int | None = None
        self._write_started = False

    def _handle_read_holding(self, payload: bytes) -> bytes:
        address = int.from_bytes(payload[2:4], "big")
        if self._write_started and self.fail_readback_at == address:
            return self._exception(0x03, 0x02)
        return super()._handle_read_holding(payload)

    def _handle_write_single(self, payload: bytes) -> bytes:
        address = int.from_bytes(payload[2:4], "big")
        word = int.from_bytes(payload[4:6], "big")
        self.requests.append((6, address, word))
        self._write_started = True
        if self.deny_once_at == address:
            self.deny_once_at = None
            return self._exception(0x06, 0x0B)
        original = self._registers.get(address)
        reply = super()._handle_write_single(payload)
        if self.ignore_write_at == address:
            self._registers[address] = original if original is not None else 0
        return reply

    def _handle_write_multiple(self, payload: bytes) -> bytes:
        address = int.from_bytes(payload[2:4], "big")
        word = int.from_bytes(payload[7:9], "big")
        self.requests.append((16, address, word))
        self._write_started = True
        return super()._handle_write_multiple(payload)

    @staticmethod
    def _exception(function: int, code: int) -> bytes:
        frame = bytes((TARGET.device_addr, function | 0x80, code))
        return frame + crc16_modbus(frame).to_bytes(2, "little")


class SmxControlsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.driver = SrneModbusDriver()
        self.transport = _WriteTraceTransport()
        self.inverter = await self.driver.async_probe(self.transport, TARGET)
        assert self.inverter is not None

    async def test_legacy_profile_has_full_controls_but_only_two_tested(self):
        capabilities = self.inverter.capabilities
        self.assertEqual(len(capabilities), 36)
        self.assertEqual(
            {c.key for c in capabilities if c.tested},
            {"output_priority", "charger_source_priority"},
        )
        self.assertTrue(all(c.requires_confirm for c in capabilities))
        # Full Control must expose the complete restored legacy settings set
        # without requiring 34 per-entity enable actions. This only controls
        # the HA entity registry default; no Modbus write runs on startup.
        self.assertTrue(all(c.enabled_default for c in capabilities))
        self.assertFalse(next(c for c in capabilities if c.key == "battery_type").tested)
        self.assertTrue(next(c for c in capabilities if c.key == "inverter_power").requires_confirm)

    async def test_existing_control_policy_auto_full_and_read_only(self):
        capabilities = self.inverter.capabilities
        self.assertEqual(sum(can_expose_capability(
            c, control_mode="auto", detection_confidence="high"
        ) for c in capabilities), 2)
        self.assertEqual(sum(can_expose_capability(
            c, control_mode="full", detection_confidence="high"
        ) for c in capabilities), 36)
        self.assertFalse(any(can_expose_capability(
            c, control_mode="read_only", detection_confidence="high"
        ) for c in capabilities))
        self.assertTrue(controls_enabled(
            control_mode="full", write_capability_count=len(capabilities)
        ))

    async def test_exact_device_writes_fc06_and_confirms_scaled_readback(self):
        state = {}
        result = await self.driver.async_write_capability(
            self.transport, self.inverter, "max_ac_charge_current", 60, runtime_state=state
        )
        self.assertEqual(result, 60.0)
        self.assertEqual(self.transport._registers[0xE205], 600)
        self.assertEqual(self.transport.requests, [(6, 0xE205, 600)])
        from custom_components.eybond_local.drivers.write_confirmation import (
            write_confirmation_diagnostics,
        )
        confirmation = write_confirmation_diagnostics(state)
        self.assertIn("runtime_capability_write_confirmation", confirmation)
        self.assertEqual(
            confirmation["runtime_capability_write_confirmation"]["immediate_status"],
            "matched",
        )

    async def test_legacy_enums_and_24v_voltage_scaling(self):
        self.assertEqual(
            await self.driver.async_write_capability(
                self.transport, self.inverter, "output_priority", "Utility First"
            ),
            "Utility First",
        )
        self.assertEqual(self.transport._registers[0xE204], 1)
        self.assertEqual(
            await self.driver.async_write_capability(
                self.transport, self.inverter, "battery_float_voltage", 27.6
            ),
            27.6,
        )
        self.assertEqual(self.transport._registers[0xE009], 138)

    async def test_generic_and_nearby_models_never_write(self):
        for identity in ("SR-EOV24", "SR-2206260036-300918"):
            transport = _WriteTraceTransport(identity=identity)
            inverter = await self.driver.async_probe(transport, TARGET)
            assert inverter is not None
            self.assertFalse(inverter.capabilities)
            with self.assertRaisesRegex(ValueError, "unsupported_capability"):
                await self.driver.async_write_capability(
                    transport, inverter, "output_priority", 1
                )
            self.assertEqual(transport.requests, [])

    async def test_manipulated_identity_cannot_reuse_capability_profile(self):
        evidence = self.inverter.details["catalog_detection"]
        for bad in (
            replace(self.inverter, profile_name=""),
            replace(self.inverter, variant_key="srne_family"),
            replace(self.inverter, register_schema_name="srne_modbus/base.json"),
            replace(self.inverter, details={
                **self.inverter.details, "product_info": "SR-2206260036-300918",
            }),
            replace(self.inverter, details={
                **self.inverter.details, "catalog_detection": {
                    **evidence, "resolution": "family",
                },
            }),
        ):
            with self.assertRaisesRegex(ValueError, "unsupported_capability"):
                await self.driver.async_write_capability(
                    self.transport, bad, "output_priority", 1
                )
        self.assertEqual(self.transport.requests, [])

    async def test_unknown_keys_and_invalid_values_fail_before_writes(self):
        for key, value in (
            ("injected_control", 1),
            ("max_ac_charge_current", 999),
            ("battery_float_voltage", 50),
            ("output_priority", "Unknown"),
        ):
            with self.assertRaises(ValueError):
                await self.driver.async_write_capability(
                    self.transport, self.inverter, key, value
                )
        self.assertEqual(self.transport.requests, [])

    async def test_default_password_retry_only_after_explicit_denial(self):
        self.transport.deny_once_at = 0xE204
        result = await self.driver.async_write_capability(
            self.transport, self.inverter, "output_priority", "Utility First"
        )
        self.assertEqual(result, "Utility First")
        self.assertEqual(self.transport.requests, [
            (6, 0xE204, 1),
            (16, 0xE203, 0),
            (6, 0xE204, 1),
        ])

    async def test_nondefault_password_status_never_unlocks(self):
        self.transport._registers[0x0211] = 1
        self.transport.deny_once_at = 0xE204
        with self.assertRaises(ModbusError):
            await self.driver.async_write_capability(
                self.transport, self.inverter, "output_priority", 1
            )
        self.assertEqual(self.transport.requests, [(6, 0xE204, 1)])
        self.assertNotIn(0xE203, self.transport._registers)

    async def test_single_fc16_masked_write_preserves_other_bits(self):
        result = await self.driver.async_write_capability(
            self.transport, self.inverter, "inverter_power", True
        )
        self.assertTrue(result)
        self.assertEqual(self.transport._registers[57088], 0b1011)
        self.assertEqual(self.transport.requests, [(16, 57088, 0b1011)])

    async def test_write_ack_without_applied_value_is_error(self):
        self.transport.ignore_write_at = 0xE205
        state = {}
        with self.assertRaisesRegex(RuntimeError, "write_readback_mismatch"):
            await self.driver.async_write_capability(
                self.transport, self.inverter, "max_ac_charge_current", 60,
                runtime_state=state,
            )
        self.assertEqual(self.transport._registers[0xE205], 0)

    async def test_postwrite_read_error_does_not_imply_success(self):
        self.transport.fail_readback_at = 0xE205
        state = {}
        with self.assertRaises(CapabilityPostWriteReadError):
            await self.driver.async_write_capability(
                self.transport, self.inverter, "max_ac_charge_current", 60,
                runtime_state=state,
            )
        self.assertEqual(self.transport.requests, [(6, 0xE205, 600)])
        from custom_components.eybond_local.drivers.write_confirmation import (
            write_confirmation_diagnostics,
        )
        self.assertEqual(
            write_confirmation_diagnostics(state)[
                "runtime_capability_write_confirmation"
            ]["immediate_status"],
            "unavailable",
        )

    async def test_slow_poll_confirms_write_without_extra_register_reads(self):
        from custom_components.eybond_local.drivers.write_confirmation import (
            write_confirmation_diagnostics,
        )

        state = {}
        await self.driver.async_read_values(
            self.transport, self.inverter, runtime_state=state, poll_interval=5.0
        )
        await self.driver.async_write_capability(
            self.transport, self.inverter, "max_ac_charge_current", 60,
            runtime_state=state,
        )
        self.transport.requests.clear()
        await self.driver.async_read_values(
            self.transport, self.inverter, runtime_state=state, poll_interval=5.0
        )
        trace = write_confirmation_diagnostics(state)[
            "runtime_capability_write_confirmation"
        ]
        self.assertEqual(trace["first_full_poll_status"], "pending")
        self.assertEqual(self.transport.requests, [])  # Polling is read-only.

        for _ in range(20):
            await self.driver.async_read_values(
                self.transport, self.inverter, runtime_state=state, poll_interval=5.0
            )
        trace = write_confirmation_diagnostics(state)[
            "runtime_capability_write_confirmation"
        ]
        self.assertEqual(trace["first_full_poll_status"], "matched")
        self.assertEqual(trace["convergence"], "requested_value_observed")


if __name__ == "__main__":
    unittest.main()
