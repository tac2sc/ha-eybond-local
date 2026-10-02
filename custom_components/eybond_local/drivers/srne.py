"""SRNE Modbus RTU driver with a separately identified SMX-II profile."""

from __future__ import annotations

import logging
from typing import Any

from ..metadata.compiled_detection_catalog import load_compiled_detection_catalog
from ..metadata.detection_decision_tree import evaluate_detection_decision_tree_static
from ..metadata.profile_loader import load_driver_profile
from ..metadata.register_schema_loader import load_register_schema
from ..models import DetectedInverter, ProbeTarget
from ..payload.modbus import ModbusError, ModbusSession
from ..payload.register_decode import decode_ascii_low_bytes, read_spec_set_values
from ..poll_policy import PollPolicy
from .base import InverterDriver
from .capability_codec import (
    CapabilityPreWriteReadError,
    decode_capability_value,
    encode_capability_words,
    find_capability,
    merge_capability_register_word,
)
from .local_register_evidence import (
    LocalRegisterReadPlan,
    LocalRegisterSnapshot,
    async_capture_modbus_snapshot,
)
from .read_result import DriverReadMode, DriverReadResult
from .support_diagnostics import capture_support_reads
from .modbus_write_error import ModbusWriteErrorMixin
from .write_confirmation import (
    load_write_confirmation,
    start_write_confirmation,
    store_write_confirmation,
    write_confirmation_diagnostics,
)


# SRNE Modbus V2.07, P01 DC Data Area (addresses in that table are hexadecimal).
# Documented short reads after an explicit rejection of the 0x0100/18 block.
# In particular, do not cross the optional/new fields or reserved 0x010D again.
_DC_DIAGNOSTIC_RANGES = (
    (0x0100, 3, "battery"),
    (0x0107, 3, "pv1"),
    (0x010B, 1, "charge_state"),
    (0x010E, 1, "charge_power"),
    (0x010F, 3, "pv2"),
)
_DC_DIAGNOSTIC_TIMEOUT = 15.0

_LOGGER = logging.getLogger(__name__)


class SrneModbusDriver(ModbusWriteErrorMixin, InverterDriver):
    """Read-only SRNE family; SMX-II controls require exact catalog identity."""

    key = "srne_modbus"
    poll_policy = PollPolicy(min_auto_interval=5.0, max_auto_interval=90.0)
    name = "SRNE / Modbus"

    @property
    def probe_timeout(self) -> float:
        return load_compiled_detection_catalog().protocols[self.key].probe_timeout

    @property
    def probe_targets(self) -> tuple[ProbeTarget, ...]:
        return tuple(
            ProbeTarget(
                devcode=devcode,
                collector_addr=collector_addr,
                device_addr=device_addr,
            )
            for devcode, collector_addr, device_addr
            in load_compiled_detection_catalog().protocols[self.key].probe_targets
        )

    @property
    def register_schema_name(self) -> str:
        return _srne_default_schema_name()

    @property
    def profile_name(self) -> str:
        return _srne_default_surface().profile_name

    @property
    def measurements(self):
        schema = self.register_schema_metadata
        return schema.measurement_descriptions if schema is not None else ()

    @property
    def capability_groups(self):
        profile = self.profile_metadata
        return profile.groups if profile is not None else ()

    @property
    def write_capabilities(self):
        profile = self.profile_metadata
        return profile.capabilities if profile is not None else ()

    async def async_probe(self, transport, target: ProbeTarget) -> DetectedInverter | None:
        schema_name = self.register_schema_name
        schema = load_register_schema(schema_name)
        session = self._session(transport, target)
        try:
            product_block = schema.block("serial")
            product_words = await session.read_holding(
                product_block.start,
                product_block.count,
            )
        except Exception:
            return None

        product_info = _decode_product_info(product_words)
        if not _looks_like_srne_product_info(product_info):
            return None

        catalog = load_compiled_detection_catalog()
        evidence = {
            "identity.product_info": product_info,
            "protocol.protocol_id": "SRNE_MODBUS",
        }
        evaluation = evaluate_detection_decision_tree_static(catalog.decision_trees[self.key], evidence)
        resolution = catalog.resolution_for_candidates(
            protocol_key=self.key,
            candidate_keys=evaluation.candidate_keys if evaluation.status == "resolved" else (),
            evidence=evidence,
        )
        # A broad SRNE marker proves only the read-only family. Model-specific
        # battery scaling and limits require an exact, source-backed identity.
        if resolution.resolution != "exact":
            resolution = catalog.resolve_family(protocol_key=self.key, evidence=evidence)
        if not resolution.surface_key:
            return None
        surface = catalog.surfaces[resolution.surface_key]
        profile = load_driver_profile(surface.profile_name) if surface.profile_name else None
        details = {
            "product_info": product_info,
            "protocol_id": "SRNE_MODBUS",
            "catalog_detection": {
                "resolution": resolution.resolution,
                "surface_key": surface.key,
                "confidence": resolution.confidence,
                "candidate_keys": list(resolution.candidate_keys),
                "catalog_version": resolution.catalog_version,
                "descriptor_revisions": list(resolution.descriptor_revisions),
                "evidence_fingerprint": resolution.evidence_fingerprint,
                "evidence": evidence,
                "decision_path": list(resolution.decision_path),
            },
        }
        return DetectedInverter(
            driver_key=self.key,
            protocol_family="srne_modbus",
            model_name=f"SRNE {product_info}",
            serial_number="",
            probe_target=target,
            variant_key=surface.variant_key,
            details=details,
            profile_name=surface.profile_name,
            register_schema_name=surface.register_schema_name,
            capability_groups=tuple(profile.groups) if profile is not None else (),
            capabilities=tuple(profile.capabilities) if profile is not None else (),
            capability_presets=tuple(profile.presets) if profile is not None else (),
        )

    async def async_read_values(
        self,
        transport,
        inverter: DetectedInverter,
        *,
        runtime_state: dict[str, Any] | None = None,
        poll_interval: float | None = None,
        now_monotonic: float | None = None,
    ) -> DriverReadResult:
        schema = load_register_schema(
            inverter.register_schema_name or self.register_schema_name
        )
        session = self._session(transport, inverter.probe_target)
        values = await read_spec_set_values(
            session,
            schema,
            ascii_style="printable",
            illegal_address_fallbacks={
                (3, 0x0100, 18): tuple((start, count) for start, count, _ in _DC_DIAGNOSTIC_RANGES)
            },
        )
        diagnostics = _observe_capability_write_full_poll(
            runtime_state,
            inverter.capabilities,
            values,
        )
        return DriverReadResult(
            values=values,
            mode=DriverReadMode.FULL,
            diagnostics=diagnostics,
        )

    async def async_write_capability(
        self,
        transport,
        inverter: DetectedInverter,
        capability_key: str,
        value: Any,
        *,
        runtime_state: dict[str, Any] | None = None,
    ) -> Any:
        capability = find_capability(
            capability_key,
            inverter.capabilities,
        )
        raw_words = encode_capability_words(capability, value)
        native_value = decode_capability_value(capability, raw_words)
        session = self._session(transport, inverter.probe_target)

        if capability.bitmask:
            try:
                current = await session.read_holding(capability.register, 1)
            except ModbusError as exc:
                raise CapabilityPreWriteReadError(
                    f"bitmask_pre_write_read_failed:{capability.key}:{exc}"
                ) from exc
            if not current:
                raise CapabilityPreWriteReadError(
                    f"bitmask_pre_write_read_empty:{capability.key}"
                )
            wire_words = [
                merge_capability_register_word(
                    capability,
                    current_word=int(current[0]),
                    encoded_word=int(raw_words[0]),
                )
            ]
        else:
            wire_words = [int(word) for word in raw_words]

        if capability.write_function == 6:
            for offset, word in enumerate(wire_words):
                try:
                    await session.write_single_holding(capability.register + offset, word)
                except ModbusError as exc:
                    # SRNE uses 0x0B for write permission denial. An explicit
                    # rejection is safe to retry once after user authorization;
                    # timeouts, actions and partly written multiword values are not.
                    if (
                        str(exc) != "exception_code:11"
                        or capability.value_kind == "action"
                        or not 0xE000 <= capability.register <= 0xE2FF
                        or len(wire_words) != 1
                        or inverter.profile_name != "srne_modbus/smx_ii.json"
                    ):
                        raise
                    password_status = await session.read_holding(0x0211, 1)
                    if password_status != [0]:
                        _LOGGER.warning(
                            "SRNE denied write to 0x%04X; default user authorization "
                            "was skipped because password status is not zero",
                            capability.register,
                        )
                        raise
                    # 0xE203 is password INPUT; 0xE202 changes the password and
                    # must never be touched here. Zero is the documented default.
                    await session.write_holding(0xE203, [0])
                    _LOGGER.info(
                        "SRNE accepted default user authorization; retrying "
                        "setting register 0x%04X once",
                        capability.register,
                    )
                    await session.write_single_holding(capability.register, word)
        else:
            await session.write_holding(capability.register, wire_words)

        trace = start_write_confirmation(
            runtime_state,
            capability_key=capability.key,
            value_key=capability.value_key,
            requested_value=value,
            expected_value=native_value,
            requested_words=tuple(int(word) for word in raw_words),
        )
        try:
            observed_wire_words = tuple(
                int(word)
                for word in await session.read_holding(
                    capability.register,
                    capability.word_count,
                )
            )
            observed_words = _comparable_capability_words(
                capability,
                observed_wire_words,
            )
            observed_value = decode_capability_value(capability, list(observed_words))
            trace = trace.with_immediate_observation(
                value=observed_value,
                words=observed_words,
                matched=(observed_words == trace.requested_words),
            )
        except Exception as exc:  # the mandatory coordinator refresh may still confirm
            trace = trace.with_immediate_unavailable(error=exc)
        store_write_confirmation(runtime_state, trace)
        return native_value

    async def async_capture_support_evidence(
        self,
        transport,
        inverter: DetectedInverter,
    ) -> dict[str, Any]:
        schema = load_register_schema(
            inverter.register_schema_name or self.register_schema_name
        )
        session = self._session(transport, inverter.probe_target)
        captured_ranges: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        needs_dc_diagnostics = False
        for block in schema.blocks:
            try:
                values = await session.read_holding(block.start, block.count)
            except Exception as exc:
                if (block.start, block.count) == (0x0100, 18) and _is_address_rejection(exc):
                    needs_dc_diagnostics = True
                failures.append(
                    {
                        "start": block.start,
                        "count": block.count,
                        "error": str(exc),
                    }
                )
                continue
            captured_ranges.append(
                {
                    "start": block.start,
                    "count": block.count,
                    "words": list(values),
                }
            )
        evidence = {
            "capture_kind": "srne_modbus_register_dump",
            "driver_key": self.key,
            "model_name": inverter.model_name,
            "serial_number": inverter.serial_number,
            "capture_notes": [
                "SRNE/EASUN SMX-II support expects Modbus RTU at 9600 8N1, slave address 1.",
                "Writes use the profile-declared Modbus function and are followed by an exact-register read-back."
            ],
            "planned_ranges": [
                {"start": block.start, "count": block.count}
                for block in schema.blocks
            ],
            "captured_ranges": captured_ranges,
            "range_failures": failures,
            "fixture_ranges": [
                {
                    "start": item["start"],
                    "count": item["count"],
                    "values": list(item["words"]),
                }
                for item in captured_ranges
            ],
        }
        # Finish the ordinary evidence first, so extra diagnostics cannot consume
        # its budget. Keep the rejected parent and successful subreads separate.
        if needs_dc_diagnostics:
            diagnostics = await _capture_dc_subranges(session)
            evidence["dc_subrange_diagnostics"] = diagnostics
            evidence["fixture_ranges"].extend(
                {
                    "start": item["start"],
                    "count": item["count"],
                    "values": list(item["words"]),
                }
                for item in diagnostics["captured_ranges"]
            )
        return evidence

    def local_register_read_plans(
        self, inverter: DetectedInverter
    ) -> tuple[LocalRegisterReadPlan, ...]:
        schema = load_register_schema(
            inverter.register_schema_name or self.register_schema_name
        )
        # Bounded background evidence uses the same documented DC groups, not
        # the unsupported parent or zero-filled holes. Ordinary polling still
        # prefers the compact parent when the device accepts it.
        plans = []
        for block in schema.blocks:
            ranges = (
                tuple((start, count) for start, count, _ in _DC_DIAGNOSTIC_RANGES)
                if (block.start, block.count) == (0x0100, 18)
                else ((block.start, block.count),)
            )
            plans.extend(
                LocalRegisterReadPlan.for_target(
                    inverter.probe_target, function=3, start=start, count=count
                )
                for start, count in ranges
            )
        return tuple(plans)

    async def async_capture_local_register_snapshot(
        self, transport, inverter: DetectedInverter, *, collector_pn: str
    ) -> LocalRegisterSnapshot:
        return await async_capture_modbus_snapshot(
            collector_pn=collector_pn,
            driver_key=self.key,
            plans=self.local_register_read_plans(inverter),
            session_factory=lambda target: self._session(transport, target),
        )

    @staticmethod
    def _session(transport, target: ProbeTarget) -> ModbusSession:
        return ModbusSession(
            transport,
            route=target.link_route,
            slave_id=target.payload_address,
        )


def _is_address_rejection(error: Exception) -> bool:
    return isinstance(error, ModbusError) and str(error) == "exception_code:2"


async def _capture_dc_subranges(session: ModbusSession) -> dict[str, Any]:
    """Try at most five documented DC groups with one shared deadline.

    Preserve normal Modbus retry semantics, but stop this diagnostic sequence on
    any error except an explicit illegal-address response. No recursive splitting,
    phase probing, capability writes or mutation of the runtime schema occurs.
    """

    result = await capture_support_reads(
        session,
        _DC_DIAGNOSTIC_RANGES,
        timeout_seconds=_DC_DIAGNOSTIC_TIMEOUT,
        source="SRNE Modbus V2.07, P01 DC Data Area",
        purpose="support_only_rejected_dc_block",
    )
    result["trigger_range"] = {"start": 0x0100, "count": 18}
    return result


def _srne_default_schema_name() -> str:
    return _srne_default_surface().register_schema_name


def _srne_default_surface():
    for surface in load_compiled_detection_catalog().surfaces.values():
        if surface.driver_key == SrneModbusDriver.key and surface.default_for_driver:
            return surface
    raise LookupError("srne_default_surface_not_found")


def _comparable_capability_words(capability, words: tuple[int, ...]) -> tuple[int, ...]:
    if not capability.bitmask:
        return words
    if len(words) != 1:
        raise ValueError(f"unexpected_word_length:{capability.key}:{len(words)}")
    return ((int(words[0]) & capability.bitmask) >> capability.bitmask_shift,)


def _observe_capability_write_full_poll(
    runtime_state: dict[str, Any] | None,
    capabilities,
    values: dict[str, Any],
) -> dict[str, Any]:
    trace = load_write_confirmation(runtime_state)
    if trace is None:
        return {}
    capability = next(
        (item for item in capabilities if item.key == trace.capability_key),
        None,
    )
    if capability is None or trace.value_key not in values:
        trace = trace.with_poll_observation(value=None, matched=None)
    else:
        observed_value = values[trace.value_key]
        if capability.value_kind == "scaled_u16":
            # Compare register units, not float products such as 142 * 0.2,
            # which need not equal the rounded telemetry value 28.4 exactly.
            try:
                matched = (
                    tuple(encode_capability_words(capability, observed_value))
                    == trace.requested_words
                )
            except (TypeError, ValueError):
                matched = False
        else:
            matched = observed_value == trace.expected_value
        trace = trace.with_poll_observation(
            value=observed_value,
            matched=matched,
        )
    store_write_confirmation(runtime_state, trace)
    return write_confirmation_diagnostics(runtime_state)


def _looks_like_srne_product_info(product_info: str) -> bool:
    return len(product_info) >= 3 and "SR" in product_info.upper()


def _decode_product_info(words: list[int]) -> str:
    return decode_ascii_low_bytes(words)
