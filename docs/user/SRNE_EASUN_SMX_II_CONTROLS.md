# SRNE / EASUN SMX-II Monitoring and Controls

The `srne_modbus` driver supports the Modbus map used by the EASUN iSolar
SMX-II 3.6 kW family at 9600 baud, 8 data bits, no parity, one stop bit, and
slave address 1.

## Identity boundary

Generic SRNE detection remains read-only and uses `srne_modbus/base.json`.
The SMX-II 24 V controls use a separate profile and
`srne_modbus/smx_ii_24v.json`; they are never the driver's default.
Automatic selection requires an exact, source-backed model fingerprint.
The owner supplied a nameplate confirming the 24 V model and serial
`SR-2206260036-300917-B02`. The current detection entry accepts only its exact
20-character Modbus product-info value `SR-2206260036-300917`. This identifies
one physical unit, not every SMX-II model or any serial-number prefix.
Other units require independent identification and remain read-only.
A generic SRNE match or a manually edited HA label cannot enable the profile.

The 20-33 V battery limits and 0.2 V configuration scale must not be applied
to 12 V, 48 V or unidentified SRNE devices. A live battery voltage reading
is not proof of nominal voltage or model identity.

The schema reads the stable scalar values documented by two independent
community implementations. This includes firmware identity, battery and PV
telemetry, inverter and phase telemetry, temperatures, charging state,
configuration values, daily and lifetime energy counters, and runtime totals.
The register ranges are intentionally split around undocumented holes because
some SMX-II firmware rejects one wide `256..273` request while answering the
documented sub-ranges.

Configuration values are also retained as disabled diagnostic sensors. They
can therefore be inspected without enabling write access.

The 24 V SMX-II stores battery-voltage thresholds in 0.2 V wire increments,
unlike live battery voltage, which uses 0.1 V increments. The schema applies
that distinction in both directions: for example, register value `142` is
shown as `28.4 V`, and a requested `28.8 V` setting is written as `144`.

## Control exposure

Output priority and charger-source priority have direct example-level evidence
and are enabled by default when the integration's normal control policy allows
writes. The remaining settings are marked conditional and disabled by default
until they receive broader hardware confirmation.

To test a conditional setting:

1. Open **Settings -> Devices & Services -> EyeBond Local -> Configure**.
2. Set **Control mode** to **Full Control**.
3. Open the inverter entity list and enable only the setting being tested.
4. Record the current value and change it by the smallest safe amount.
5. Confirm the result on the inverter display and create a Support Archive.

Battery thresholds and charging currents must match the battery manufacturer's
requirements. Enabling a control only makes it available; it does not make a
particular value safe for the installation.

## Write confirmation

Normal settings use Modbus function 06. The community-documented inverter
power bit uses function 16 and a read-modify-write operation so unrelated bits
in the shared register are preserved.

After every successful wire acknowledgement, the driver immediately reads the
exact target register and records whether the raw value matches. The mandatory
normal refresh then reads the setting again and records whether it converged.
A write acknowledgement alone is never projected as the current value.
For scaled settings, full-poll confirmation compares register units to avoid
floating-point differences such as `28.4` versus `28.400000000000002`.

## Default user authorization

Some SRNE firmware uses exception `0x0B` to deny writes to protected settings.
For this SMX-II profile, a rejected single-register FC06 setting write triggers
one read of password status `0x0211`. Only when it is zero does the driver
submit the documented default user password to password-input register
`0xE203` using FC16, then repeat the exact setting write once. The normal
immediate and full-poll readback checks still apply. Password-change register
`0xE202` is never written.

No authorization is attempted for actions, FC16 controls, multiword settings,
timeouts, other errors or nonzero password status. A repeated rejection remains
an error: some OEM firmware permanently locks individual settings. This path
has automated protocol tests; successful authorization on the user's firmware
still requires a hardware check. Do not use it as a custom-password mechanism.

The [SRNE V1.7 register table](https://github.com/RAR/esphome-srne-inverter/blob/main/srne-hybrid-solar-inverter-modbus-protocol-v1-7.pdf)
documents password input separately from password changes. The SRNE-specific
`0x0B` interpretation is also documented in
[srne_ble_modbus](https://github.com/krimsonkla/srne_ble_modbus/blob/main/docs/ARCHITECTURE.md).

## Deliberate exclusions

The profile does not expose password registers, customer identifiers, reserved
words, undocumented function-enable bitfields, RS485 addressing, parallel-mode
addressing, or BMS protocol selection as writable controls. These fields are
credentials, installation topology, or insufficiently documented and are not
appropriate as ordinary Home Assistant controls.

The primary register evidence is:

- [jsayol/easun-modbus](https://github.com/jsayol/easun-modbus), tested by its
  author with an EASUN iSolar SMX-II 3.6 kW over USB;
- [vladyspavlov SMX-II ESPHome map](https://gist.github.com/vladyspavlov/d7819b255a81ea45659e63a1a92a66b2),
  an independent SRNE/EASUN register configuration.
