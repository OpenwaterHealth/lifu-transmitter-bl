#!/usr/bin/env python3
"""
get-version.py

Query the bootloader version from a downstream transmitter running in I2C DFU
mode (I2C_DFU_CMD_GETVERSION), then optionally issue a reset.

The device must already be in I2C DFU mode at slave address 0x42 (the default
I2C_DFU_SLAVE_ADDR).  An I2C master adapter accessible via smbus2 is required
(e.g. a Raspberry Pi I2C bus, CH341 USB-to-I2C, or any Linux /dev/i2c-N).

Usage examples:
    python get-version.py                       # bus 1, addr 0x42 (defaults)
    python get-version.py --bus 3 --addr 0x42
    python get-version.py --bus 1 --no-prompt   # print version and exit, no reboot prompt
"""

import argparse
import sys
import time

try:
    import smbus2
except ImportError:
    raise SystemExit(
        "Missing dependency 'smbus2'. Install with: python -m pip install smbus2"
    )

# ── Protocol constants (must match i2c_dfu_if.h) ─────────────────────────────

I2C_DFU_SLAVE_ADDR      = 0x42

CMD_GETVERSION          = 0x06
CMD_GETSTATUS           = 0x03
CMD_RESET               = 0x05

STATUS_OK               = 0x00
STATUS_BUSY             = 0x01
STATUS_ERROR            = 0x02
STATUS_BAD_ADDR         = 0x03
STATUS_FLASH_ERR        = 0x04

STATE_NAMES = {
    0x00: "IDLE",
    0x01: "DNBUSY",
    0x02: "DNLOAD_IDLE",
    0x03: "MANIFEST",
    0x04: "ERROR",
}

STATUS_NAMES = {
    STATUS_OK:          "OK",
    STATUS_BUSY:        "BUSY",
    STATUS_ERROR:       "ERROR",
    STATUS_BAD_ADDR:    "BAD_ADDR",
    STATUS_FLASH_ERR:   "FLASH_ERR",
}

VERSION_STR_MAX         = 32   # I2C_DFU_VERSION_STR_MAX
GETVERSION_READ_LEN     = 2 + VERSION_STR_MAX   # status + state + version string

BUSY_RETRY_DELAY_S      = 0.05
BUSY_MAX_RETRIES        = 20


# ── I2C helpers ───────────────────────────────────────────────────────────────

def _write_cmd(bus: smbus2.SMBus, addr: int, payload: bytes) -> None:
    """Send a write transaction (command byte + optional payload)."""
    msg = smbus2.i2c_msg.write(addr, list(payload))
    bus.i2c_rdwr(msg)


def _read_response(bus: smbus2.SMBus, addr: int, length: int) -> bytes:
    """Issue a read transaction and return the response bytes."""
    msg = smbus2.i2c_msg.read(addr, length)
    bus.i2c_rdwr(msg)
    return bytes(msg)


def _poll_until_ready(bus: smbus2.SMBus, addr: int) -> tuple[int, int]:
    """
    Send GETSTATUS repeatedly until the device is no longer BUSY.
    Returns (status, state) from the final response.
    """
    for _ in range(BUSY_MAX_RETRIES):
        _write_cmd(bus, addr, bytes([CMD_GETSTATUS]))
        resp = _read_response(bus, addr, 2)
        status, state = resp[0], resp[1]
        if status != STATUS_BUSY:
            return status, state
        time.sleep(BUSY_RETRY_DELAY_S)
    return status, state


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_get_version(bus: smbus2.SMBus, addr: int) -> str:
    """Send GETVERSION and return the version string."""
    _write_cmd(bus, addr, bytes([CMD_GETVERSION]))
    resp = _read_response(bus, addr, GETVERSION_READ_LEN)

    status = resp[0]
    state  = resp[1]
    ver_bytes = resp[2:]

    status_name = STATUS_NAMES.get(status, f"0x{status:02X}")
    state_name  = STATE_NAMES.get(state, f"0x{state:02X}")

    if status != STATUS_OK:
        raise RuntimeError(
            f"GETVERSION failed: status={status_name}, state={state_name}"
        )

    # Strip null padding
    version = ver_bytes.split(b"\x00")[0].decode("ascii", errors="replace")
    return version, state_name


def cmd_reset(bus: smbus2.SMBus, addr: int) -> None:
    """Send RESET.  The device will reboot after ACKing the command."""
    _write_cmd(bus, addr, bytes([CMD_RESET]))
    # Read the final status response — device resets shortly after ACK
    try:
        resp = _read_response(bus, addr, 2)
        status = resp[0]
        status_name = STATUS_NAMES.get(status, f"0x{status:02X}")
        if status != STATUS_OK:
            print(f"Warning: RESET response status={status_name}")
    except OSError:
        # Device may have reset before the read completes — this is expected
        pass


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Query I2C DFU bootloader version and optionally reset the device."
    )
    parser.add_argument(
        "--bus",
        type=int,
        default=1,
        metavar="N",
        help="I2C bus number (default: 1, i.e. /dev/i2c-1)",
    )
    parser.add_argument(
        "--addr",
        type=lambda s: int(s, 0),
        default=I2C_DFU_SLAVE_ADDR,
        metavar="ADDR",
        help=f"7-bit I2C slave address (default: 0x{I2C_DFU_SLAVE_ADDR:02X})",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Print version and exit without asking about reboot",
    )
    args = parser.parse_args()

    try:
        bus = smbus2.SMBus(args.bus)
    except FileNotFoundError:
        raise SystemExit(f"I2C bus {args.bus} not found (is the adapter connected?)")
    except PermissionError:
        raise SystemExit(
            f"Permission denied opening I2C bus {args.bus}. "
            "Try running with sudo or add your user to the 'i2c' group."
        )

    with bus:
        # ── Get version ───────────────────────────────────────────────────
        try:
            version, state = cmd_get_version(bus, args.addr)
        except OSError as e:
            raise SystemExit(
                f"I2C error communicating with device at 0x{args.addr:02X} "
                f"on bus {args.bus}: {e}"
            )
        except RuntimeError as e:
            raise SystemExit(str(e))

        print(f"Bootloader version : {version}")
        print(f"DFU state          : {state}")

        if args.no_prompt:
            return

        # ── Ask about reboot ──────────────────────────────────────────────
        print()
        try:
            answer = input("Reboot device now? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if answer in ("y", "yes"):
            print("Sending reset command...")
            try:
                cmd_reset(bus, args.addr)
            except OSError:
                # Bus error after reset is normal — device disconnected
                pass
            print("Reset issued. Device is rebooting.")
        else:
            print("Device remains in DFU mode.")


if __name__ == "__main__":
    main()
