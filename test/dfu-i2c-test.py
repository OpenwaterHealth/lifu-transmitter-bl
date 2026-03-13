import argparse
import hashlib
import hmac
import struct
import sys
import time

try:
	from smbus2 import SMBus, i2c_msg
except ImportError:
	SMBus = None
	i2c_msg = None

try:
	from cryptography.hazmat.primitives import hashes, serialization
	from cryptography.hazmat.primitives.asymmetric import ec
	from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature, Prehashed
except ImportError:
	serialization = None
	ec = None
	decode_dss_signature = None
	encode_dss_signature = None
	Prehashed = None


# ---------------------------------------------------------------------------
# Memory layout defaults — must match memory_map.h
# ---------------------------------------------------------------------------

APP_ADDRESS_DEFAULT  = 0x08010000
META_ADDRESS_DEFAULT = 0x0800F800

# ---------------------------------------------------------------------------
# Metadata / package constants — identical to dfu-test.py
# ---------------------------------------------------------------------------

META_MAGIC                   = 0x314D4657  # 'WFM1'
META_VERSION                 = 3
META_FLAGS_SIGNATURE_REQUIRED = 1
SIGNATURE_SIZE_BYTES          = 64
TRUST_TAG_SIZE_BYTES          = 32
META_STRUCT_WITHOUT_CRC       = "<IHHIIII64s32s"
META_STRUCT_FULL              = "<IHHIIII64s32sI"
DEFAULT_RELOCATE_WINDOW       = 190 * 1024

SIGNED_PKG_MAGIC       = 0x314B4750  # 'PGK1'
SIGNED_PKG_VERSION     = 1
SIGNED_PKG_HEADER_NOCRC = "<IHHIIIII"
SIGNED_PKG_HEADER_FULL  = "<IHHIIIIII"

# ---------------------------------------------------------------------------
# I2C DFU protocol constants — must match i2c_dfu_if.h
# ---------------------------------------------------------------------------

I2C_DFU_SLAVE_ADDR_DEFAULT = 0x72

# Commands (byte[0] of every write transaction)
CMD_DNLOAD     = 0x01
CMD_ERASE      = 0x02
CMD_GETSTATUS  = 0x03
CMD_MANIFEST   = 0x04
CMD_RESET      = 0x05
CMD_GETVERSION = 0x06

# Status codes (byte[0] of every read response)
STATUS_OK        = 0x00
STATUS_BUSY      = 0x01
STATUS_ERROR     = 0x02
STATUS_BAD_ADDR  = 0x03
STATUS_FLASH_ERR = 0x04

STATUS_NAMES = {
	STATUS_OK:        "OK",
	STATUS_BUSY:      "BUSY",
	STATUS_ERROR:     "ERROR",
	STATUS_BAD_ADDR:  "BAD_ADDR",
	STATUS_FLASH_ERR: "FLASH_ERR",
}

# DFU state codes (byte[1] of every read response)
STATE_IDLE        = 0x00
STATE_DNBUSY      = 0x01
STATE_DNLOAD_IDLE = 0x02
STATE_MANIFEST    = 0x03
STATE_ERROR       = 0x04

STATE_NAMES = {
	STATE_IDLE:        "IDLE",
	STATE_DNBUSY:      "DNBUSY",
	STATE_DNLOAD_IDLE: "DNLOAD_IDLE",
	STATE_MANIFEST:    "MANIFEST",
	STATE_ERROR:       "ERROR",
}

# Maximum firmware payload per DNLOAD transaction — must match I2C_DFU_MAX_XFER_SIZE
MAX_XFER_SIZE    = 2048
VERSION_STR_MAX  = 32  # must match I2C_DFU_VERSION_STR_MAX
GETVERSION_READ_LEN = 2 + VERSION_STR_MAX

# Delays
_WRITE_READ_DELAY_S  = 0.005   # gap between write and read transaction
_BUSY_POLL_DELAY_S   = 0.020   # retry interval when STATUS_BUSY
_ERASE_TIMEOUT_S     = 10.0    # per-page erase timeout
_MASS_ERASE_TIMEOUT_S = 120.0  # full-region mass erase timeout
_WRITE_TIMEOUT_S     = 10.0    # per-block write timeout


# ===========================================================================
# STM32 I2C DFU client
# ===========================================================================

class STM32I2CDFU:
	"""Minimal I2C DFU client that speaks the i2c_dfu_if.h protocol."""

	def __init__(self, bus_num: int = 1, addr: int = I2C_DFU_SLAVE_ADDR_DEFAULT):
		if SMBus is None or i2c_msg is None:
			raise RuntimeError("Missing dependency 'smbus2'. Install with: pip install smbus2")
		self.bus_num = bus_num
		self.addr = addr
		self.bus: SMBus | None = None

	# ------------------------------------------------------------------
	# Context manager / open / close
	# ------------------------------------------------------------------

	def open(self) -> "STM32I2CDFU":
		self.bus = SMBus(self.bus_num)
		return self

	def close(self) -> None:
		if self.bus is not None:
			self.bus.close()
			self.bus = None

	def __enter__(self) -> "STM32I2CDFU":
		return self.open()

	def __exit__(self, exc_type, exc, tb) -> None:
		self.close()

	# ------------------------------------------------------------------
	# Raw I2C primitives
	# ------------------------------------------------------------------

	def _write(self, payload: bytes) -> None:
		"""Send a single I2C write transaction to the slave."""
		msg = i2c_msg.write(self.addr, list(payload))
		self.bus.i2c_rdwr(msg)

	def _read(self, length: int) -> bytes:
		"""Send a single I2C read transaction from the slave."""
		msg = i2c_msg.read(self.addr, length)
		self.bus.i2c_rdwr(msg)
		return bytes(msg)

	def _exchange(self, payload: bytes, read_len: int, pre_read_delay_s: float = _WRITE_READ_DELAY_S) -> bytes:
		"""Write command, optionally wait, then read response."""
		self._write(payload)
		if pre_read_delay_s > 0:
			time.sleep(pre_read_delay_s)
		return self._read(read_len)

	# ------------------------------------------------------------------
	# Status polling
	# ------------------------------------------------------------------

	def get_status(self) -> dict:
		"""Send GETSTATUS and return a dict with status and state fields."""
		raw = self._exchange(bytes([CMD_GETSTATUS]), 2)
		return {"status": raw[0], "state": raw[1], "raw": raw}

	def _wait_while_busy(self, timeout_s: float = _ERASE_TIMEOUT_S) -> dict:
		"""Poll GETSTATUS until the operation completes or times out."""
		deadline = time.monotonic() + timeout_s
		while time.monotonic() < deadline:
			st = self.get_status()
			if st["state"] == STATE_ERROR or st["status"] == STATUS_ERROR:
				raise RuntimeError(
					f"I2C DFU error: status={STATUS_NAMES.get(st['status'], hex(st['status']))}, "
					f"state={STATE_NAMES.get(st['state'], hex(st['state']))}"
				)
			if st["status"] != STATUS_BUSY and st["state"] != STATE_DNBUSY:
				return st
			time.sleep(_BUSY_POLL_DELAY_S)
		raise TimeoutError(f"I2C DFU operation timed out after {timeout_s:.0f}s")

	# ------------------------------------------------------------------
	# DFU commands
	# ------------------------------------------------------------------

	def erase_page(self, address: int) -> None:
		"""Erase the flash page containing 'address'."""
		self._write(struct.pack("<BI", CMD_ERASE, address))
		self._wait_while_busy(timeout_s=_ERASE_TIMEOUT_S)

	def mass_erase(self) -> None:
		"""Erase all application flash pages (addr == 0xFFFFFFFF sentinel)."""
		self._write(struct.pack("<BI", CMD_ERASE, 0xFFFFFFFF))
		self._wait_while_busy(timeout_s=_MASS_ERASE_TIMEOUT_S)

	def write_block(self, address: int, data: bytes) -> None:
		"""Program one block (≤ MAX_XFER_SIZE bytes) at 'address'."""
		if not data:
			return
		payload = struct.pack("<BIH", CMD_DNLOAD, address, len(data)) + data
		self._write(payload)
		self._wait_while_busy(timeout_s=_WRITE_TIMEOUT_S)

	def write_memory(self, address: int, data: bytes) -> None:
		"""Program arbitrary-length data, splitting into MAX_XFER_SIZE chunks."""
		for offset in range(0, len(data), MAX_XFER_SIZE):
			chunk = data[offset:offset + MAX_XFER_SIZE]
			self.write_block(address + offset, chunk)
			if len(data) > MAX_XFER_SIZE:
				# Progress indicator for multi-block transfers
				pct = min(100, int((offset + len(chunk)) * 100 / len(data)))
				print(f"\r  {pct:3d}%  [{offset + len(chunk)}/{len(data)} bytes]", end="", flush=True)
		if len(data) > MAX_XFER_SIZE:
			print()  # newline after progress

	def manifest(self) -> None:
		"""Send MANIFEST to finalise the download (locks flash)."""
		self._write(bytes([CMD_MANIFEST]))
		self._wait_while_busy(timeout_s=_ERASE_TIMEOUT_S)

	def reset(self) -> None:
		"""Send CMD_RESET; device reboots immediately (no response)."""
		self._write(bytes([CMD_RESET]))

	def get_version(self) -> str:
		"""Send GETVERSION and return the null-terminated version string."""
		raw = self._exchange(bytes([CMD_GETVERSION]), GETVERSION_READ_LEN)
		if raw[0] not in (STATUS_OK, STATUS_BUSY):
			raise RuntimeError(f"GETVERSION failed: status={STATUS_NAMES.get(raw[0], hex(raw[0]))}")
		ver_bytes = raw[2:]
		return ver_bytes.split(b"\x00")[0].decode("ascii", errors="replace")


# ===========================================================================
# Pure-Python helpers — identical to dfu-test.py
# ===========================================================================

def stm32_crc32(data: bytes, init: int = 0xFFFFFFFF) -> int:
	"""CRC compatible with STM32 CRC peripheral default settings (poly 0x04C11DB7)."""
	poly = 0x04C11DB7
	crc = init & 0xFFFFFFFF
	for b in data:
		crc ^= (b & 0xFF) << 24
		for _ in range(8):
			if crc & 0x80000000:
				crc = ((crc << 1) ^ poly) & 0xFFFFFFFF
			else:
				crc = (crc << 1) & 0xFFFFFFFF
	return crc


def _require_cryptography() -> None:
	if serialization is None or ec is None or decode_dss_signature is None or Prehashed is None:
		raise RuntimeError(
			"Missing dependency 'cryptography'. Install with: pip install cryptography"
		)


def _load_private_key(key_bytes: bytes):
	_require_cryptography()
	if b"-----BEGIN" in key_bytes:
		return serialization.load_pem_private_key(key_bytes, password=None)
	if len(key_bytes) == 32:
		d = int.from_bytes(key_bytes, "big")
		if d <= 0:
			raise ValueError("Invalid raw private key scalar (must be non-zero)")
		return ec.derive_private_key(d, ec.SECP256R1())
	raise ValueError("Unsupported private key format: expected PEM private key or raw 32-byte scalar")


def _load_public_key(key_bytes: bytes):
	_require_cryptography()
	if b"-----BEGIN" in key_bytes:
		try:
			key = serialization.load_pem_public_key(key_bytes)
		except ValueError:
			key = serialization.load_pem_private_key(key_bytes, password=None).public_key()
		if not isinstance(key, ec.EllipticCurvePublicKey):
			raise ValueError("Provided PEM key is not an EC key")
		return key
	if len(key_bytes) == 64:
		x = int.from_bytes(key_bytes[:32], "big")
		y = int.from_bytes(key_bytes[32:], "big")
		return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
	if len(key_bytes) == 32:
		return _load_private_key(key_bytes).public_key()
	raise ValueError(
		"Unsupported verification key format: expected PEM public/private key, "
		"raw 64-byte x||y public key, or raw 32-byte private scalar"
	)


def _ecdsa_p256_sign_raw(private_key_bytes: bytes, digest32: bytes) -> bytes:
	if len(digest32) != 32:
		raise ValueError("digest must be 32 bytes")
	priv = _load_private_key(private_key_bytes)
	der_sig = priv.sign(digest32, ec.ECDSA(Prehashed(hashes.SHA256())))
	r, s = decode_dss_signature(der_sig)
	return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _ecdsa_p256_verify_raw(public_or_private_key_bytes: bytes, digest32: bytes, sig64: bytes) -> bool:
	if len(digest32) != 32:
		raise ValueError("digest must be 32 bytes")
	if len(sig64) != 64:
		raise ValueError("signature must be 64 bytes")
	pub = _load_public_key(public_or_private_key_bytes)
	r = int.from_bytes(sig64[:32], "big")
	s = int.from_bytes(sig64[32:], "big")
	der_sig = encode_dss_signature(r, s)
	try:
		pub.verify(der_sig, digest32, ec.ECDSA(Prehashed(hashes.SHA256())))
		return True
	except Exception:
		return False


def _load_trust_key(key_bytes: bytes) -> bytes:
	raw = key_bytes.strip()
	if len(raw) == 32:
		return raw
	if len(raw) == 64:
		try:
			decoded = bytes.fromhex(raw.decode("ascii"))
			if len(decoded) == 32:
				return decoded
		except Exception:
			pass
	raise ValueError("Unsupported trust key format: expected 32-byte raw key or 64-char hex")


def build_metadata_blob(
	fw_bytes: bytes,
	signing_key_bytes: bytes,
	fw_address: int,
	key_id: int,
	trust_key_bytes: bytes | None,
) -> bytes:
	fw_len = len(fw_bytes)
	fw_crc = stm32_crc32(fw_bytes)
	digest = hashlib.sha256(fw_bytes).digest()
	signature = _ecdsa_p256_sign_raw(signing_key_bytes, digest)

	if trust_key_bytes:
		trust_tag = hmac.new(trust_key_bytes, digestmod=hashlib.sha256)
		trust_tag.update(
			struct.pack(
				"<IHHIIII64s",
				META_MAGIC,
				META_VERSION,
				META_FLAGS_SIGNATURE_REQUIRED,
				fw_address,
				fw_len,
				fw_crc,
				key_id,
				signature,
			)
		)
		trust_tag_bytes = trust_tag.digest()
	else:
		trust_tag_bytes = bytes(TRUST_TAG_SIZE_BYTES)

	meta_wo_crc = struct.pack(
		META_STRUCT_WITHOUT_CRC,
		META_MAGIC,
		META_VERSION,
		META_FLAGS_SIGNATURE_REQUIRED,
		fw_address,
		fw_len,
		fw_crc,
		key_id,
		signature,
		trust_tag_bytes,
	)
	meta_crc = stm32_crc32(meta_wo_crc)
	return meta_wo_crc + struct.pack("<I", meta_crc)


def parse_metadata_blob(meta: bytes):
	if len(meta) < struct.calcsize(META_STRUCT_FULL):
		raise ValueError("metadata blob too small")
	return struct.unpack(META_STRUCT_FULL, meta[: struct.calcsize(META_STRUCT_FULL)])


def build_signed_package(fw: bytes, meta: bytes, fw_address: int, meta_address: int) -> bytes:
	header_size = struct.calcsize(SIGNED_PKG_HEADER_FULL)
	payload = fw + meta
	payload_crc = stm32_crc32(payload)
	header_wo_crc = struct.pack(
		SIGNED_PKG_HEADER_NOCRC,
		SIGNED_PKG_MAGIC,
		SIGNED_PKG_VERSION,
		header_size,
		fw_address,
		len(fw),
		meta_address,
		len(meta),
		payload_crc,
	)
	header_crc = stm32_crc32(header_wo_crc)
	return header_wo_crc + struct.pack("<I", header_crc) + payload


def parse_signed_package(pkg: bytes):
	header_size = struct.calcsize(SIGNED_PKG_HEADER_FULL)
	if len(pkg) < header_size:
		raise ValueError("signed package too small")
	(
		magic, version, declared_header_size,
		fw_address, fw_len,
		meta_address, meta_len,
		payload_crc, header_crc,
	) = struct.unpack(SIGNED_PKG_HEADER_FULL, pkg[:header_size])

	if magic != SIGNED_PKG_MAGIC:
		raise ValueError("signed package magic mismatch")
	if version != SIGNED_PKG_VERSION:
		raise ValueError(f"signed package version mismatch: {version}")
	if declared_header_size != header_size:
		raise ValueError("signed package header size mismatch")

	calc_header_crc = stm32_crc32(pkg[: header_size - 4])
	if header_crc != calc_header_crc:
		raise ValueError(
			f"signed package header CRC mismatch: pkg=0x{header_crc:08X}, calc=0x{calc_header_crc:08X}"
		)

	payload_len = fw_len + meta_len
	payload = pkg[header_size:]
	if len(payload) != payload_len:
		raise ValueError(
			f"signed package payload size mismatch: expected={payload_len}, file={len(payload)}"
		)

	calc_payload_crc = stm32_crc32(payload)
	if payload_crc != calc_payload_crc:
		raise ValueError(
			f"signed package payload CRC mismatch: pkg=0x{payload_crc:08X}, calc=0x{calc_payload_crc:08X}"
		)

	return {
		"fw_address":   fw_address,
		"meta_address": meta_address,
		"fw":           payload[:fw_len],
		"meta":         payload[fw_len:],
	}


def relocate_flash_addresses(blob: bytes, link_origin: int, run_origin: int, window_size: int) -> bytes:
	if window_size <= 0:
		raise ValueError("window_size must be positive")
	delta = run_origin - link_origin
	start = link_origin
	end   = link_origin + window_size
	out   = bytearray(blob)
	for i in range(0, len(out) - 3, 4):
		word = struct.unpack_from("<I", out, i)[0]
		if start <= word < end:
			struct.pack_into("<I", out, i, (word + delta) & 0xFFFFFFFF)
	return bytes(out)


# ===========================================================================
# CLI
# ===========================================================================

def _parse_int(value: str) -> int:
	return int(value, 0)


def main() -> None:
	p = argparse.ArgumentParser(description="STM32 I2C DFU test utility")
	p.add_argument("--bus",  type=int, default=1,
	               help="I2C bus number (default: 1)")
	p.add_argument("--addr", type=_parse_int, default=I2C_DFU_SLAVE_ADDR_DEFAULT,
	               help=f"I2C slave address (default: 0x{I2C_DFU_SLAVE_ADDR_DEFAULT:02X})")

	sub = p.add_subparsers(dest="cmd", required=True)

	# ---- device commands -------------------------------------------------

	sub.add_parser("erase",      help="Erase one flash page at address")\
	   .add_argument("address", type=_parse_int)

	sub.add_parser("mass-erase", help="Erase all application flash pages")

	sub.add_parser("info",       help="Print I2C DFU status and version")

	sub.add_parser("get-version", help="Read bootloader version string")

	sub.add_parser("reboot",     help="Reset the device")

	sub.add_parser("getstatus",  help="Print current DFU status/state")

	w = sub.add_parser("write", help="Write binary file to target memory")
	w.add_argument("address", type=_parse_int)
	w.add_argument("infile")
	w.add_argument("--erase-pages", action="store_true",
	               help="Erase touched pages before writing")
	w.add_argument("--manifest", action="store_true",
	               help="Send MANIFEST after writing (finalises download)")

	pp = sub.add_parser("program-package",
	                    help="Program firmware+metadata from signed package")
	pp.add_argument("packagefile")
	pp.add_argument("--manifest", action="store_true",
	                help="Send MANIFEST after programming")

	ps = sub.add_parser("program-signed",
	                    help="Program firmware and sign metadata in one step")
	ps.add_argument("infile")
	ps.add_argument("keyfile")
	ps.add_argument("--address",      type=_parse_int, default=APP_ADDRESS_DEFAULT)
	ps.add_argument("--meta-address", type=_parse_int, default=META_ADDRESS_DEFAULT)
	ps.add_argument("--key-id",       type=_parse_int, default=1)
	ps.add_argument("--link-origin",  type=_parse_int, default=None,
	                help="Original link address to relocate from (e.g. 0x08000000)")
	ps.add_argument("--run-origin",   type=_parse_int, default=None,
	                help="Runtime/program address to relocate to (defaults to --address)")
	ps.add_argument("--relocate-window", type=_parse_int, default=DEFAULT_RELOCATE_WINDOW,
	                help="Address window size to relocate")
	ps.add_argument("--trust-keyfile", default=None,
	                help="Optional trust HMAC key file (raw 32-byte or 64-char hex)")
	ps.add_argument("--manifest", action="store_true",
	                help="Send MANIFEST after programming")

	# ---- pure-Python commands (no device required) ----------------------

	sm = sub.add_parser("sign-metadata",
	                    help="Create metadata block for a firmware image (offline)")
	sm.add_argument("infile")
	sm.add_argument("keyfile", help="Signing key (PEM private key or raw 32-byte scalar)")
	sm.add_argument("outfile")
	sm.add_argument("--address",     type=_parse_int, default=APP_ADDRESS_DEFAULT)
	sm.add_argument("--key-id",      type=_parse_int, default=1)
	sm.add_argument("--link-origin", type=_parse_int, default=None)
	sm.add_argument("--run-origin",  type=_parse_int, default=None)
	sm.add_argument("--relocate-window", type=_parse_int, default=DEFAULT_RELOCATE_WINDOW)
	sm.add_argument("--trust-keyfile", default=None)

	vm = sub.add_parser("verify-metadata",
	                    help="Verify metadata blob against firmware/key (offline)")
	vm.add_argument("infile")
	vm.add_argument("keyfile", help="Verification key (PEM public/private key or raw bytes)")
	vm.add_argument("metafile")
	vm.add_argument("--link-origin",     type=_parse_int, default=None)
	vm.add_argument("--run-origin",      type=_parse_int, default=None)
	vm.add_argument("--relocate-window", type=_parse_int, default=DEFAULT_RELOCATE_WINDOW)
	vm.add_argument("--trust-keyfile",   default=None)

	pk = sub.add_parser("pack-signed",
	                    help="Create distributable signed package file (offline)")
	pk.add_argument("infile")
	pk.add_argument("keyfile", help="Signing key (PEM private key or raw 32-byte scalar)")
	pk.add_argument("outfile")
	pk.add_argument("--address",      type=_parse_int, default=APP_ADDRESS_DEFAULT)
	pk.add_argument("--meta-address", type=_parse_int, default=META_ADDRESS_DEFAULT)
	pk.add_argument("--key-id",       type=_parse_int, default=1)
	pk.add_argument("--link-origin",  type=_parse_int, default=None)
	pk.add_argument("--run-origin",   type=_parse_int, default=None)
	pk.add_argument("--relocate-window", type=_parse_int, default=DEFAULT_RELOCATE_WINDOW)
	pk.add_argument("--trust-keyfile", default=None)

	vp = sub.add_parser("verify-package",
	                    help="Verify signed package integrity and metadata (offline)")
	vp.add_argument("packagefile")
	vp.add_argument("keyfile", help="Verification key (PEM public/private key or raw bytes)")
	vp.add_argument("--trust-keyfile", default=None)

	args = p.parse_args()

	# ====================================================================
	# Offline commands — no I2C device needed
	# ====================================================================

	if args.cmd == "sign-metadata":
		with open(args.infile, "rb") as f:
			fw = f.read()

		if args.link_origin is not None:
			run_origin = args.run_origin if args.run_origin is not None else args.address
			fw = relocate_flash_addresses(fw, args.link_origin, run_origin, args.relocate_window)
			print(f"Relocated image: 0x{args.link_origin:08X} -> 0x{run_origin:08X} "
			      f"(window {args.relocate_window} bytes)")

		with open(args.keyfile, "rb") as f:
			key = f.read()

		trust_key = None
		if args.trust_keyfile:
			with open(args.trust_keyfile, "rb") as f:
				trust_key = _load_trust_key(f.read())

		meta = build_metadata_blob(fw, key, args.address, args.key_id, trust_key)
		with open(args.outfile, "wb") as f:
			f.write(meta)
		print(f"Metadata written: {args.outfile} ({len(meta)} bytes)")
		if trust_key is None:
			print("Note: trust_tag not sealed (all zeros); bootloader will use slow ECDSA path on cold boot.")
		return

	if args.cmd == "verify-metadata":
		with open(args.infile, "rb") as f:
			fw = f.read()
		with open(args.keyfile, "rb") as f:
			key = f.read()
		with open(args.metafile, "rb") as f:
			meta_blob = f.read()

		(magic, version, flags, fw_addr, fw_len, fw_crc, key_id, signature, trust_tag, meta_crc) = \
			parse_metadata_blob(meta_blob)

		if args.link_origin is not None:
			run_origin = args.run_origin if args.run_origin is not None else fw_addr
			fw = relocate_flash_addresses(fw, args.link_origin, run_origin, args.relocate_window)
			print(f"Relocated image for verify: 0x{args.link_origin:08X} -> 0x{run_origin:08X} "
			      f"(window {args.relocate_window} bytes)")
		elif args.run_origin is not None:
			raise SystemExit("--run-origin requires --link-origin")

		calc_meta_crc  = stm32_crc32(meta_blob[: struct.calcsize(META_STRUCT_WITHOUT_CRC)])
		calc_fw_crc    = stm32_crc32(fw)
		calc_fw_digest = hashlib.sha256(fw).digest()
		signature_ok   = _ecdsa_p256_verify_raw(key, calc_fw_digest, signature)
		trust_ok       = None

		if args.trust_keyfile:
			with open(args.trust_keyfile, "rb") as f:
				trust_key = _load_trust_key(f.read())
			msg = struct.pack("<IHHIIII64s", magic, version, flags, fw_addr, fw_len, fw_crc, key_id, signature)
			trust_ok = hmac.compare_digest(hmac.new(trust_key, msg, hashlib.sha256).digest(), trust_tag)

		ok = True
		if magic != META_MAGIC or version != META_VERSION:
			print("Metadata magic/version mismatch"); ok = False
		if flags != META_FLAGS_SIGNATURE_REQUIRED:
			print(f"Metadata flags mismatch: meta=0x{flags:04X}, expected=0x{META_FLAGS_SIGNATURE_REQUIRED:04X}"); ok = False
		if fw_len != len(fw):
			print(f"Firmware length mismatch: meta={fw_len}, file={len(fw)}"); ok = False
		if fw_crc != calc_fw_crc:
			print(f"Firmware CRC mismatch: meta=0x{fw_crc:08X}, calc=0x{calc_fw_crc:08X}"); ok = False
		if meta_crc != calc_meta_crc:
			print(f"Metadata CRC mismatch: meta=0x{meta_crc:08X}, calc=0x{calc_meta_crc:08X}"); ok = False
		if signature_ok is False:
			print("ECDSA signature mismatch"); ok = False
		if trust_ok is False:
			print("Trust-tag HMAC mismatch"); ok = False
		if not ok:
			raise SystemExit(2)
		if trust_ok is True:
			print("Trust-tag verify OK")
		print(f"Metadata verify OK (key_id={key_id}, fw_addr=0x{fw_addr:08X}, flags=0x{flags:04X})")
		return

	if args.cmd == "pack-signed":
		with open(args.infile, "rb") as f:
			fw = f.read()

		if args.link_origin is not None:
			run_origin = args.run_origin if args.run_origin is not None else args.address
			fw = relocate_flash_addresses(fw, args.link_origin, run_origin, args.relocate_window)
			print(f"Relocated image: 0x{args.link_origin:08X} -> 0x{run_origin:08X} "
			      f"(window {args.relocate_window} bytes)")

		with open(args.keyfile, "rb") as f:
			key = f.read()

		trust_key = None
		if args.trust_keyfile:
			with open(args.trust_keyfile, "rb") as f:
				trust_key = _load_trust_key(f.read())

		meta = build_metadata_blob(fw, key, args.address, args.key_id, trust_key)
		pkg  = build_signed_package(fw, meta, args.address, args.meta_address)
		with open(args.outfile, "wb") as f:
			f.write(pkg)
		print(f"Signed package written: {args.outfile} ({len(pkg)} bytes)")
		if trust_key is None:
			print("Note: trust_tag not sealed (all zeros); bootloader will use slow ECDSA path on cold boot.")
		return

	if args.cmd == "verify-package":
		with open(args.packagefile, "rb") as f:
			pkg_blob = f.read()
		with open(args.keyfile, "rb") as f:
			key = f.read()

		pkg = parse_signed_package(pkg_blob)
		fw       = pkg["fw"]
		meta     = pkg["meta"]
		fw_addr  = pkg["fw_address"]

		trust_key = None
		if args.trust_keyfile:
			with open(args.trust_keyfile, "rb") as f:
				trust_key = _load_trust_key(f.read())

		ok, messages, key_id, _, flags = _verify_package_contents(fw, meta, key, trust_key)
		for m in messages:
			print(m)
		if not ok:
			raise SystemExit(2)
		print(
			f"Package verify OK (key_id={key_id}, fw_addr=0x{fw_addr:08X}, "
			f"meta_addr=0x{pkg['meta_address']:08X}, flags=0x{flags:04X})"
		)
		return

	# ====================================================================
	# Device commands — open I2C bus
	# ====================================================================

	with STM32I2CDFU(bus_num=args.bus, addr=args.addr) as dfu:

		if args.cmd == "getstatus":
			st = dfu.get_status()
			status_name = STATUS_NAMES.get(st["status"], f"0x{st['status']:02X}")
			state_name  = STATE_NAMES.get(st["state"],   f"0x{st['state']:02X}")
			print(f"Status: {status_name} (0x{st['status']:02X})")
			print(f"State:  {state_name} (0x{st['state']:02X})")

		elif args.cmd == "get-version":
			ver = dfu.get_version()
			if not ver:
				print("Version string is empty (bootloader may not support this command)")
			else:
				print(f"Bootloader version: {ver}")

		elif args.cmd == "info":
			print(f"I2C bus:   {args.bus}")
			print(f"I2C addr:  0x{args.addr:02X}")
			st = dfu.get_status()
			status_name = STATUS_NAMES.get(st["status"], f"0x{st['status']:02X}")
			state_name  = STATE_NAMES.get(st["state"],   f"0x{st['state']:02X}")
			print(f"Status:    {status_name} (0x{st['status']:02X})")
			print(f"State:     {state_name} (0x{st['state']:02X})")
			try:
				ver = dfu.get_version()
				print(f"Version:   {ver or '(empty)'}")
			except Exception as exc:
				print(f"Version:   (error: {exc})")

		elif args.cmd == "reboot":
			dfu.reset()
			print("Reset command sent. Device is rebooting.")

		elif args.cmd == "erase":
			dfu.erase_page(args.address)
			print(f"Erased page at 0x{args.address:08X}")

		elif args.cmd == "mass-erase":
			print("Sending mass-erase (this may take a while)...")
			dfu.mass_erase()
			print("Mass erase complete")

		elif args.cmd == "write":
			with open(args.infile, "rb") as f:
				blob = f.read()

			if args.erase_pages and blob:
				page_size = 2048
				first = args.address & ~(page_size - 1)
				last  = (args.address + len(blob) - 1) & ~(page_size - 1)
				num_pages = (last - first) // page_size + 1
				print(f"Erasing {num_pages} page(s) starting at 0x{first:08X}...")
				for i in range(num_pages):
					dfu.erase_page(first + i * page_size)

			print(f"Writing {len(blob)} bytes to 0x{args.address:08X}...")
			dfu.write_memory(args.address, blob)
			print(f"Write complete")

			if args.manifest:
				dfu.manifest()
				print("Manifest sent: device should leave DFU and run application")

		elif args.cmd == "program-package":
			with open(args.packagefile, "rb") as f:
				pkg_blob = f.read()
			pkg      = parse_signed_package(pkg_blob)
			fw       = pkg["fw"]
			meta     = pkg["meta"]
			fw_addr  = pkg["fw_address"]
			meta_addr = pkg["meta_address"]

			if fw:
				page_size = 2048
				first = fw_addr & ~(page_size - 1)
				last  = (fw_addr + len(fw) - 1) & ~(page_size - 1)
				num_pages = (last - first) // page_size + 1
				print(f"Erasing {num_pages} firmware page(s)...")
				for i in range(num_pages):
					dfu.erase_page(first + i * page_size)

			print(f"Erasing metadata page at 0x{meta_addr:08X}...")
			dfu.erase_page(meta_addr)

			print(f"Writing firmware ({len(fw)} bytes) to 0x{fw_addr:08X}...")
			dfu.write_memory(fw_addr, fw)

			print(f"Writing metadata ({len(meta)} bytes) to 0x{meta_addr:08X}...")
			dfu.write_memory(meta_addr, meta)

			print(
				f"Programmed package: firmware ({len(fw)} bytes) at 0x{fw_addr:08X}, "
				f"metadata ({len(meta)} bytes) at 0x{meta_addr:08X}"
			)

			if args.manifest:
				dfu.manifest()
				print("Manifest sent: device should leave DFU and run application")

		elif args.cmd == "program-signed":
			with open(args.infile, "rb") as f:
				fw = f.read()

			if args.link_origin is not None:
				run_origin = args.run_origin if args.run_origin is not None else args.address
				fw = relocate_flash_addresses(fw, args.link_origin, run_origin, args.relocate_window)
				print(f"Relocated image: 0x{args.link_origin:08X} -> 0x{run_origin:08X} "
				      f"(window {args.relocate_window} bytes)")

			with open(args.keyfile, "rb") as f:
				key = f.read()

			trust_key = None
			if args.trust_keyfile:
				with open(args.trust_keyfile, "rb") as f:
					trust_key = _load_trust_key(f.read())

			meta = build_metadata_blob(fw, key, args.address, args.key_id, trust_key)

			if fw:
				page_size = 2048
				first = args.address & ~(page_size - 1)
				last  = (args.address + len(fw) - 1) & ~(page_size - 1)
				num_pages = (last - first) // page_size + 1
				print(f"Erasing {num_pages} firmware page(s)...")
				for i in range(num_pages):
					dfu.erase_page(first + i * page_size)

			print(f"Erasing metadata page at 0x{args.meta_address:08X}...")
			dfu.erase_page(args.meta_address)

			print(f"Writing firmware ({len(fw)} bytes) to 0x{args.address:08X}...")
			dfu.write_memory(args.address, fw)

			print(f"Writing metadata ({len(meta)} bytes) to 0x{args.meta_address:08X}...")
			dfu.write_memory(args.meta_address, meta)

			print(f"Programmed signed firmware ({len(fw)} bytes) and metadata at 0x{args.meta_address:08X}")
			if trust_key is None:
				print("Note: trust_tag not sealed (all zeros); bootloader will use slow ECDSA path on cold boot.")

			if args.manifest:
				dfu.manifest()
				print("Manifest sent: device should leave DFU and run application")


def _verify_package_contents(fw, meta, key, trust_key):
	"""Helper used by verify-package (offline)."""
	(magic, version, flags, fw_addr, fw_len, fw_crc, key_id, signature, trust_tag, meta_crc) = \
		parse_metadata_blob(meta)
	calc_meta_crc  = stm32_crc32(meta[: struct.calcsize(META_STRUCT_WITHOUT_CRC)])
	calc_fw_crc    = stm32_crc32(fw)
	calc_fw_digest = hashlib.sha256(fw).digest()
	signature_ok   = _ecdsa_p256_verify_raw(key, calc_fw_digest, signature)
	trust_ok       = None

	if trust_key is not None:
		msg = struct.pack("<IHHIIII64s", magic, version, flags, fw_addr, fw_len, fw_crc, key_id, signature)
		trust_ok = hmac.compare_digest(hmac.new(trust_key, msg, hashlib.sha256).digest(), trust_tag)

	messages: list[str] = []
	ok = True
	if magic != META_MAGIC or version != META_VERSION:
		messages.append("Metadata magic/version mismatch"); ok = False
	if flags != META_FLAGS_SIGNATURE_REQUIRED:
		messages.append(f"Metadata flags mismatch: meta=0x{flags:04X}, expected=0x{META_FLAGS_SIGNATURE_REQUIRED:04X}"); ok = False
	if fw_len != len(fw):
		messages.append(f"Firmware length mismatch: meta={fw_len}, file={len(fw)}"); ok = False
	if fw_crc != calc_fw_crc:
		messages.append(f"Firmware CRC mismatch: meta=0x{fw_crc:08X}, calc=0x{calc_fw_crc:08X}"); ok = False
	if meta_crc != calc_meta_crc:
		messages.append(f"Metadata CRC mismatch: meta=0x{meta_crc:08X}, calc=0x{calc_meta_crc:08X}"); ok = False
	if signature_ok is False:
		messages.append("ECDSA signature mismatch"); ok = False
	if trust_ok is False:
		messages.append("Trust-tag HMAC mismatch"); ok = False
	if trust_ok is True:
		messages.append("Trust-tag verify OK")
	return ok, messages, key_id, fw_addr, flags


if __name__ == "__main__":
	main()
