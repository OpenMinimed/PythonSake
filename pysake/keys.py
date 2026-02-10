from typing import Dict
import logging
import zlib
import sys

from pysake.device_types import DeviceType

class StaticKeys:

    def __init__(self, derivation_key: bytes, handshake_auth_key: bytes,
                 permit_decrypt_key: bytes, permit_auth_key: bytes,
                 handshake_payload: bytes) -> None:
        self.derivation_key = derivation_key
        self.handshake_auth_key = handshake_auth_key
        self.permit_decrypt_key = permit_decrypt_key
        self.permit_auth_key = permit_auth_key
        self.handshake_payload = handshake_payload
        return

    @staticmethod
    def from_bytes(data: bytes) -> "StaticKeys":
        parts = [data[i : i + 16] for i in range(0, 80, 16)]
        return StaticKeys(*parts)

    def __repr__(self) -> str:
        return (
            f"StaticKeys(derivation_key={self.derivation_key.hex()}, "
            f"handshake_auth_key={self.handshake_auth_key.hex()}, "
            f"permit_decrypt_key={self.permit_decrypt_key.hex()}, "
            f"permit_auth_key={self.permit_auth_key.hex()}, "
            f"handshake_payload={self.handshake_payload.hex()})"
        )


class KeyDatabase:

    def __init__(self, local_device_type: DeviceType, remote_devices: Dict[DeviceType, StaticKeys], crc: bytes) -> None:
        self.local_device_type = local_device_type
        self.remote_devices = remote_devices
        self.crc = crc
        return

    @classmethod
    def from_bytes(cls, data: bytes) -> "KeyDatabase":

        from pysake.constants import LOGGER_NAME # due to circular imports
        
        log = logging.getLogger(LOGGER_NAME).getChild("KeyDatabase")
        crc = data[0:4]
        # validate CRC
        payload = data[4:]
        expected_crc = cls._compute_crc(payload)
        if expected_crc != crc:
            raise ValueError(f"crc mismatch: expected {expected_crc.hex()} got {crc.hex()}")
        # parse
        n = data[5]
        if len(data) != 6 + 81 * n:
            raise ValueError("invalid keydb length")
        local_device_type = DeviceType(data[4])
        log.debug(f"local_device_type = {local_device_type.name}")
        remote_devices: Dict[DeviceType, StaticKeys] = {}
        for i in range(n):
            p = 6 + 81 * i
            dev = DeviceType(data[p])
            remote_devices[dev] = StaticKeys.from_bytes(data[p + 1 : p + 81])
        log.debug(f"remote_devices = {[d.name for d in remote_devices.keys()]}")
        return cls(local_device_type=local_device_type, remote_devices=remote_devices, crc=crc)

    @staticmethod
    def _compute_crc(payload: bytes) -> bytes:
        """Return 4-byte big-endian CRC32 for payload."""
        val = zlib.crc32(payload) & 0xFFFFFFFF
        return val.to_bytes(4, "big")

    def _payload_bytes(self) -> bytes:
        """
        Build the payload bytes (local_device_type + n + entries) used for CRC calculation
        and for the final serialized form (after the 4-byte CRC).
        """
        n = len(self.remote_devices)
        payload = bytearray()
        payload.append(self.local_device_type.value)
        payload.append(n & 0xFF)
        for dev, sk in self.remote_devices.items():
            payload.append(dev.value)
            payload.extend(sk.derivation_key)
            payload.extend(sk.handshake_auth_key)
            payload.extend(sk.permit_decrypt_key)
            payload.extend(sk.permit_auth_key)
            payload.extend(sk.handshake_payload)
        return bytes(payload)

    def to_bytes(self) -> bytes:
        """
        Serialize KeyDatabase to bytes with CRC32 (big-endian) in first 4 bytes.
        Layout: [4-byte CRC][1-byte local_device_type][1-byte n][n * (1-byte dev_type + 80-byte StaticKeys)]
        CRC is computed over bytes after the CRC field (i.e. from local_device_type onwards).
        """
        payload = self._payload_bytes()
        crc_bytes = self._compute_crc(payload)
        return crc_bytes + payload

    def reverse(self) -> "KeyDatabase":
        """
        If this database contains exactly one remote device, return a single reversed KeyDatabase
        swapping local and remote. CRC is recalculated and set on the returned object. CRC is
        verified after calculation.
        """
        if len(self.remote_devices) != 1:
            raise ValueError("reverse() requires exactly one remote device; use reversed_databases() for multiple")
        remote_dev, sk = next(iter(self.remote_devices.items()))
        new_db = KeyDatabase(local_device_type=remote_dev, remote_devices={self.local_device_type: sk}, crc=b"\x00\x00\x00\x00")
        crc = self._compute_crc(new_db._payload_bytes())
        new_db.crc = crc
        # sanity check
        if self._compute_crc(new_db._payload_bytes()) != new_db.crc:
            raise ValueError("crc mismatch after reverse calculation")
        return new_db

    def __repr__(self) -> str:
        if self.remote_devices:
            remote_entries = ",\n  ".join(
                f"{dev.name}: {repr(sk)}" for dev, sk in self.remote_devices.items()
            )
            remote_block = f"[\n  {remote_entries}\n]"
        else:
            remote_block = "[]"
        return (
            f"KeyDatabase(local_device_type={self.local_device_type.name}, "
            f"remote_devices={remote_block}, crc={self.crc.hex()})"
        )

if __name__ == "__main__":
    from pysake.constants import AVAILABLE_KEYS

    for key in AVAILABLE_KEYS:
        print("\n" + "*"*30 + "\n")
        print("\norig:\n")
        print(key)
        print(key.to_bytes().hex()) 
        print("\n\nreverse:\n")
        rev = key.reverse()
        print(rev)
        print(rev.to_bytes().hex())