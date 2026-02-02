from typing import Dict
import logging

from pysake.constants import LOGGER_NAME
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
        log = logging.getLogger(LOGGER_NAME).getChild("KeyDatabase")
        crc = data[0:4]
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


KEYDB_G4_CGM = KeyDatabase.from_bytes(bytes.fromhex("5fe5928308010230f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326"))
KEYDB_PUMP_EXTRACTED = KeyDatabase.from_bytes(bytes.fromhex("f75995e70401011bc1bf7cbf36fa1e2367d795ff09211903da6afbe986b650f14179c0e6852e0ce393781078ffc6f51919e2eaefbde69b8eca21e41ab59b881a0bea0286ea91dc7582a86a714e1737f558f0d66dc1895c"))
KEYDB_PUMP_HARDCODED = KeyDatabase.from_bytes(bytes.fromhex("c2cdfdd1040101fce36ed66ef21def3b0763975494b239038ebe8606f79a9bf00d9f11b6db04c7c0434787cbf00d5476289c22288e2105ae40e01391837f9476fa5003895c5a1afe35662a2a6211826af016eebe30e4ba"))

AVAILABLE_KEYS = [
    KEYDB_G4_CGM,
    KEYDB_PUMP_EXTRACTED,
    KEYDB_PUMP_HARDCODED,
]

if __name__ == "__main__":
    print("\n")
    for k in AVAILABLE_KEYS:
        print(k)    

