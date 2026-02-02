from typing import Dict
import logging

#from pysake.constants import LOGGER_NAME
LOGGER_NAME = "pysake" # TODO: circular import 

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

    def reverse(self) -> "KeyDatabase":
        """
        If this database contains exactly one remote device, return a single reversed KeyDatabase
        swapping local and remote. Otherwise raise ValueError.
        """
        if len(self.remote_devices) != 1:
            raise ValueError("reverse() requires exactly one remote device; use reversed_databases() for multiple")
        remote_dev, sk = next(iter(self.remote_devices.items()))
        return KeyDatabase(local_device_type=remote_dev, remote_devices={self.local_device_type: sk}, crc=self.crc)

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
    print("\n")
    for k in AVAILABLE_KEYS:
        print("\n" + "*"*30 + "\n")
        print(k)
        print("\nreverse:\n")
        print(k.reverse())

    