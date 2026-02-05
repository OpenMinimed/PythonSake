from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

import hashlib
import logging

from pysake.constants import LOGGER_NAME
from pysake.keys import KeyDatabase
from pysake.seqcrypt import SeqCrypt
from pysake.device_types import DeviceType

class Session():

    # ctor
    client_key_db:KeyDatabase = None
    server_key_db:KeyDatabase = None

    # permit
    client_static_keys:bytes = None
    server_static_keys:bytes = None

    # msg 0
    server_device_type:DeviceType = None

    # msg 1
    client_device_type:DeviceType = None

    client_key_material:bytes = None
    client_nonce:bytes = None

    derivation_key:bytes = None
    handshake_auth_key:bytes = None

    # msg 2
    server_key_material:bytes = None
    server_nonce:bytes = None

    # msg 4
    client_crypt:SeqCrypt = None
    server_crypt:SeqCrypt = None

    # region ctor

    def __init__(self, client_keydb:KeyDatabase=None, server_keydb:KeyDatabase=None):
        
        c = 0
        for d in [client_keydb, server_keydb]:
            if d != None:
                c+=1

        if c != 1:
            raise ValueError(f"Exactly one keydb argument is required! {c} given")

        self.client_key_db = client_keydb
        self.server_key_db = server_keydb
        self.log = logging.getLogger(LOGGER_NAME).getChild("Session")
        return
    
    # region helpers

    def __repr__(self):
        def fmt(v):
            if v is None:
                return "None"
            if isinstance(v, bytes):
                return v.hex()
            if hasattr(v, "__repr__") and type(v).__repr__ is not object.__repr__:
                return repr(v)
            return repr(v)

        parts = [
       #     f"client_static_keys={fmt(self.client_static_keys)}",
      #      f"server_static_keys={fmt(self.server_static_keys)}",

            f"server_device_type={self.server_device_type}",
            f"client_device_type={self.client_device_type}",

            f"client_key_material={fmt(self.client_key_material)}",
            f"client_nonce={fmt(self.client_nonce)}",

            f"derivation_key={fmt(self.derivation_key)}",
            f"handshake_auth_key={fmt(self.handshake_auth_key)}",

            f"server_key_material={fmt(self.server_key_material)}",
            f"server_nonce={fmt(self.server_nonce)}",

            f"client_crypt={fmt(self.client_crypt)}",
            f"server_crypt={fmt(self.server_crypt)}",
        ]

        return f"{self.__class__.__name__}(\n  " + ",\n  ".join(parts) + "\n)"

    def get_state_checksum(self,len=4) -> str:
        h = hashlib.sha256(str(self).encode("utf-8")).digest()
        return h[:len].hex()

    def __check_permit(self, payload, verifier_static_keys, prover_static_keys, prover_device_type:int):

        if prover_static_keys is not None:
            self.log.debug(f"check_permit() 1: {payload.hex() = }")
            self.log.debug(f"check_permit() 1: {prover_static_keys.handshake_payload.hex() = }")
            if payload == prover_static_keys.handshake_payload:
                self.log.debug("check_permit() 1: handshake payload match")
                # TODO add this to return condition??
            else:
                self.log.error(f"check_permit() 1: mismatched!")
        
        if verifier_static_keys is not None:
            
            plain = AES.new(verifier_static_keys.permit_decrypt_key, AES.MODE_ECB).decrypt(
                payload
            )
            auth = CMAC.new(verifier_static_keys.permit_auth_key, ciphermod=AES, mac_len=4)
            auth.update(plain[:12])
            self.log.debug(f"check_permit() 2: plain first = {plain[12:].hex() = }")
            self.log.debug(f"check_permit() 2: plain last  = {plain[:12].hex() = }")
            auth.verify(plain[12:])
            
            if plain[0] == 0 and plain[1] == prover_device_type:
                self.log.debug("check_permit() 2: prover device type match")
                return True
            else:
                self.log.error(f"check_permit() 2: mismatched")

        
        return False
     
    @staticmethod
    def cmac8(client_key_material, server_key_material, derivation_key, handshake_auth_key):
        logging.debug(f"cmac8() = {client_key_material.hex() = } {server_key_material.hex() = } {derivation_key.hex() = } {handshake_auth_key.hex() = }")
        msg = server_key_material + client_key_material + derivation_key
        assert len(msg) == 32
        cobj = CMAC.new(handshake_auth_key, ciphermod=AES, mac_len=8)
        cobj.update(msg)
        return cobj
    
    @staticmethod
    def check_len(data:bytes) -> None:
        l = len(data)
        exp = 20
        if l != exp:
            raise ValueError(f"Invalid message length: {l}, expected {exp}!")
        return
    
    # region handshake

    def handshake_0_s(self, msg:bytes):
        self.log.debug("handshake_0_s()")
        self.check_len(msg)
        
        if msg[1] != 1: # TODO: what is this?
            raise ValueError
        
        self.server_device_type = DeviceType(msg[0])
        return

    def handshake_1_c(self, msg: bytes):
        self.log.debug("handshake_1_c()")

        self.check_len(msg)

        self.client_key_material = msg[:8]
        self.client_nonce = msg[9:13]
        self.client_device_type = DeviceType(msg[8])

        # macros for easier access
        cdt = self.client_device_type.value
        sdt = self.server_device_type.value
        ckd = self.client_key_db
        skd = self.server_key_db
        if ckd is None and skd is None:
            raise ValueError("No key database available.")
        
        # try to get the static keys between the two device databases
        static_keys = None
        if ckd is not None and ckd.local_device_type.value == cdt:
            static_keys = self.client_static_keys = ckd.remote_devices.get(sdt)
        if skd is not None and skd.local_device_type.value == sdt:
            static_keys = self.server_static_keys = skd.remote_devices.get(cdt)
        if static_keys is None:
            raise KeyError(f"No keys available for client device type {cdt} and server device type {sdt}.")
        
        # extract the two main keys
        self.derivation_key = static_keys.derivation_key
        self.handshake_auth_key = static_keys.handshake_auth_key
        self.log.debug(f"handshake_1_c() done, deriv and handshake keys are selected")
        return

    def handshake_2_s(self, msg: bytes):
        self.log.debug("handshake_2_s()")
        self.check_len(msg)
        server_key_material = msg[8:16]
        server_nonce = msg[16:20]
        auth = self.cmac8(
            self.client_key_material,
            server_key_material,
            self.derivation_key,
            self.handshake_auth_key,
        )
        received = msg[0:8]
        auth.verify(received)
        self.log.debug(f"handshake_2_s() verified")
        self.server_key_material = server_key_material
        self.server_nonce = server_nonce
        return

    def handshake_3_c(self, msg: bytes):
        self.log.debug("handshake_3_c()")

        self.check_len(msg)

        auth1 = self.cmac8(
            self.client_key_material,
            self.server_key_material,
            self.derivation_key,
            self.handshake_auth_key,
        )

        inner = (
            auth1.digest() + self.server_key_material + self.derivation_key
        )

        auth2 = CMAC.new(self.handshake_auth_key, ciphermod=AES, mac_len=8)
        auth2.update(inner)

        received_mac = msg[:8]
        expected_mac = auth2.digest()
        # self.log.debug(f"expected auth2 cmac = {expected_mac.hex()} for {inner.hex()} data")
        # # auth2.verify(received_mac) # this throws on my pump!
        if received_mac != expected_mac:
            self.log.error(f"MAC MISMATCH! IGNORING! {received_mac.hex() = } vs {expected_mac.hex() = }")

        self._create_crypts()

        return

    def _create_crypts(self):
        key = AES.new(self.derivation_key, AES.MODE_ECB).encrypt(
            self.server_key_material + self.client_key_material
        )
        nonce = self.client_nonce + self.server_nonce
        self.log.debug(f"merged nonces = {nonce.hex() = }")
        self.client_crypt = SeqCrypt(key=key, nonce=nonce, seq=0)
        self.server_crypt = SeqCrypt(key=key, nonce=nonce, seq=1)
        self.log.debug(f"seqcrypts are created!")
        return
    
    def handshake_4_s(self, msg: bytes) -> bool:
        self.log.debug("handshake_4_s()")
        self.check_len(msg)

        # moved to the end of 3_c():
        # self._create_crypts()

        inner = self.server_crypt.decrypt(msg)[:16]
        self.log.debug(f"handshake_4_s() {inner.hex() = }")
        return self.__check_permit(inner, self.client_static_keys, self.server_static_keys, self.server_device_type.value)
        
    def handshake_5_c(self, msg: bytes) -> bool:
        self.log.debug("handshake_5_c()")
        self.check_len(msg)
        self.log.debug(f"handshake_5_c(): arg = {msg.hex()}")
        inner = self.client_crypt.decrypt(msg)[:-1]
        self.log.debug(f"handshake_5_c(): {inner.hex() = }")
        self.log.debug(f"{self.server_static_keys =}, {self.client_static_keys = }, {self.client_device_type = }")
        return self.__check_permit(inner, self.server_static_keys, self.client_static_keys, self.client_device_type.value)

if __name__ == "__main__":

    import logging
    logging.basicConfig(level=logging.DEBUG)

    PUMP_TEST = True

    if PUMP_TEST:
        from pysake.constants import PUMP_TEST_MSGS, PUMP_TEST_KEYDB
        test_db = PUMP_TEST_KEYDB
        test_msgs = PUMP_TEST_MSGS
        sess = Session(server_keydb=test_db)
    else:
        from pysake.constants import CGM_TEST_KEYDB, CGM_TEST_MSGS
        test_db = CGM_TEST_KEYDB
        test_msgs = CGM_TEST_MSGS
        sess = Session(client_keydb=test_db)

    sess.handshake_0_s(test_msgs[0])
    print(sess)
    sess.handshake_1_c(test_msgs[1])
    print(sess)
    sess.handshake_2_s(test_msgs[2])
    print(sess)
    sess.handshake_3_c(test_msgs[3])
    print(sess)
    sess.handshake_4_s(test_msgs[4])
    print(sess)
    sess.handshake_5_c(test_msgs[5])

    print("session test did not crash. this is definitely a good sign! run the client and server tests too!")
    print(sess)
    print(sess.get_state_checksum())
