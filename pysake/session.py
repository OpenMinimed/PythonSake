from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

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
    server_device_type:DeviceType

    # msg 1
    client_device_type:DeviceType

    client_key_material:bytes
    client_nonce:bytes

    derivation_key:bytes
    handshake_auth_key:bytes

    # msg 2
    server_key_material:bytes
    server_nonce:bytes

    # msg 4
    client_crypt:SeqCrypt
    server_crypt:SeqCrypt

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

    def __check_permit(self, payload, verifier_static_keys, prover_static_keys, prover_device_type:int):

        if prover_static_keys is not None:
            self.log.debug(f"check_permit(): {payload.hex() = }")
            self.log.debug(f"check_permit(): {prover_static_keys.handshake_payload.hex() = }")
            if payload == prover_static_keys.handshake_payload:
                self.log.debug("check_permit(): handshake payload match")
                # TODO add this to return condition??
        
        if verifier_static_keys is not None:
            
            plain = AES.new(verifier_static_keys.permit_decrypt_key, AES.MODE_ECB).decrypt(
                payload
            )
            auth = CMAC.new(verifier_static_keys.permit_auth_key, ciphermod=AES, mac_len=4)
            auth.update(plain[:12])
            self.log.debug(f"check_permit(): {plain[:12].hex() = }")
            self.log.debug(f"check_permit(): {plain[12:].hex() = }")
            auth.verify(plain[12:])
            
            if plain[0] == 0 and plain[1] == prover_device_type:
                self.log.debug("check_permit(): prover device type match")
                return True
        
        return False
     
    @staticmethod
    def cmac8(client_key_material, server_key_material, derivation_key, handshake_auth_key):
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
        self.check_len(msg)
        
        if msg[1] != 1: # TODO: what is this?
            raise ValueError
        
        self.server_device_type = DeviceType(msg[0])
        return

    def handshake_1_c(self, msg: bytes):
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
        return

    def handshake_2_s(self, msg: bytes):
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
        self.server_key_material = server_key_material
        self.server_nonce = server_nonce
        return

    def handshake_3_c(self, msg: bytes):
       
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
        received = msg[:8]
        auth2.verify(received) # this throws!
        self.log.debug("handshake_3_c() verified")
        return
    
    def handshake_4_s(self, msg: bytes) -> bool:
        self.check_len(msg)

        key = AES.new(self.derivation_key, AES.MODE_ECB).encrypt(
            self.server_key_material + self.client_key_material
        )
        nonce = self.client_nonce + self.server_nonce
        self.log.debug(f"handshake_4_s() {nonce.hex() = }")
        self.client_crypt = SeqCrypt(key=key, nonce=nonce, seq=0)
        self.server_crypt = SeqCrypt(key=key, nonce=nonce, seq=1)
        inner = self.server_crypt.decrypt(msg)[:16]
        self.log.debug(f"handshake_4_s() {inner.hex() = }")
        return self.__check_permit(inner, self.client_static_keys, self.server_static_keys, self.server_device_type.value)
        
    def handshake_5_c(self, msg: bytes) -> bool:
        self.check_len(msg)
        self.log.debug(f"handshake_5_c(): arg = {msg.hex()}")
        inner = self.client_crypt.decrypt(msg)[:-1]
        self.log.debug(f"handshake_5_c(): {inner.hex() = }")
        self.log.debug(f"{self.server_static_keys =}, {self.client_static_keys = }, {self.client_device_type = }")
        return self.__check_permit(inner, self.server_static_keys, self.client_static_keys, self.client_device_type.value)

if __name__ == "__main__":

    from pysake.constants import KEYDB_G4_CGM
    import logging
    logging.basicConfig(level=logging.DEBUG)

    sess = Session(client_keydb=KEYDB_G4_CGM)
    sess.handshake_0_s(bytes.fromhex("02015f0edcd0c2af98705bed6c8172856d860402"))
    sess.handshake_1_c(bytes.fromhex("a579868377f401ae083405ef88cc0962d6079a04"))
    sess.handshake_2_s(bytes.fromhex("77f3fb85b079310455fd8f47ddaf81ab49defc7b"))
    sess.handshake_3_c(bytes.fromhex("7f57c1ac4e12d21b46cfaf03f9dbd4877d0a7d76"))
    sess.handshake_4_s(bytes.fromhex("ef54ef03ad398363825fd434e69cd829630056fa"))
    sess.handshake_5_c(bytes.fromhex("2f22c383cf264fa4ebc5b10dc8a2c8a4b000619e"))