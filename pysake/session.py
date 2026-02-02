from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

import logging

from pysake.constants import LOGGER_NAME
from pysake.keys import KeyDatabase
from pysake.seqcrypt import SeqCrypt
from pysake.device_types import DeviceType

class Session():

    # ctor
    client_key_db:KeyDatabase
    server_key_db:KeyDatabase

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
        
        if client_keydb == None and server_keydb == None:
            raise AttributeError("You need to specify at least either the client db or the server db! Cant have both as None!")
        
        if client_keydb is not None:
            self.client_key_db = client_keydb

        if server_keydb is not None:
            self.server_key_db = server_keydb

        # TODO: what happens when both are given?

        self.log = logging.getLogger(LOGGER_NAME).getChild("Session")
        return
    
    # region helpers

    def __check_payload(self, payload, verifier_static_keys, prover_static_keys, prover_device_type:int):

        if prover_static_keys is not None:
            self.log.debug(f"check_payload(): {payload.hex() = }")
            self.log.debug(f"check_payload(): {prover_static_keys.handshake_payload.hex() = }")
            if payload == prover_static_keys.handshake_payload:
                self.log.debug("check_payload(): handshake payload match")
                # TODO add this to return condition??
        
        if verifier_static_keys is not None:
            
            plain = AES.new(verifier_static_keys.permit_decrypt_key, AES.MODE_ECB).decrypt(
                payload
            )
            auth = CMAC.new(verifier_static_keys.permit_auth_key, ciphermod=AES, mac_len=4)
            auth.update(plain[:12])
            self.log.debug(f"check_payload(): {plain[:12].hex() = }")
            self.log.debug(f"check_payload(): {plain[12:].hex() = }")
            auth.verify(plain[12:])
            
            if plain[0] == 0 and plain[1] == prover_device_type:
                self.log.debug("pcheck_payload(): prover device type match")
                return True
        
        return False
     
    @staticmethod
    def _cmac8(client_key_material, server_key_material, derivation_key, handshake_auth_key):
        msg = server_key_material + client_key_material + derivation_key
        assert len(msg) == 32
        cobj = CMAC.new(handshake_auth_key, ciphermod=AES, mac_len=8)
        cobj.update(msg)
        return cobj
    
    @staticmethod
    def _check_len(data:bytes) -> None:
        l = len(data)
        exp = 20
        if l != exp:
            raise ValueError(f"Invalid message length: {l}, expected {exp}!")
        return
    
    # region handshake

    def handshake_0_s(self, msg:bytes):
        self._check_len(msg)
        
        if msg[1] != 1: # TODO: what is this
            raise ValueError
        
        self.server_device_type = DeviceType(msg[0])
        return

    def handshake_1_c(self, msg: bytes):
        self._check_len(msg)

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
        self._check_len(msg)

        
        server_key_material = msg[8:16]
        server_nonce = msg[16:20]
        auth = self._cmac8(
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
       
        self._check_len(msg)

        
        auth1 = self._cmac8(
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
        self._check_len(msg)

        key = AES.new(self.derivation_key, AES.MODE_ECB).encrypt(
            self.server_key_material + self.client_key_material
        )
        nonce = self.client_nonce + self.server_nonce
        self.log.debug(f"handshake_4_s() {nonce.hex() = }")
        self.client_crypt = SeqCrypt(key=key, nonce=nonce, seq=0)
        self.server_crypt = SeqCrypt(key=key, nonce=nonce, seq=1)
        inner = self.server_crypt.decrypt(msg)[:16]
        self.log.debug(f"handshake_4_s() {inner.hex() = }")
        return self.__check_payload(inner, self.client_static_keys, self.server_static_keys, self.server_device_type.value)
        
    def handshake_5_c(self, msg: bytes) -> bool:
        self._check_len(msg)

        inner = self.client_crypt.decrypt(msg)[:-1]
        self.log.debug(f"handshake_5_c(): {inner.hex() = }")
        return self.__check_payload(inner, self.server_static_keys, self.client_static_keys, self.client_device_type.value)


    # region builders

    def build_handshake_2_s(self, server_key_material: bytes, server_nonce: bytes) -> bytes:
        """
        Build the server -> client handshake_2 (20 bytes):
          [0:8]   = CMAC8(handshake_auth_key, server_key_material || client_key_material || derivation_key)
          [8:16]  = server_key_material (8 bytes)
          [16:20] = server_nonce (4 bytes)
        Requires that client_key_material, derivation_key and handshake_auth_key are already set.
        """
        if self.client_key_material is None or self.derivation_key is None or self.handshake_auth_key is None:
            raise ValueError("missing session state for building handshake_2")
        if len(server_key_material) != 8 or len(server_nonce) != 4:
            raise ValueError("server_key_material must be 8 bytes and server_nonce 4 bytes")
        auth = self._cmac8(self.client_key_material, server_key_material, self.derivation_key, self.handshake_auth_key)
        return auth.digest() + server_key_material + server_nonce

    def compute_handshake_3_prefix(self) -> bytes:
        """
        Compute the first 8 bytes of the client -> server handshake_3 message.
        This is the CMAC8 over (auth1.digest() || server_key_material || derivation_key)
        """
        if None in (self.client_key_material, self.server_key_material, self.derivation_key, self.handshake_auth_key):
            raise ValueError("missing session state for computing handshake_3")
        auth1 = self._cmac8(self.client_key_material, self.server_key_material, self.derivation_key, self.handshake_auth_key)
        inner = auth1.digest() + self.server_key_material + self.derivation_key
        auth2 = CMAC.new(self.handshake_auth_key, ciphermod=AES, mac_len=8)
        auth2.update(inner)
        return auth2.digest()

    def build_handshake_3_c(self, filler: bytes | None = None) -> bytes:
        """
        Build a full 20-byte handshake_3 message.
        By protocol only the first 8 bytes are verified; filler fills remaining 12 bytes.
        If filler is None it will be zeroes. Provide filler when replaying captures.
        """
        prefix = self.compute_handshake_3_prefix()
        if filler is None:
            filler = bytes(12)
        if len(filler) != 12:
            raise ValueError("filler must be 12 bytes")
        return prefix + filler

    def build_handshake_5_c(self, payload16: bytes | None = None) -> bytes:
        """Build a client -> server encrypted handshake_5 message.

        The encrypted frame contains 17 bytes of plaintext: the 16-byte payload
        followed by one padding byte (0). If `payload16` is None, and the
        session has `client_static_keys` or `server_static_keys`, the code will
        attempt to use the `handshake_payload` where appropriate; otherwise
        a zeroed 16-byte payload is used.
        """
        if self.client_crypt is None:
            raise ValueError("client_crypt not initialized; call handshake_4_s first")
        if payload16 is None:
            # default payload: try to use prover static payload if available
            if self.client_static_keys is not None:
                payload16 = self.client_static_keys.handshake_payload
            else:
                payload16 = bytes(16)
        if len(payload16) != 16:
            raise ValueError("payload16 must be 16 bytes")
        plaintext = payload16 + b"\x00"
        return self.client_crypt.encrypt(plaintext)
    