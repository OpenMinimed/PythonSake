from __future__ import annotations

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
from secrets import token_bytes

from binascii import hexlify

from pysake.session import Session
from pysake.device_types import DeviceType
from pysake.keys import KeyDatabase
from pysake.peer import Peer
from pysake.constants import LOGGER_NAME

class SakeClient(Peer):

    """
    Client-side wrapper around Session to drive the handshake state machine.
    """

    def __init__(
        self,
        keydb:KeyDatabase,
        local_device_type:DeviceType = DeviceType.PrimaryDisplay,
    ):
        self.local_device_type = local_device_type
        self.session = Session(client_keydb=keydb)
        self.debug = False
        self.log = logging.getLogger(LOGGER_NAME).getChild(self.__class__.__name__)
        return
    
    def _build_handshake_1_c(self) -> bytes:
        
        if self.debug:
            from pysake.constants import CGM_TEST_MSGS
            key = CGM_TEST_MSGS[1][0:8]
            nonce = CGM_TEST_MSGS[1][9:13]
        else:
            key = token_bytes(8)
            nonce = token_bytes(4)

        self.session.client_key_material = key
        self.session.client_nonce = nonce
        self.session.client_device_type = self.local_device_type
        msg = bytearray(20)
        msg[0:8] = self.session.client_key_material
        msg[8] = self.session.client_device_type
        msg[9:13] = self.session.client_nonce
        return bytes(msg)
    
    def _build_handshake_3_c(self, ) -> bytes:
        """
        Build a full 20-byte handshake_3 message.
        By protocol only the first 8 bytes are used; filler fills remaining 12 bytes.
        """

        if None in (self.session.client_key_material, self.session.server_key_material, self.session.derivation_key, self.session.handshake_auth_key):
            raise ValueError("missing session state for computing handshake_3")
        
        # calc mac0
        auth1 = self.session.cmac8(self.session.client_key_material, self.session.server_key_material, self.session.derivation_key, self.session.handshake_auth_key)
        inner = auth1.digest() + self.session.server_key_material + self.session.derivation_key
        auth2 = CMAC.new(self.session.handshake_auth_key, ciphermod=AES, mac_len=8)
        auth2.update(inner)
        prefix = auth2.digest()

        if self.debug:
            filler = bytes(12) # just be predictable
        else:
            filler = token_bytes(12)

        return prefix + filler
    
    def _build_handshake_5_c(self) -> bytes:
        """
        Build a client -> server encrypted handshake_5 message.
        """
        if self.session.client_crypt is None:
            raise ValueError("client_crypt not initialized; call handshake_4_s first")
        
        # if something is None we crash
        payload16 = self.session.client_static_keys.handshake_payload
                
        if len(payload16) != 16 or payload16 is None:
            raise ValueError("payload16 must be 16 bytes")
        
        if self.debug:
            from pysake.constants import CGM_TEST_MSGS
            expected = CGM_TEST_MSGS[-1][-4]
            i = self._brute_force_ghost_byte(self.session.client_crypt, payload16, expected)
            pad = i.to_bytes()
        else:
            pad = b"\x00"

        plaintext = payload16 + pad
        return self.session.client_crypt.encrypt(plaintext)
 

    def handshake(self, input_data: bytes) -> bytes|None:        
        self.session.check_len(input_data)
        toret = None

        if self.get_stage() == 0:

            self.session.handshake_0_s(input_data)
            self.increment_stage() # = 1

            toret = self._build_handshake_1_c()
            self.session.handshake_1_c(toret)
            self.increment_stage() # = 2

        elif self.get_stage() == 2:
            self.session.handshake_2_s(input_data)
            self.increment_stage() # = 3

            toret = self._build_handshake_3_c()
            self.session.handshake_3_c(toret)
            self.increment_stage() # = 4

        elif self.get_stage() == 4:
            ok = self.session.handshake_4_s(input_data)
            if not ok:
                raise RuntimeError("permit failure")
            self.increment_stage() # = 5

            toret = self._build_handshake_5_c()

            # DO NOT call this when we are a client!
            # we have already sent it and it shall be performed by the server
            # self.session.handshake_5_c(toret)

            self.increment_stage() # = 6

        return toret


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG)
  
    from pysake.constants import CGM_TEST_KEYDB, CGM_TEST_MSGS

    client = SakeClient(CGM_TEST_KEYDB)
    client.debug = True

    for m in [CGM_TEST_MSGS[0], CGM_TEST_MSGS[2], CGM_TEST_MSGS[4]]:
        out = client.handshake(m)
        print(f"stage # {client.get_stage()}: in = {m.hex()}, out = {out.hex()}")
    
    print(out.hex())
    if out == CGM_TEST_MSGS[-1]:
        print("test passes!")
    else:
        print("test failed")