from __future__ import annotations

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
from secrets import token_bytes

import logging
import sys

from pysake.session import Session
from pysake.device_types import DeviceType
from pysake.keys import KeyDatabase
from pysake.peer import Peer
from pysake.seqcrypt import SeqCrypt
from pysake.constants import LOGGER_NAME

class SakeServer(Peer):

    """
    Server-side wrapper around Session to drive the handshake state machine.
    """

    def __init__(
        self,
        keydb: KeyDatabase,
        local_device_type: DeviceType = DeviceType.MobileApplication,
    ):
        self.local_device_type = local_device_type
        self.session = Session(server_keydb=keydb)
        self.debug = False
        self.log = logging.getLogger(LOGGER_NAME).getChild(self.__class__.__name__)
        return

    def _build_handshake_2_s(self) -> bytes:
        """
        Build a 20-byte server -> client handshake_2 message.
        Format: 8-byte CMAC prefix || 8-byte server_key_material || 4-byte server_nonce
        """
        if self.session.client_key_material is None or self.session.derivation_key is None or self.session.handshake_auth_key is None:
            raise ValueError("missing session state for computing handshake_2")

        if self.debug:
            from pysake.constants import PUMP_TEST_MSGS
            server_key_material = PUMP_TEST_MSGS[2][8:16]
            server_nonce = PUMP_TEST_MSGS[2][16:20]
        else:
            server_key_material = token_bytes(8)
            server_nonce = token_bytes(4)

        # NOTE: we dont need these, since it is performed by handshake_2_s()
        # self.session.server_key_material = server_key_material
        # self.session.server_nonce        = server_nonce

        # compute auth prefix using same order as Session.cmac8 expects
        auth = self.session.cmac8(self.session.client_key_material, server_key_material, self.session.derivation_key, self.session.handshake_auth_key)
        prefix = auth.digest()
        return prefix + server_key_material + server_nonce

    def _build_handshake_0_s(self) -> bytes:
        """
        Build a 20-byte server -> client handshake_0 message.
        When `debug` is True return the test vector, otherwise construct one.
        """
        if self.debug:
            from pysake.constants import PUMP_TEST_MSGS
            return PUMP_TEST_MSGS[0]
        msg = bytearray(20)
        msg[0] = int(self.local_device_type.value)
        msg[1] = 1
        msg[2:] = token_bytes(18)
        return bytes(msg)

    def _build_handshake_4_s(self) -> bytes:
        """
        Build a server -> client encrypted handshake_4 message.
        Plaintext is server static handshake_payload (16 bytes) + 1 byte filler.
        """
        if None in (self.session.server_key_material, self.session.client_key_material, self.session.derivation_key, self.session.server_static_keys, self.session.client_nonce, self.session.server_nonce):
            raise ValueError("missing session state for computing handshake_4")

        key = AES.new(self.session.derivation_key, AES.MODE_ECB).encrypt(
            self.session.server_key_material + self.session.client_key_material
        )
        
        # NOTE: we do this in session.handshake_3_c() instead
        #nonce = self.session.client_nonce + self.session.server_nonce
        # initialize sequence ciphers (match Session.handshake_4_s behavior)
        #self.session.client_crypt = SeqCrypt(key=key, nonce=nonce, seq=0)
        #self.session.server_crypt = SeqCrypt(key=key, nonce=nonce, seq=1)

        payload16 = self.session.server_static_keys.handshake_payload
        if len(payload16) != 16 or payload16 is None:
            raise ValueError("payload16 must be 16 bytes")

        self.log.debug(f"4_s() payload is {payload16.hex()}")
    
        if self.debug:
            from pysake.constants import PUMP_TEST_MSGS
            i = self._brute_force_ghost_byte(self.session.server_crypt, payload16, PUMP_TEST_MSGS[-2][-4])
            pad = i.to_bytes()
            #pad = b"\x00"
        else:
            pad = b"\x69"

        plaintext = payload16 + pad
        return self.session.server_crypt.encrypt(plaintext)

    def handshake(self, input_data: bytes) -> bytes | None:
        self.session.check_len(input_data)
        toret = None

        log = self.log.getChild("handshake")

        log.debug(f">> {input_data.hex()}")

       # log.debug(self.session)

        if self.get_stage() == 0:

            if input_data != bytes(20):
                raise ValueError("Please start the process with 20 zero bytes")
            self.log.debug(f"stage 0 entry...")
            toret = self._build_handshake_0_s()
            self.session.handshake_0_s(toret)
            self.increment_stage()  # = 1
            log.debug(f"<< {toret.hex()}")
            return toret

        if self.get_stage() == 1:
            self.log.debug(f"stage 1 (and 2) entry...")

            self.session.handshake_1_c(input_data)
            self.increment_stage()  # = 2

            # build and apply handshake_2 (server -> client)
            toret = self._build_handshake_2_s()
            # update session state as if this message was handled
            self.session.handshake_2_s(toret)
            self.increment_stage()  # = 3
            log.debug(f"<< {toret.hex()}")
            return toret

        elif self.get_stage() == 3:

            self.log.debug(f"stage 3 (and 4) entry...")

            # process client's handshake_3
            self.session.handshake_3_c(input_data)
            self.increment_stage()  # = 4

            # build handshake_4 (server -> client)
            toret = self._build_handshake_4_s()

            # DO NOT call this, we only need to verify the payload in 5_c(): 
            # self.session._create_crypts()
            #self.session.handshake_4_s(toret)

            self.increment_stage()  # = 5
            log.debug(f"<< {toret.hex()}")
            return toret

        elif self.get_stage() == 5:
            # final client message 5 arrives; verify
            ok = self.session.handshake_5_c(input_data)
            if not ok:
                raise RuntimeError("permit failure")                
            self.increment_stage()
            return None

        raise Exception("Handshake should be already done?! what are you doing here")


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    from pysake.constants import PUMP_TEST_MSGS, PUMP_TEST_KEYDB

    server = SakeServer(PUMP_TEST_KEYDB)
    server.debug = True

    # trigger msg0 generation
    out0 = server.handshake(bytes(20))
    print(f"stage # {server.get_stage()}: out0 = {out0.hex()}")

    last_valid_out = None
    for m in [PUMP_TEST_MSGS[1], PUMP_TEST_MSGS[3], PUMP_TEST_MSGS[5]]:
        out = server.handshake(m)
        out_text = out.hex() if out is not None else "<NONE>"
        if out is not None:
            last_valid_out = out
        print(f"stage # {server.get_stage()}: in = {m.hex()}, out = {out_text}")
    
    if last_valid_out == PUMP_TEST_MSGS[4]:
        print("test passed")
        print(server.session)
        print(server.session.get_state_checksum())

    else:
        print(f"test failed: {last_valid_out.hex()} vs {PUMP_TEST_MSGS[4].hex()}")