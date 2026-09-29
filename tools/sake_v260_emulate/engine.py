"""
Persistent, connector-callable wrapper around the real libandroid-sake-lib.so
(v260) protocol-v2 (passkey/SRP-6a) client and server, running inside the
Unicorn-based harness in harness.py.

This is the API `PythonPumpConnector`'s `ble/sake.py` should call into for
`--sake-v2` instead of the retired `pysake.v2.SakeV2Server`. Every crypto
operation (SRP-6a, the KDF, the permit AES-ECB/CMAC exchange, the secure-link
cipher) is whatever the real library computes -- there is no separate,
hand-rolled formula to get wrong.

Addresses below are specific to the v260 armeabi-v7a build this harness maps
(see README.md) and were confirmed via Ghidra + live instrumentation, not
guessed from decompiler pseudocode alone (which repeatedly misread this
library's NEON/struct-return calling convention -- see README.md's "Solving
the permit exchange" section for the concrete case).
"""
import struct

import harness as h

uc, call, heap_alloc = h.uc, h.call, h.heap_alloc

# Sake_Client_Init, Sake_Client_Handshake
_ADDR_CLIENT_INIT = 0x1612e
_ADDR_CLIENT_HANDSHAKE = 0x165a4
_CLIENT_MEMORY_SIZE, _CLIENT_SIZE = 952, 124
_CLIENT_OFF_STATE = 0
_CLIENT_OFF_SECURE_LINK = 64
_CLIENT_OFF_IS_SECURE_LINK_ESTABLISHED = 112
_CLIENT_OFF_LAST_ERROR = 120
_CLIENT_OFF_KEYDATABASE = 56

# Sake_Server_Init, Sake_Server_Handshake
_ADDR_SERVER_INIT = 0x17036
_ADDR_SERVER_HANDSHAKE = 0x175e8
_SERVER_MEMORY_SIZE, _SERVER_SIZE = 948, 172
_SERVER_OFF_STATE = 0
_SERVER_OFF_SECURE_LINK = 112
_SERVER_OFF_IS_SECURE_LINK_ESTABLISHED = 160
_SERVER_OFF_LAST_ERROR = 168
_SERVER_OFF_KEYDATABASE = 104

# SakeKeyDB_CreateDatabase, SakeKeyDB_ResetAndRecomputeCRC
_ADDR_KEYDB_CREATE = 0x16d76
_ADDR_KEYDB_RECOMPUTE_CRC = 0x16c2c
_KEYDB_ENTRY_SIZE = 0x51  # 1 type byte + 80 bytes of material

# SakeCrypto_AES_ECB_EncryptBlock, SakeCrypto_VerifyMessageHF
_ADDR_AES_ECB_ENCRYPT = 0x17e0c
_ADDR_VERIFY_MESSAGE_HF = 0x17cb0

# post-handshake secure-message encrypt/decrypt over the established secure
# link (client+0x40 / server+0x40 is the persisted SakeCrypto cipher state,
# i.e. exactly pSecureLink -- confirmed by disassembling the JNI wrappers'
# targets, which is also where MAX_SAKE_USER_MESSAGE_BYTE_COUNT's 0x4d-byte
# cap on the plaintext size comes from, per FUN_000169e0's own check)
_ADDR_CLIENT_SECURE_FOR_SENDING = 0x16668
_ADDR_CLIENT_UNSECURE_AFTER_RECEIVING = 0x1667a
_ADDR_SERVER_SECURE_FOR_SENDING = 0x176a4
_ADDR_SERVER_UNSECURE_AFTER_RECEIVING = 0x176b6

RET_ERROR = 0  # from earlier drives: not actually observed as a *first* return; kept for completeness
RET_DONE = 0
RET_FAILED = 1
RET_CONTINUE = 2

SAKE_HANDSHAKE_NO_ERROR = 0
SAKE_HANDSHAKE_ERROR_PERMIT_RECEIVED_INVALID = 18


class SakeHandshakeFailed(RuntimeError):
    def __init__(self, side, last_error):
        super().__init__(f"{side} SAKE v2 handshake failed, lastError={last_error}")
        self.side = side
        self.last_error = last_error


class SakeSecureMessageFailed(RuntimeError):
    pass


def _mk_msg(payload: bytes = b""):
    buf = heap_alloc(0x60)
    if payload:
        uc.mem_write(buf, payload)
    uc.mem_write(buf + 0x50, struct.pack("<I", len(payload)))
    return buf


def _msg_bytes(buf) -> bytes:
    n = struct.unpack("<I", bytes(uc.mem_read(buf + 0x50, 4)))[0]
    return bytes(uc.mem_read(buf, n))


def _mk_passkey(passkey: int):
    buf = heap_alloc(20)
    b = passkey.to_bytes(4, "big")
    uc.mem_write(buf, b + b"\x00" * 12)
    uc.mem_write(buf + 16, struct.pack("<I", 4))
    return buf


def aes_ecb_encrypt(plaintext16: bytes, key16: bytes) -> bytes:
    """Encrypt one 16-byte block with the real library's AES-128-ECB."""
    assert len(plaintext16) == 16 and len(key16) == 16
    kbuf = heap_alloc(16)
    uc.mem_write(kbuf, key16)
    pbuf = heap_alloc(16)
    uc.mem_write(pbuf, plaintext16)
    obuf = heap_alloc(16)
    uc.mem_write(obuf, bytes(16))
    call(_ADDR_AES_ECB_ENCRYPT, [kbuf, pbuf, obuf])
    return bytes(uc.mem_read(obuf, 16))


def verify_message_hf(key16: bytes, data12: bytes) -> bytes:
    """
    Run the real library's SakeCrypto_VerifyMessageHF (a CMAC-style MAC over
    `data12` under `key16`) and return its 16-byte output. Used to build the
    permit's embedded checksum -- see build_permit_plaintext().
    """
    assert len(key16) == 16 and len(data12) == 12
    kbuf = heap_alloc(16)
    uc.mem_write(kbuf, key16)
    dbuf = heap_alloc(12)
    uc.mem_write(dbuf, data12)
    obuf = heap_alloc(16)
    uc.mem_write(obuf, bytes(16))
    r = call(_ADDR_VERIFY_MESSAGE_HF, [kbuf, dbuf, 12, obuf])
    if r == 0:
        raise RuntimeError("SakeCrypto_VerifyMessageHF operation failed")
    return bytes(uc.mem_read(obuf, 16))


def build_permit_plaintext(device_type: int, mac_key16: bytes, proprietary10: bytes = None) -> bytes:
    """
    Build the 16-byte "permit" plaintext block embedded (AES-ECB-encrypted,
    then wrapped again under the session cipher) in the last message of the
    handshake, proving the sender knows the pre-shared identity secret for
    this device-type pair.

    Layout (confirmed via live instrumentation of
    SakeClient_DecryptValidateServerPermitHF -- see README.md):
      byte 0      : 0x00 (a "status" byte the receiver requires to be zero)
      byte 1      : device type of the SENDER (validated against
                    SakeError_IsValidCode / the receiver's expected type)
      bytes 2:12  : "proprietary bytes" (10 bytes, receiver doesn't validate
                    their content, just stores them)
      bytes 12:16 : self-consistency checksum -- must equal the first 4
                    bytes of SakeCrypto_VerifyMessageHF(mac_key16, bytes0:12)
    """
    if proprietary10 is None:
        proprietary10 = bytes(10)
    assert len(proprietary10) == 10
    content = bytes([0, device_type]) + proprietary10
    tag = verify_message_hf(mac_key16, content)[:4]
    return content + tag


def build_permit_key_material(decrypt_key16: bytes, mac_key16: bytes, outgoing_permit_ciphertext16: bytes) -> bytes:
    """
    Build the 80-byte key-database entry material for one peer device type.

    decrypt_key16: AES-128 key this side uses to decrypt an INCOMING permit
      from that peer (must equal the key the peer used to encrypt its
      outgoing permit -- i.e. this side's decrypt_key16 == peer's "encrypt
      key" for messages addressed to this side).
    mac_key16: key used to validate the self-consistency checksum of an
      INCOMING permit from that peer.
    outgoing_permit_ciphertext16: AES_ECB_Encrypt(this side's own permit
      plaintext, using the PEER's decrypt key) -- what gets embedded as
      this side's own outgoing permit payload when it sends its handshake
      finalize message.

    Byte layout (offsets confirmed via Ghidra's SAKE_KEY_DATABASE struct +
    live instrumentation):
      [0:32]  unused by the protocol-v2 permit path (kept zero)
      [32:48] decrypt_key16
      [48:64] mac_key16
      [64:80] outgoing_permit_ciphertext16
    """
    assert len(decrypt_key16) == 16 and len(mac_key16) == 16 and len(outgoing_permit_ciphertext16) == 16
    return bytes(32) + decrypt_key16 + mac_key16 + outgoing_permit_ciphertext16


def _secure_op(addr, struct_ptr, data: bytes) -> bytes:
    inp = _mk_msg(data)
    out = _mk_msg()
    r = call(addr, [struct_ptr, inp, out])
    if r == 0:
        raise SakeSecureMessageFailed("secure-message operation failed")
    return _msg_bytes(out)


def build_key_database(own_type: int, peer_type: int, material_80b: bytes):
    """
    Allocate and populate a SAKE_KEY_DATABASE_S with a single remote-device
    entry, matching exactly what the real FUN_00016dba (the native backer of
    Sake_KeyDatabase_AddRemoteDeviceKey) writes -- confirmed via decompile,
    not assumed. Returns the database buffer's address.
    """
    assert len(material_80b) == 80
    bufsize = 6 + _KEYDB_ENTRY_SIZE
    buf = heap_alloc(bufsize)
    handle = heap_alloc(8)
    call(_ADDR_KEYDB_CREATE, [handle, own_type, buf, bufsize])
    entry = bytes([peer_type]) + material_80b
    uc.mem_write(buf + 6, entry)
    uc.mem_write(buf + 5, bytes([1]))  # entry count = 1
    call(_ADDR_KEYDB_RECOMPUTE_CRC, [handle])
    return buf


class SakeV2Client:
    def __init__(self, passkey: int, key_database_addr: int):
        self._memory = heap_alloc(_CLIENT_MEMORY_SIZE)
        self._struct = heap_alloc(_CLIENT_SIZE)
        call(_ADDR_CLIENT_INIT, [self._struct, self._memory, _mk_passkey(passkey)])
        uc.mem_write(self._struct + _CLIENT_OFF_KEYDATABASE, struct.pack("<I", key_database_addr))

    def step(self, incoming: bytes = None) -> bytes:
        """
        Feed one incoming message (None to kick off the handshake) and
        return the reply to send back, or None if the handshake is done and
        no further reply is needed. Raises SakeHandshakeFailed on failure.
        """
        inp = _mk_msg(incoming) if incoming is not None else 0
        out = _mk_msg()
        ret = call(_ADDR_CLIENT_HANDSHAKE, [self._struct, inp, out])
        if ret == RET_FAILED:
            raise SakeHandshakeFailed("client", self.last_error)
        reply = _msg_bytes(out)
        return reply if reply else None

    @property
    def is_done(self) -> bool:
        return bool(uc.mem_read(self._struct + _CLIENT_OFF_IS_SECURE_LINK_ESTABLISHED, 1)[0])

    @property
    def last_error(self) -> int:
        return struct.unpack("<I", bytes(uc.mem_read(self._struct + _CLIENT_OFF_LAST_ERROR, 4)))[0]

    @property
    def secure_link(self) -> bytes:
        return bytes(uc.mem_read(self._struct + _CLIENT_OFF_SECURE_LINK, 48))

    def secure_for_sending(self, plaintext: bytes) -> bytes:
        """Encrypt+sign a post-handshake message to send to the server."""
        return _secure_op(_ADDR_CLIENT_SECURE_FOR_SENDING, self._struct, plaintext)

    def unsecure_after_receiving(self, ciphertext: bytes) -> bytes:
        """Decrypt+verify a post-handshake message received from the server."""
        return _secure_op(_ADDR_CLIENT_UNSECURE_AFTER_RECEIVING, self._struct, ciphertext)


class SakeV2Server:
    def __init__(self, passkey: int, key_database_addr: int):
        self._memory = heap_alloc(_SERVER_MEMORY_SIZE)
        self._struct = heap_alloc(_SERVER_SIZE)
        call(_ADDR_SERVER_INIT, [self._struct, self._memory, _mk_passkey(passkey)])
        uc.mem_write(self._struct + _SERVER_OFF_KEYDATABASE, struct.pack("<I", key_database_addr))

    def step(self, incoming: bytes = None) -> bytes:
        inp = _mk_msg(incoming) if incoming is not None else 0
        out = _mk_msg()
        ret = call(_ADDR_SERVER_HANDSHAKE, [self._struct, inp, out])
        if ret == RET_FAILED:
            raise SakeHandshakeFailed("server", self.last_error)
        reply = _msg_bytes(out)
        return reply if reply else None

    @property
    def is_done(self) -> bool:
        return bool(uc.mem_read(self._struct + _SERVER_OFF_IS_SECURE_LINK_ESTABLISHED, 1)[0])

    @property
    def last_error(self) -> int:
        return struct.unpack("<I", bytes(uc.mem_read(self._struct + _SERVER_OFF_LAST_ERROR, 4)))[0]

    @property
    def secure_link(self) -> bytes:
        return bytes(uc.mem_read(self._struct + _SERVER_OFF_SECURE_LINK, 48))

    def secure_for_sending(self, plaintext: bytes) -> bytes:
        """Encrypt+sign a post-handshake message to send to the client."""
        return _secure_op(_ADDR_SERVER_SECURE_FOR_SENDING, self._struct, plaintext)

    def unsecure_after_receiving(self, ciphertext: bytes) -> bytes:
        """Decrypt+verify a post-handshake message received from the client."""
        return _secure_op(_ADDR_SERVER_UNSECURE_AFTER_RECEIVING, self._struct, ciphertext)
