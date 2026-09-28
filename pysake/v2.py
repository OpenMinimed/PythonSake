from __future__ import annotations

import hmac
import hashlib
import logging

import srp

from pysake.constants import LOGGER_NAME
from pysake.peer import Peer
from pysake.seqcrypt import SeqCrypt

# protocol-version 2 (passkey / SRP-6a) selects this path, see SakeLibraryRE
# README section 24/25.
#
# STATUS (validated against libandroid-sake-lib_v260.so via live ARM
# emulation and disassembly in this session -- see
# tools/sake_v260_emulate/ and the commit that added this comment):
#
#   VERIFIED from real disassembly (SRPClient_Step @ 0x19184,
#   SRPServer_Step @ 0x197f0, SRPServer_Init @ 0x19568):
#     - message framing IS payload + u32 LE length at a fixed +0x50
#       offset (matches this file's frame-byte approach, minus the type
#       byte -- see below)
#     - the "kick" that starts SRPClient_Step is 16 bytes, not 20
#       (0x10 checked at SRPClient_Step state 1) -- the 20-zero-byte
#       trigger this file uses is a *GATT-level* convention carried
#       over from the v1 protocol and is never fed into the real SRP
#       code, so it does not need to match
#     - public values A and B are each exactly 64 bytes on the wire
#       (hardcoded 0x40, not derived from the actual export length),
#       i.e. the real group is a *custom ~512-bit* modulus -- NOT the
#       128-byte/1024-bit RFC5054-style group this file assumed
#       (srp.NG_1024). No 1024-bit standard group ever produces a
#       64-byte public value, so the old FRAME_PUB_A/B "(128 bytes)"
#       comments and _VALUE_WIDTH=128 below were simply wrong.
#     - the proof messages M1/M2 are 32 bytes, and there's a 1-byte
#       status message after -- matches this file's FRAME_PROOF/
#       FRAME_STATUS already.
#
#   NOT YET RECOVERED -- and the reason a generic SRP library (this
#   file's approach) cannot actually interoperate with a real pump,
#   even after fixing the group size:
#     - the real modulus N and generator g bytes. SRPClient_Init only
#       ever calls BignumCtx_SetDataField() with an *empty* string, so
#       N/g are not a simple embedded ASCII/byte constant at a fixed
#       offset findable by string search; they get populated lazily
#       through a chain of bignum-init calls that this session's ARM
#       emulation harness (tools/sake_v260_emulate/) does not yet get
#       through cleanly (a realloc() call deep inside a nested
#       SRP_BignumCtx_Init -> SRP_HashToBignum -> BN_Grow chain reads
#       what looks like an uninitialized/garbage pointer -- harness
#       bug, not a property of the real library, which of course works
#       fine on-device).
#     - the exact `x` (SRP private exponent) derivation. On real
#       SRPClient_Step state 1, `x` comes from
#       SRP_HashToBignum(ctx, <128-byte embedded constant>, 0x80,
#                         <1-byte embedded constant>, 1,
#                         <16-byte kick input>, 0x10)
#       i.e. it is NOT simply H(salt || passkey) the way vanilla SRP-6a
#       (and this file, via python-srp) computes it. The two embedded
#       constants above are not yet extracted either. The *passkey*
#       itself only enters afterwards, via a separate
#       SRP_GenVerifierClient() call. Because of this, plugging the
#       real N/g into python-srp (e.g. via srp.NG_CUSTOM) would still
#       not produce byte-compatible messages with a real pump -- the
#       whole x/verifier construction needs a bespoke reimplementation,
#       or the SAKE v2 handshake needs to be run through the real
#       native library directly (see tools/sake_v260_emulate/).
#
# Given the above, this module is kept as a self-consistent (client
# talks only to server, both in this same process) protocol-shaped
# demo/testbed, NOT a validated implementation of the real pump
# protocol. Do not expect it to pair with an actual device.

# default passkey used when none is supplied (hardcoded for testing)
TEST_PASSKEY = 123456

# SRP group / hash
#
# PLACEHOLDER ONLY: this is a standard 1024-bit RFC5054-style group,
# picked purely so the self-consistent demo below has *some* working
# group. It is confirmed (see status block above) to NOT be the real
# pump's group, which uses 64-byte (~512-bit) public values.
_NG = srp.NG_1024
_HASH = srp.SHA256

# frame type bytes
FRAME_PUB_A    = 0x01  # client public value A -- verified 64 bytes on the real pump, but see _VALUE_WIDTH note
FRAME_PUB_B    = 0x02  # salt (16, verified) || server pub B (64 bytes on the real pump)
FRAME_PROOF    = 0x03  # SRP proof M1 / M2 (32 bytes, verified)
FRAME_STATUS   = 0x05  # status byte (0x04 = success, verified: SRP state 4 "emit success, byteCount=1, out[0]=4")

_STATUS_OK = 0x04  # per v260 SRP state 4: "emit success (byteCount=1, out[0]=4)"

# Fixed width in bytes of the serialized SRP values for the PLACEHOLDER
# group above (_NG = NG_1024, whose public values ARE 128 bytes). This is
# deliberately kept consistent with _NG for the self-test to work; it does
# NOT reflect the real pump's verified 64-byte public value width, since
# that requires the real (unknown) group, not a same-sized substitute --
# python-srp ties the public-value width to N's bit length, so there is no
# way to get 64-byte values out of it without the real N.
_VALUE_WIDTH = 128


class Passkey:
    """
    Mirror of SAKE_PASSKEY_S (20 bytes): up to 16-byte passkey + byteCount.
    """

    _capacity = 16

    def __init__(self, data: bytes):
        if len(data) > self._capacity:
            raise ValueError(f"passkey too long: {len(data)} > {self._capacity}")
        self.pBytes = bytes(data)
        self.byteCount = len(data)
        return

    @classmethod
    def from_integer(cls, value: int) -> "Passkey":
        """Big-endian 4-byte passkey, like SakePasskey_FromInteger."""
        return cls(value.to_bytes(4, "big"))

    def __bytes__(self) -> bytes:
        return self.pBytes

    def __repr__(self) -> str:
        return f"Passkey(pBytes={self.pBytes.hex()}, byteCount={self.byteCount})"


def _pad(value: int) -> bytes:
    return value.to_bytes(_VALUE_WIDTH, "big")


def _unpad(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _frame(t: int, payload: bytes) -> bytes:
    return bytes([t]) + payload


def _split_frame(msg: bytes) -> tuple[int, bytes]:
    if len(msg) < 1:
        raise ValueError("empty v2 frame")
    return msg[0], msg[1:]


def _status_frame(code: int) -> bytes:
    return _frame(FRAME_STATUS, bytes([code]))


class V2Session:
    """
    v2 counterpart of Session: drives the SRP-6a passkey handshake on either
    side and exposes the derived secure-link crypts like the v1 session does.
    """

    def __init__(self, passkey: Passkey):
        self.log = logging.getLogger(LOGGER_NAME).getChild("V2Session")
        self.passkey = passkey

        self.username = ""  # no username in x (see srp.no_username_in_x)
        self.password = bytes(passkey)

        self.salt: bytes = None
        self.verifier: bytes = None

        self.client_pub: bytes = None  # A
        self.server_pub: bytes = None  # B
        self.client_proof: bytes = None  # M1
        self.server_proof: bytes = None  # M2

        self.client_crypt: SeqCrypt = None
        self.server_crypt: SeqCrypt = None
        return

    #region SRP client role

    def client_init(self) -> bytes:
        self._user = srp.User(self.username, self.password, _HASH, _NG)
        _, a = self._user.start_authentication()
        self.client_pub = a
        self.log.debug(f"client pub A = {a.hex()}")
        return _frame(FRAME_PUB_A, a)

    def client_process_b(self, msg: bytes) -> bytes:
        t, payload = _split_frame(msg)
        if t != FRAME_PUB_B:
            raise ValueError(f"expected FRAME_PUB_B, got 0x{t:02x}")
        salt, b = payload[:16], payload[16:]
        self.salt = salt
        self.server_pub = b
        self.log.debug(f"client got salt = {salt.hex()}, pub B = {b.hex()}")
        self.client_proof = self._user.process_challenge(salt, b)
        if self.client_proof is None:
            raise ValueError("SRP-6a safety check failed in process_challenge")
        self.log.debug(f"client proof M1 = {self.client_proof.hex()}")
        return _frame(FRAME_PROOF, self.client_proof)

    def client_verify_server_proof(self, msg: bytes) -> bytes:
        t, payload = _split_frame(msg)
        if t != FRAME_PROOF:
            raise ValueError(f"expected FRAME_PROOF, got 0x{t:02x}")
        self.server_proof = payload
        self._user.verify_session(self.server_proof)
        if not self._user.authenticated:
            raise ValueError("server proof M2 verification failed")
        self.log.debug("client verified server proof M2")
        self._derive_crypts()
        return _status_frame(_STATUS_OK)

    #endregion

    #region SRP server role

    def server_init(self) -> bytes:
        # the server provisions the (salt, verifier) from the shared passkey
        self.salt, self.verifier = srp.create_salted_verification_key(
            self.username, self.password, _HASH, _NG, salt_len=16,
        )
        self._verifier = srp.Verifier(
            self.username, self.salt, self.verifier,
            hash_alg=_HASH, ng_type=_NG,
        )
        b = self._verifier.get_challenge()[1]
        self.server_pub = b
        self.log.debug(f"server salt = {self.salt.hex()}, pub B = {b.hex()}")
        return _frame(FRAME_PUB_B, self.salt + b)

    def server_process_a(self, msg: bytes) -> bytes:
        t, payload = _split_frame(msg)
        if t != FRAME_PUB_A:
            raise ValueError(f"expected FRAME_PUB_A, got 0x{t:02x}")
        self.client_pub = payload
        self.log.debug(f"server got pub A = {payload.hex()}")
        # pub A consumed; the server proof is sent once M1 arrives
        return None

    def server_verify_client_proof(self, msg: bytes) -> bytes:
        t, payload = _split_frame(msg)
        if t != FRAME_PROOF:
            raise ValueError(f"expected FRAME_PROOF, got 0x{t:02x}")
        self.client_proof = payload
        m2 = self._verifier.verify_session(self.client_proof, self.client_pub)
        if m2 is None:
            raise ValueError("client proof M1 verification failed")
        self.server_proof = m2
        self.log.debug(f"server proof M2 = {m2.hex()}")
        self._derive_crypts()
        return _frame(FRAME_PROOF, m2)

    def server_consume_status(self, msg: bytes) -> None:
        t, payload = _split_frame(msg)
        if t != FRAME_STATUS:
            raise ValueError(f"expected FRAME_STATUS, got 0x{t:02x}")
        if payload != bytes([_STATUS_OK]):
            raise ValueError(f"client reported handshake failure, status=0x{payload[0]:02x}")
        self.log.debug("server confirmed client success")
        return

    #endregion

    #region session keys

    def _derive_crypts(self):
        """
        Derive the AES-CTR + CMAC secure-link state from the SRP session key.

        Theorized KDF (mirrors the v260 PRF_ExpandCounterLoop): the SRP
        session key K = SHA256(S) seeds a counter-mode HMAC expansion that
        yields the two per-direction SeqCrypt keys plus their 8-byte nonce.
        """
        k = self._session_key()
        if k is None:
            raise ValueError("no authenticated SRP session key available")
        material = b""
        prev = b""
        i = 1
        while len(material) < 40:
            prev = hmac.new(k, bytes([i]) + prev, hashlib.sha256).digest()
            material += prev
            i += 1
        client_key = material[0:16]
        server_key = material[16:32]
        nonce = material[32:40]
        self.client_crypt = SeqCrypt(key=client_key, nonce=nonce, seq=0)
        self.server_crypt = SeqCrypt(key=server_key, nonce=nonce, seq=1)
        self.log.debug(f"derived client_crypt key={client_key.hex()}, nonce={nonce.hex()}")
        return

    def _session_key(self) -> bytes | None:
        if hasattr(self, "_user"):
            return self._user.get_session_key()
        return self._verifier.get_session_key()

    #endregion


class SakeV2Server(Peer):
    """
    Server-side v2 handshake driver. Interface-compatible with the v1
    SakeServer (handshake(), get_stage(), is_done()) but runs the
    passkey / SRP-6a flow instead of the challenge/CMAC flow.
    """

    def __init__(self, passkey: Passkey | int | None = None):
        if passkey is None:
            self.log = logging.getLogger(LOGGER_NAME).getChild("SakeV2Server")
            self.log.warning(f"no passkey given, using hardcoded test passkey {TEST_PASSKEY}")
            passkey = TEST_PASSKEY
        if isinstance(passkey, int):
            passkey = Passkey.from_integer(passkey)
        self.passkey = passkey
        self.session = V2Session(passkey)
        self.log = logging.getLogger(LOGGER_NAME).getChild("SakeV2Server")
        return

    def handshake(self, input_data: bytes) -> bytes | None:
        log = self.log.getChild("handshake")
        log.debug(f">> {input_data.hex()}")
        toret = None

        if self.get_stage() == 0:
            # optional v1-style kick; consume silently, no reply
            if input_data == bytes(20):
                self.log.debug("consumed handshake kick")
                return None
            toret = self.session.server_init()
            self.session.server_process_a(input_data)
            self.increment_stage()  # = 1
        elif self.get_stage() == 1:
            toret = self.session.server_verify_client_proof(input_data)
            self.increment_stage()  # = 2
        elif self.get_stage() == 2:
            self.session.server_consume_status(input_data)
            self.increment_stage()  # = 3
        else:
            raise RuntimeError("v2 handshake already completed")

        log.debug(f"<< {toret.hex() if toret is not None else 'None'}")
        return toret

    def is_done(self) -> bool:
        return self.get_stage() == 3


class SakeV2Client(Peer):
    """
    Client-side v2 handshake driver. Interface-compatible with the v1
    SakeClient but runs the passkey / SRP-6a flow.
    """

    def __init__(self, passkey: Passkey | int | None = None):
        if passkey is None:
            self.log = logging.getLogger(LOGGER_NAME).getChild("SakeV2Client")
            self.log.warning(f"no passkey given, using hardcoded test passkey {TEST_PASSKEY}")
            passkey = TEST_PASSKEY
        if isinstance(passkey, int):
            passkey = Passkey.from_integer(passkey)
        self.passkey = passkey
        self.session = V2Session(passkey)
        self.log = logging.getLogger(LOGGER_NAME).getChild("SakeV2Client")
        return

    def handshake(self, input_data: bytes) -> bytes | None:
        log = self.log.getChild("handshake")
        log.debug(f">> {input_data.hex()}")
        toret = None

        if self.get_stage() == 0:
            if input_data != bytes(20):
                raise ValueError("please start the process with 20 zero bytes")
            toret = self.session.client_init()
            self.increment_stage()  # = 1
        elif self.get_stage() == 1:
            toret = self.session.client_process_b(input_data)
            self.increment_stage()  # = 2
        elif self.get_stage() == 2:
            toret = self.session.client_verify_server_proof(input_data)
            self.increment_stage()  # = 3
        else:
            raise RuntimeError("v2 handshake already completed")

        log.debug(f"<< {toret.hex() if toret is not None else 'None'}")
        return toret

    def is_done(self) -> bool:
        return self.get_stage() == 3


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG)

    server = SakeV2Server()
    client = SakeV2Client()

    # optional kick consumed silently by the server, like the connector sends it
    assert server.handshake(bytes(20)) is None

    a = client.handshake(bytes(20))
    print(f"client stage {client.get_stage()}: out A   = {a.hex()}")

    b = server.handshake(a)
    print(f"server stage {server.get_stage()}: out B   = {b.hex()}")

    m1 = client.handshake(b)
    print(f"client stage {client.get_stage()}: out M1  = {m1.hex()}")

    m2 = server.handshake(m1)
    print(f"server stage {server.get_stage()}: out M2  = {m2.hex()}")

    status = client.handshake(m2)
    print(f"client stage {client.get_stage()}: out OK  = {status.hex()}")

    done = server.handshake(status)
    print(f"server stage {server.get_stage()}: out     = {done}")

    assert client.is_done() and server.is_done(), "both sides must be done"
    assert server.session.client_crypt is not None
    assert server.session.server_crypt is not None
    print("v2 handshake succeeded")
