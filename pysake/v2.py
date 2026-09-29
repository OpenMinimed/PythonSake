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
# STATUS (validated against libandroid-sake-lib_v260.so via a working live
# ARM emulation harness -- see tools/sake_v260_emulate/, whose
# SRPClient_Init/SRPClient_Step run the real code end-to-end successfully):
#
#   CONFIRMED, by directly running the real code and reading back the
#   populated bignums (not guessed, not inferred from disassembly alone):
#
#     - N and g ARE the standard RFC5054 1024-bit SRP group -- i.e.
#       srp.NG_1024 below was, by luck, already the right choice. Verified
#       two ways: (1) a 128-byte embedded constant the real code loads
#       matches the RFC5054 N byte-for-byte; (2) after running
#       SRPClient_Init+SRPClient_Step in the emulator, reading the actual
#       populated SAKE_MP_INT bignum at the modulus's struct offset and
#       reconstructing it from its 28-bit limbs reproduces that exact
#       1024-bit value, and the neighboring "g" slot holds exactly 2.
#     - the wire DOES truncate: SRPClient_Step copies only the first 64
#       bytes of the (up to 128-byte) exported public value onto the wire,
#       via a hardcoded 0x40 -- confirmed by running it: the real,
#       successfully-computed A came back as exactly 64 bytes. So A/B are
#       64 bytes on the wire despite N being 1024-bit/128 bytes; this file
#       does NOT reproduce that truncation (python-srp always emits the
#       full N-width value), which is one of the two remaining gaps below.
#     - message framing is payload + u32 LE length at a fixed +0x50 offset
#       (matches this file's frame-byte approach, minus the type byte).
#     - the "kick" that starts SRPClient_Step is 16 bytes, not 20 (0x10
#       checked at SRPClient_Step state 1) -- the 20-zero-byte trigger
#       this file uses is a *GATT-level* convention carried over from the
#       v1 protocol and is never fed into the real SRP code, so it does
#       not need to match.
#     - proof messages M1/M2 are 32 bytes, with a 1-byte status message
#       after -- matches this file's FRAME_PROOF/FRAME_STATUS already.
#
#   Getting this far took finding and fixing two real bugs in the
#   emulation harness itself (not properties of the pump): ARM's
#   "vld1/vst1 ...!" and "...],Rn" writeback addressing wasn't advancing
#   the base register, and the software NEON register file didn't alias
#   Qn with its Dn*2/Dn*2+1 halves, so a "zero out q8" write was
#   invisible to a later "store d16,d17" read, which then silently wrote
#   back stale data (in one very confusing case, a prior SHA-256 IV
#   constant) instead of zero. See tools/sake_v260_emulate/harness.py.
#
#   STILL NOT CONFIRMED -- the reason this file is a self-consistent demo,
#   not a validated implementation of the real pump protocol:
#     - the exact `x` (SRP private exponent) derivation. On real
#       SRPClient_Step state 1, `x` comes from
#       SRP_HashToBignum(ctx, <128-byte embedded constant>, 0x80,
#                         <1-byte embedded constant>, 1,
#                         <16-byte kick input>, 0x10)
#       i.e. it is NOT simply H(salt || passkey) the way vanilla SRP-6a
#       (and this file, via python-srp) computes it. The passkey itself
#       only enters afterwards, via a separate SRP_GenVerifierClient()
#       call. This file's python-srp-based x/verifier computation will
#       therefore never match a real pump's, regardless of N/g being
#       right, until this exact construction is reproduced (or driven
#       through the real library directly, per tools/sake_v260_emulate/).
#     - the wire truncation to 64 bytes (see above) isn't reproduced here.
#     - the session-key -> AES-CTR/CMAC KDF below is still fully theorized.
#
# Given the above, this module is kept as a self-consistent (client talks
# only to server, both in this same process) protocol-shaped demo/testbed.
# Do not expect it to pair with an actual device.

# default passkey used when none is supplied (hardcoded for testing)
TEST_PASSKEY = 123456

# SRP group / hash
#
# CONFIRMED correct -- see status block above. This is the real pump's
# group, verified by running the real native library and reading back its
# populated N/g bignums, not merely assumed because it's the RFC5054
# default.
_NG = srp.NG_1024
_HASH = srp.SHA256

# frame type bytes
FRAME_PUB_A    = 0x01  # client public value A -- real pump truncates this to 64 bytes on the wire (not reproduced here, see status block)
FRAME_PUB_B    = 0x02  # salt (16, confirmed) || server pub B (64 bytes on the real pump, not reproduced here)
FRAME_PROOF    = 0x03  # SRP proof M1 / M2 (32 bytes, confirmed)
FRAME_STATUS   = 0x05  # status byte (0x04 = success, confirmed: SRP state 4 "emit success, byteCount=1, out[0]=4")

_STATUS_OK = 0x04  # per v260 SRP state 4: "emit success (byteCount=1, out[0]=4)"

# Fixed width in bytes of the serialized SRP values for _NG (NG_1024, whose
# public values are the full 128 bytes of N). The real pump truncates its
# wire messages to 64 bytes instead (confirmed, see status block above);
# this file does not reproduce that truncation, so its self-test messages
# are full-width and would NOT match a real pump's byte-for-byte.
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
