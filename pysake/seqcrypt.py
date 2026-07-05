import logging

from pysake.constants import LOGGER_NAME

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

class SeqCrypt:
    """
    CTR + CMAC encrypt/decrypt per message direction.

    Native library model (libandroid-sake-lib_v210.so):
      - Single 64-bit counter per SAKE_SECURE_LINK_S, +1 per msg
      - CTR nonce encodes: (mode & 1) | (counter << 1) as 5-byte big-endian
      - Wire trailer byte: counter & 0xFF
      - mode=0 for client, mode=1 for server

    Python model (this class):
      - Separate tx_seq (send) and rx_seq (receive), +2 per msg
      - CTR nonce: seq.to_bytes(5, 'big')
      - Wire trailer byte: (seq // 2) & 0xFF
      - Client starts at seq=0, server at seq=1

    Mapping:  Python seq = native_counter * 2 + mode
              native_counter = seq // 2
              mode = seq & 1  (0=client, 1=server)

    The step of +2 and the halved wire byte exactly compensate
    for the native +1 with mode bit baked into the nonce.
    """

    def __init__(self, key: bytes, nonce: bytes, seq: int):
        self.key = key
        self.nonce = nonce
        # track separate sequence numbers for transmit (tx) and receive (rx)
        self.rx_seq = int(seq)
        self.tx_seq = int(seq)
        if len(self.nonce) != 8:
            raise ValueError("nonce must be 8 bytes")
        self.log = logging.getLogger(LOGGER_NAME).getChild("SeqCrypt")
        return

    def __repr__(self):
        return (
            f"SeqCrypt("
            f"key={self.key.hex()}, "
            f"nonce={self.nonce.hex()}, "
            f"tx_seq={self.tx_seq}, rx_seq={self.rx_seq}"
            f")"
        )

    def decrypt(self, msg: bytes) -> bytes:
        if len(msg) < 3:
            raise ValueError("Message length too small!")

        log = self.log.getChild("decrypt")

        # Wire byte = (seq // 2) & 0xFF  (= native counterLow & 0xFF)
        # Reconstruct delta from halved wire byte, then full seq.
        # Equivalent to native: delta = (seqByte - counterLow) & 0xFF

        seq_byte = msg[-3]
        d = (seq_byte - (self.rx_seq // 2)) & 0xFF
        seq = self.rx_seq + 2*d
        log.debug(f"local rx seq={self.rx_seq}, delta={d}, seq = {seq}")
        nonce = seq.to_bytes(length=5, byteorder="big") + self.nonce
        cobj = CMAC.new(self.key, ciphermod=AES, mac_len=4)
        ciphertext = msg[:-3]
        #log.debug(f"{ciphertext.hex() = }")
        cobj.update(nonce.ljust(16, b"\0") + ciphertext)
        digest = cobj.digest()

        next = seq + 2 # = native (counter+1) * 2 + mode

        log.debug(
            f"decrypt: seq={seq}, nonce={nonce.hex()}, ciphertext_len={len(ciphertext)}, "
            f"received_mac={msg[-2:].hex()}, computed_mac={digest.hex()}, next_rx_seq={next}"
        )

        # Only the first two bytes of the CMAC are transmitted; compare those.
        if digest[:2] != msg[-2:]:

            recv_mac = msg[-2:]
            found = self.__bruteforce_seq_matches(ciphertext, recv_mac, self.rx_seq)
            if found is not None:
                log.debug(
                    f"MAC mismatch: computed_mac={digest.hex()}, received={recv_mac.hex()}, "
                    f"found_seq={found} near rx_seq={self.rx_seq}"
                )
            else:
                log.debug(
                    f"MAC mismatch: computed_mac={digest.hex()}, received={recv_mac.hex()}, "
                    f"no matching seq found around rx_seq={self.rx_seq}"
                )
            self.rx_seq = next
            raise ValueError("MAC verification failed")
        
        self.rx_seq = next # only set it if everything (mac) goes right
        plaintext = AES.new(self.key, AES.MODE_CTR, nonce=nonce).decrypt(ciphertext)
        log.debug("decrypt ok")
        return plaintext

    def encrypt(self, plaintext: bytes) -> bytes:
        seq = self.tx_seq
        log = self.log.getChild("encrypt")
        nonce = seq.to_bytes(length=5, byteorder="big") + self.nonce
        # seq.to_bytes(5) = native (mode | counter<<1) as 5-byte big-endian
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        cobj = CMAC.new(self.key, ciphermod=AES, mac_len=4)
        cobj.update(nonce.ljust(16, b"\0") + ciphertext)
        digest = cobj.digest()
        trailer = bytes([(seq // 2) & 0xFF]) + digest[:2]
        self.tx_seq = seq + 2
        #self.rx_seq += 1
        log.debug(
            f"encrypt done: seq={seq}, nonce={nonce.hex()}, ciphertext_len={len(ciphertext)}, "
            f"computed_mac={digest.hex()}, trailer={trailer.hex()}, next_tx_seq={self.tx_seq}"
        )
        return ciphertext + trailer

    def __bruteforce_seq_matches(self, ciphertext: bytes, recv_mac: bytes, center: int, limit: int = 1024) -> int | None:
        """
        Search for a seq whose CMAC prefix matches recv_mac,
        centered around `center` within +- limit/2 range. Returns the
        first matching seq or None.
        """
        half = limit // 2
        for offset in range(-half, half + 1):
            seq_try = center + offset
            if seq_try < 0:
                continue
            nonce_try = seq_try.to_bytes(length=5, byteorder="big") + self.nonce
            cobj_try = CMAC.new(self.key, ciphermod=AES, mac_len=4)
            cobj_try.update(nonce_try.ljust(16, b"\0") + ciphertext)
            if cobj_try.digest()[:2] == recv_mac:
                return seq_try
        return None
    