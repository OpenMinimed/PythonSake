import logging

from pysake.constants import LOGGER_NAME

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

class SeqCrypt:

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

        # The trailer contains a 1-byte sequence field equal to (seq//2) & 0xFF.
        # We reconstruct the full 32-bit seq by treating the received byte as
        # an offset (delta) from the current `rx_seq` // 2 value. `d` is that
        # delta in 0..255. This handles wrap-around of the low 8-bit field.

        seq_byte = msg[-3]
        d = (seq_byte - (self.rx_seq // 2)) & 0xFF
        seq = self.rx_seq + d
        log.debug(f"local rx seq={self.rx_seq}, delta={d}, seq = {seq}")
        nonce = seq.to_bytes(length=5, byteorder="big") + self.nonce
        cobj = CMAC.new(self.key, ciphermod=AES, mac_len=4)
        ciphertext = msg[:-3]
        #log.debug(f"{ciphertext.hex() = }")
        cobj.update(nonce.ljust(16, b"\0") + ciphertext)
        digest = cobj.digest()

        next = seq + 2
        log.debug(
            f"decrypt: seq={seq}, nonce={nonce.hex()}, ciphertext_len={len(ciphertext)}, "
            f"received_mac={msg[-2:].hex()}, computed_mac={digest.hex()}, next_rx_seq={next}"
        )

        # Only the first two bytes of the CMAC are transmitted; compare those.
        if digest[:2] != msg[-2:]:

            recv_mac = msg[-2:]
            matches = self.__bruteforce_seq_matches(ciphertext, recv_mac, limit=1024)
            if matches:
                log.debug(
                    f"MAC mismatch: computed_mac={digest.hex()}, received={recv_mac.hex()}, "
                    f"possible_seq_matches={matches} (showing up to 10)"
                )
            else:
                log.debug(
                    f"MAC mismatch: computed_mac={digest.hex()}, received={recv_mac.hex()}, "
                    f"no matching seq found in first 1024 candidates starting at 0"
                )
            self.rx_seq += 1 # recover!?
            raise ValueError("MAC verification failed")
        
        self.rx_seq = next # only set it if everything (mac) goes right
        plaintext = AES.new(self.key, AES.MODE_CTR, nonce=nonce).decrypt(ciphertext)
        log.debug("decrypt ok")
        return plaintext
    
    def encrypt(self, plaintext: bytes) -> bytes:
        seq = self.tx_seq
        log = self.log.getChild("encrypt")        
        nonce = seq.to_bytes(length=5, byteorder="big") + self.nonce
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

    def __bruteforce_seq_matches(self, ciphertext: bytes, recv_mac: bytes, limit: int = 1024) -> list:
        """Private debug helper: brute-force the first `limit` sequence values
        starting from 0 and return a list of seq values whose CMAC prefix matches
        `recv_mac`. Sequence values tested are 0,1,2,... (limit entries).
        """
        matches = []
        for i in range(limit):
            seq_try = i
            nonce_try = seq_try.to_bytes(length=5, byteorder="big") + self.nonce
            cobj_try = CMAC.new(self.key, ciphermod=AES, mac_len=4)
            cobj_try.update(nonce_try.ljust(16, b"\0") + ciphertext)
            if cobj_try.digest()[:2] == recv_mac:
                matches.append(seq_try)
                if len(matches) >= 10:
                    break
        return matches
    