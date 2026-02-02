import logging

from pysake.constants import LOGGER_NAME

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

class SeqCrypt:

    def __init__(self, key: bytes, nonce: bytes, seq: int):
        self.key = key
        self.nonce = nonce
        self.seq = int(seq)
        if len(self.nonce) != 8:
            raise ValueError("nonce must be 8 bytes")
        self.log = logging.getLogger(LOGGER_NAME).getChild("SeqCrypt")
        return

    def decrypt(self, msg: bytes) -> bytes:
        if len(msg) < 3:
            raise ValueError("Message length too small!")

        log = self.log.getChild("decrypt")        
        d = (msg[-3] - self.seq // 2) & 0xFF
        seq = self.seq + 2 * d
        log.debug(f"{seq = }, {d = }")
        nonce = seq.to_bytes(length=5, byteorder="big") + self.nonce
        cobj = CMAC.new(self.key, ciphermod=AES, mac_len=4)
        ciphertext = msg[:-3]
        log.debug(f"{ciphertext.hex() = }")
        cobj.update(nonce.ljust(16, b"\0") + ciphertext)
        log.debug(f"{msg[-2:].hex() = }, {cobj.digest().hex() = }")
        cobj.verify(msg[-2:] + cobj.digest()[2:4])
        self.seq = seq + 2
        log.debug(f"seq={seq} nonce={nonce.hex()} ciphertext={ciphertext.hex()}")
        return AES.new(self.key, AES.MODE_CTR, nonce=nonce).decrypt(ciphertext)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        seq = self.seq
        log = self.log.getChild("encrypt")        
        nonce = seq.to_bytes(length=5, byteorder="big") + self.nonce
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        cobj = CMAC.new(self.key, ciphermod=AES, mac_len=4)
        cobj.update(nonce.ljust(16, b"\0") + ciphertext)
        digest = cobj.digest()
        trailer = bytes([(seq // 2) & 0xFF]) + digest[:2]
        self.seq = seq + 2
        log.debug(f"encrypt: seq={seq} nonce={nonce.hex()} ciphertext={ciphertext.hex()} trailer={trailer.hex()}")
        return ciphertext + trailer
    