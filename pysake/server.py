
    # def build_handshake_2_s(self, server_key_material: bytes, server_nonce: bytes) -> bytes:
    #     """
    #     Build the server -> client handshake_2 (20 bytes):
    #       [0:8]   = CMAC8(handshake_auth_key, server_key_material || client_key_material || derivation_key)
    #       [8:16]  = server_key_material (8 bytes)
    #       [16:20] = server_nonce (4 bytes)
    #     Requires that client_key_material, derivation_key and handshake_auth_key are already set.
    #     """
    #     if self.client_key_material is None or self.derivation_key is None or self.handshake_auth_key is None:
    #         raise ValueError("missing session state for building handshake_2")
    #     if len(server_key_material) != 8 or len(server_nonce) != 4:
    #         raise ValueError("server_key_material must be 8 bytes and server_nonce 4 bytes")
    #     auth = self.cmac8(self.client_key_material, server_key_material, self.derivation_key, self.handshake_auth_key)
    #     return auth.digest() + server_key_material + server_nonce

    # def compute_handshake_3_prefix(self) -> bytes:
    #     """
    #     Compute the first 8 bytes of the client -> server handshake_3 message.
    #     This is the CMAC8 over (auth1.digest() || server_key_material || derivation_key)
    #     """
    #     if None in (self.client_key_material, self.server_key_material, self.derivation_key, self.handshake_auth_key):
    #         raise ValueError("missing session state for computing handshake_3")
    #     auth1 = self.cmac8(self.client_key_material, self.server_key_material, self.derivation_key, self.handshake_auth_key)
    #     inner = auth1.digest() + self.server_key_material + self.derivation_key
    #     auth2 = CMAC.new(self.handshake_auth_key, ciphermod=AES, mac_len=8)
    #     auth2.update(inner)
    #     return auth2.digest()

    # def build_handshake_3_c(self, filler: bytes | None = None) -> bytes:
    #     """
    #     Build a full 20-byte handshake_3 message.
    #     By protocol only the first 8 bytes are verified; filler fills remaining 12 bytes.
    #     If filler is None it will be zeroes. Provide filler when replaying captures.
    #     """
    #     prefix = self.compute_handshake_3_prefix()
    #     if filler is None:
    #         filler = bytes(12)
    #     if len(filler) != 12:
    #         raise ValueError("filler must be 12 bytes")
    #     return prefix + filler

    # def build_handshake_5_c(self, payload16: bytes | None = None) -> bytes:
    #     """Build a client -> server encrypted handshake_5 message.

    #     The encrypted frame contains 17 bytes of plaintext: the 16-byte payload
    #     followed by one padding byte (0). If `payload16` is None, and the
    #     session has `client_static_keys` or `server_static_keys`, the code will
    #     attempt to use the `handshake_payload` where appropriate; otherwise
    #     a zeroed 16-byte payload is used.
    #     """
    #     if self.client_crypt is None:
    #         raise ValueError("client_crypt not initialized; call handshake_4_s first")
    #     if payload16 is None:
    #         # default payload: try to use prover static payload if available
    #         if self.client_static_keys is not None:
    #             payload16 = self.client_static_keys.handshake_payload
    #         else:
    #             payload16 = bytes(16)
    #     if len(payload16) != 16:
    #         raise ValueError("payload16 must be 16 bytes")
    #     plaintext = payload16 + b"\x00"
    #     return self.client_crypt.encrypt(plaintext)
    