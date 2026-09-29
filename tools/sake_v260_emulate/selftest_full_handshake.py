"""
Self-test: drives a complete protocol-v2 (passkey/SRP-6a) handshake, client
and server alternating, using the real library via engine.py -- through
every layer: SRP-6a core, the session KDF, and the permit exchange (AES-ECB
+ self-consistency checksum). Confirms both sides end with
bIsSecureLinkEstablished=1 and identical pSecureLink state.

Run: python3 selftest_full_handshake.py
"""
from engine import (
    SakeV2Client,
    SakeV2Server,
    build_permit_plaintext,
    build_permit_key_material,
    build_key_database,
    aes_ecb_encrypt,
)

PASSKEY = 123456
CLIENT_DEVICE_TYPE = 4  # MobileApplication
SERVER_DEVICE_TYPE = 1  # InsulinPump

# In a real pairing this 4x16-byte identity material comes from the pump's
# own provisioning (see README.md's "What's real vs. synthetic here"
# section) -- these are placeholder values for the self-test only.
K_CLIENT_DECRYPT = bytes(range(0xA0, 0xB0))
K_SERVER_DECRYPT = bytes(range(0xB0, 0xC0))
MAC_CLIENT = bytes(range(0xC0, 0xD0))
MAC_SERVER = bytes(range(0xD0, 0xE0))

permit_server_to_client = build_permit_plaintext(SERVER_DEVICE_TYPE, MAC_CLIENT)
permit_client_to_server = build_permit_plaintext(CLIENT_DEVICE_TYPE, MAC_SERVER)

client_material = build_permit_key_material(
    K_CLIENT_DECRYPT, MAC_CLIENT,
    aes_ecb_encrypt(permit_client_to_server, K_SERVER_DECRYPT),
)
server_material = build_permit_key_material(
    K_SERVER_DECRYPT, MAC_SERVER,
    aes_ecb_encrypt(permit_server_to_client, K_CLIENT_DECRYPT),
)

client_kdb = build_key_database(CLIENT_DEVICE_TYPE, SERVER_DEVICE_TYPE, client_material)
server_kdb = build_key_database(SERVER_DEVICE_TYPE, CLIENT_DEVICE_TYPE, server_material)

client = SakeV2Client(PASSKEY, client_kdb)
server = SakeV2Server(PASSKEY, server_kdb)

last = None
client_done = False
for rnd in range(1, 12):
    print(f"round {rnd}:")
    out_s = server.step(last)
    print(f"  server: done={server.is_done} err={server.last_error} out={(out_s or b'').hex()}")
    last = out_s
    if client_done:
        break
    out_c = client.step(last)
    print(f"  client: done={client.is_done} err={client.last_error} out={(out_c or b'').hex()}")
    last = out_c
    if client.is_done:
        client_done = True
        if not out_c:
            break

print()
print("client secure_link:", client.secure_link.hex())
print("server secure_link:", server.secure_link.hex())
assert client.is_done and server.is_done, "handshake did not complete on both sides"
assert client.secure_link[8:] == server.secure_link[8:], "secure-link key material mismatch"
print()
print("OK: full protocol-v2 handshake completed, matching secure-link state on both sides.")

# post-handshake secure messaging, both directions
ct = client.secure_for_sending(b"hello pump!!")
pt = server.unsecure_after_receiving(ct)
assert pt == b"hello pump!!", f"client->server secure message mismatch: {pt!r}"
print("OK: client->server secure message round trip matches.")

ct2 = server.secure_for_sending(b"pump says hi")
pt2 = client.unsecure_after_receiving(ct2)
assert pt2 == b"pump says hi", f"server->client secure message mismatch: {pt2!r}"
print("OK: server->client secure message round trip matches.")
