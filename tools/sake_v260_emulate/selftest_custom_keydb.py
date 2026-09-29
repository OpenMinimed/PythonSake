"""
Self-test: drives a complete protocol-v2 (passkey/SRP-6a) handshake using
pysake.constants.KEYDB_CUSTOM_SERVER / KEYDB_CUSTOM_CLIENT -- a genuinely
independent, self-generated matched key pair (each side only ever reads
its own StaticKeys entry; nothing is manually cross-linked the way
selftest_full_handshake.py's K_CLIENT_DECRYPT/K_SERVER_DECRYPT placeholders
are). This mirrors exactly how a real phone and a real pump would each
only know their own side -- and it's the same real KeyDatabase format
(pysake.keys.KeyDatabase/StaticKeys) already proven against a real pump
for protocol v1 via PythonSake's own socket_test.py.

Confirms the "forward your own precomputed handshake_payload verbatim,
let the receiver decrypt it with its own key" model (see README.md's
"What's real vs. synthetic here") actually produces a complete handshake
between two independently-provisioned sides, not just when one script
manually constructs both.

Run: python3 selftest_custom_keydb.py
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pysake.constants import KEYDB_CUSTOM_SERVER, KEYDB_CUSTOM_CLIENT
from engine import SakeV2Client, SakeV2Server, build_permit_key_material, build_key_database

PASSKEY = 123456

sk_server = KEYDB_CUSTOM_SERVER.remote_devices[1]  # our (server) own entry, about peer=pump(1)
sk_client = KEYDB_CUSTOM_CLIENT.remote_devices[4]  # pump's (client) own entry, about peer=us(4)

server_material = build_permit_key_material(
    sk_server.permit_decrypt_key, sk_server.permit_auth_key, sk_server.handshake_payload,
)
client_material = build_permit_key_material(
    sk_client.permit_decrypt_key, sk_client.permit_auth_key, sk_client.handshake_payload,
)

server_kdb = build_key_database(KEYDB_CUSTOM_SERVER.local_device_type.value, 1, server_material)
client_kdb = build_key_database(KEYDB_CUSTOM_CLIENT.local_device_type.value, 4, client_material)

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
# bytes[0:8] carry a per-role header (differs client vs server by design,
# confirmed by comparing against selftest_full_handshake.py's own output);
# bytes[8:] are the actual shared secure-link key material.
assert client.secure_link[8:] == server.secure_link[8:], "secure-link key material mismatch"
print()
print("OK: full protocol-v2 handshake completed using independently-matched")
print("    KEYDB_CUSTOM_SERVER/KEYDB_CUSTOM_CLIENT, matching secure-link state.")

ct = client.secure_for_sending(b"hello pump!!")
pt = server.unsecure_after_receiving(ct)
assert pt == b"hello pump!!", f"client->server secure message mismatch: {pt!r}"
print("OK: client->server secure message round trip matches.")

ct2 = server.secure_for_sending(b"pump says hi")
pt2 = client.unsecure_after_receiving(ct2)
assert pt2 == b"pump says hi", f"server->client secure message mismatch: {pt2!r}"
print("OK: server->client secure message round trip matches.")
