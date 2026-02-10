from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from pysake.keys import StaticKeys, DeviceType, KeyDatabase

def create_permit(crypt_key: bytes, cmac_key: bytes, plain: bytes) -> bytes:

    if len(plain) != 12:
        raise ValueError("Plaintext must be 12 bytes")

    # Compute 4-byte CMAC over first 12 bytes
    auth = CMAC.new(cmac_key, ciphermod=AES, mac_len=4)
    auth.update(plain)
    cmac_bytes = auth.digest()
    
    # Build the final plaintext block to encrypt
    full_plain = plain + cmac_bytes
    
    # Encrypt with AES-ECB using the permit_decrypt_key
    cipher = AES.new(crypt_key, AES.MODE_ECB)
    payload = cipher.encrypt(full_plain)
    
    return payload

pump_permit = bytearray(bytes.fromhex("000000000000111111111111")) # activating features on the pump (sent from the phone)
pump_permit[0] = 0
pump_permit[1] = DeviceType.MobileApplication
pump_permit = bytes(pump_permit)
pump_cmac_key = "PUMP_PERMIT_CMAC".encode('ascii')
pump_enc_key = "PUMP_PERMIT_ENCR".encode('ascii')
pump_final = create_permit(pump_enc_key, pump_cmac_key, pump_permit)
print(f"{pump_permit.hex() =}")
print(f"{pump_cmac_key.hex() =}")
print(f"{pump_enc_key.hex() =}")
print(f"{pump_final.hex() =}")


print("\n\n")

phone_permit = bytearray(bytes.fromhex("111111111111000000000000"))
phone_permit[0] = 0
phone_permit[1] = DeviceType.InsulinPump
phone_cmac_key = "PHONE_PERMIT_MAC".encode('ascii')
phone_enc_key = "PHONE_PERMIT_ENC".encode('ascii')
phone_final = create_permit(phone_enc_key, phone_cmac_key, phone_permit)
print(f"{phone_permit.hex() =}")
print(f"{phone_cmac_key.hex() =}")
print(f"{phone_enc_key.hex() =}")
print(f"{phone_final.hex() =}")


handshake_auth_key = "HNDSHKE_AUTH_KEY".encode('ascii')
deriv_key = "DERIVATION___KEY".encode('ascii')


side1 = StaticKeys(deriv_key, handshake_auth_key, phone_enc_key, phone_cmac_key, pump_final) # here they are swapped
side2 = StaticKeys(deriv_key, handshake_auth_key, pump_enc_key, pump_cmac_key, phone_final)

server_remotes = {}
server_remotes[DeviceType.InsulinPump] = side1
server_db = KeyDatabase(DeviceType.MobileApplication, server_remotes, bytes.fromhex("aabbccdd"))

client_remotes = {}
client_remotes[DeviceType.MobileApplication] = side2
client_db = KeyDatabase(DeviceType.InsulinPump, client_remotes, bytes.fromhex("aabbccdd"))

print(client_db)
print(client_db.to_bytes().hex())

print("\n\n")

print(server_db)
print(server_db.to_bytes().hex())