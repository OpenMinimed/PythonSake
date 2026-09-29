# SAKE v260 (passkey / SRP-6a) — native library emulation harness

This is the actual implementation strategy for SAKE protocol v2: instead of
reimplementing the crypto by hand (which `pysake/v2.py` tried, against a
generic SRP library — see the note at the top of that file for why that
approach is retired), this harness runs Medtronic's own, unmodified
`libandroid-sake-lib.so` (armeabi-v7a build, v260) inside a
[Unicorn](https://www.unicorn-engine.org/) CPU emulator, entirely in-process,
no device or root required. Every crypto primitive — SRP-6a, the KDF, the
secure-link cipher — is whatever the real library computes, because it's the
real library computing it. There is no separate formula to get wrong.

## Setup

Extract the armeabi-v7a build from any MiniMed Mobile APK that ships
protocol v260 (2.6.0+ observed) and place it next to this file:

```sh
unzip -p /path/to/minimed-mobile.apk lib/armeabi-v7a/libandroid-sake-lib.so \
    > tools/sake_v260_emulate/libsake_armv7.so
```

The library is not committed to this repo (it's Medtronic's proprietary
binary, extracted from their APK — same status as any other APK asset this
project's other tools work with, e.g. `SakeLibraryRE`).

Python deps beyond this repo's `requirements.txt`: `unicorn`, `capstone`,
`pyelftools`.

```sh
pip install unicorn capstone pyelftools
```

## Usage

```sh
python3 harness.py          # sanity check: calls SRPClient_Init, dumps the struct
python3 drive_handshake.py  # drives a full client<->server SRP exchange
```

`harness.py` maps the .so's PT_LOAD segments at Ghidra's own image base
(0x10000, so addresses copy-pasted from Ghidra work directly as `call()`
targets), applies `R_ARM_RELATIVE` relocations (needed for the library's own
internal function pointers to resolve correctly), resolves imported libc
functions (calloc/memcpy/etc.) to Python stubs, and falls back to a small
software NEON emulator for the `vld1`/`vst1`/`vmov`/`vpush`/`vpop`
instructions the compiler emits as bulk-copy/register-save idioms (Unicorn's
ARM core doesn't execute NEON). `SakeUtil_ReadRandomBytes` is hooked directly
(not via GOT) to real `os.urandom()`.

## Status (as of this commit)

**The SRP-6a core is fully working and proven correct**, by running it, not
by inspecting it. `SRPClient_Init`/`Step` and `SRPServer_Init`/`Step` (the
real functions, at their real addresses) now run a complete 9-message
handshake end to end with no crashes, using two entirely separate,
independently-allocated struct instances for "client" and "server" — and
the shared secret each side derives, read back byte-for-byte from their
struct state after the exchange, is identical. Along the way this also
pinned down concrete facts about the real wire protocol:

- **N and g**: reading back the populated modulus `SAKE_MP_INT` (28-bit
  limbs, per `SakeLibraryRE/README.md` §24.2) reconstructs the standard
  RFC5054 1024-bit SRP prime exactly, with `g = 2` alongside it.
- **The wire truncates public values** to 64 of that group's 128 bytes
  (the real `SRPClient_Step`/`SRPServer_Step` hand back exactly 64 bytes
  for `A`/`B`, not 128).
- **The private exponent `x` is derived through two embedded constants**
  (a 128-byte and a 1-byte one, both extracted — see the disassembly notes
  in this file's git history) plus a 16-byte per-exchange value, not
  vanilla `H(salt||password)`.
- **The KDF function is `SakeCrypto_DeriveSessionKey` (0x166f8)**, signature
  `(challengeA, challengeB, proofKey, sessionKeyK[64B], memory, output[16B])`.
  It internally calls `SakeCrypto_GenerateProof` then
  `SakeCrypto_DeriveKeyMaterialHF` (an HMAC-based PRF) with mode `6`. Called
  directly with the confirmed-correct 64-byte SRP session key, it runs and
  produces stable 16-byte output — but with placeholder (zeroed)
  challenge/transcript inputs rather than authentic ones from a real
  handshake, so that specific output is not yet a verified answer. Getting
  a *verified* KDF result needs the top-level state machine below finished.

Three real bugs in this harness's own emulation (not the library) had to be
found and fixed to get this far:

1. `vld1`/`vst1`'s `...]!` and `...],Rn` writeback addressing wasn't
   advancing the base register, so code right after a writeback-form load
   used a stale address.
2. The software NEON register file didn't alias `qN` with its `dN*2`/
   `dN*2+1` halves the way real hardware does — a `vmov qN,#0` "zero this
   register" was invisible to a later `vst1 {dN*2,dN*2+1}`, which then
   wrote back stale leftover data from an unrelated earlier load instead of
   zero. (In `BN_InitMultiZero`, that meant a "zero this bignum" call
   actually wrote back a leftover SHA-256 IV constant.)
3. `R_ARM_RELATIVE` relocations were never applied, so an internal function
   pointer used by `SRP_BignumCtx_Free` was left un-rebased and calling
   through it jumped `0x10000` bytes short of the real target.

All three are fixed (`_neon_set`/`_neon_get` and the relocation loop in
`harness.py`).

## The top-level handshake + secure link: now fully working

`Sake_Client_Handshake`/`Sake_Server_Handshake` (the real public API,
`0x165a4`/`0x175e8`) wrap the SRP core above with an additional
challenge/IV/**permit** exchange layer and, on success, populate
`SAKE_CLIENT_S.pSecureLink`/`SAKE_SERVER_S.pSecureLink` (48 bytes each,
confirmed via Ghidra's struct database — `SAKE_CLIENT_S` is 124 bytes,
`SAKE_CLIENT_MEMORY_S` 952, `SAKE_SERVER_S` 172, `SAKE_SERVER_MEMORY_S`
948, all field-accurate) with the real AES-CTR+CMAC secure-link state.

**`engine.py` now drives this end to end, and `selftest_full_handshake.py`
proves it: both sides finish with `bIsSecureLinkEstablished=1` and
byte-identical secure-link key material.** Getting there required correctly
reverse-engineering the *permit exchange* — the layer this session's
previous attempt stalled on 7 of ~9 rounds in, at `err=18`
(`PERMIT_RECEIVED_INVALID`).

### Solving the permit exchange

The permit is how each side proves, at the very end of the handshake, that
it independently knows a pre-shared identity secret for the peer's device
type (on top of what SRP-6a alone proves) — pre-shared secrets live in the
`SAKE_KEY_DATABASE_S` each side is initialized with
(`SakeKeyDB_GetEntryByType`, confirmed to return `matched_entry + 1`, i.e.
entry layout is `[0]=type byte, [1:81]=80 bytes of material`, straight from
decompiling `FUN_00016dba`, the native backer of
`Sake_KeyDatabase_AddRemoteDeviceKey` — a raw verbatim copy, no KDF).

Getting the permit right took two rounds of being fooled by decompiler
pseudocode and one round of instrumenting the *real running code* to settle
it for good:

1. **Wrong key-material layout (`err=18` immediately).** First pass used one
   identical 80-byte blob on both sides. `ClientHandshake_State7FinalizeEncrypt`
   reads its own **decrypt** key from offset `[32:48]` of its own entry but
   sends its own permit **encrypted under the offset-`[64:80]` slot** — with
   an identical blob on both sides those are different byte ranges of the
   same data, so what one side encrypts with never matches what the peer
   tries to decrypt with. Fix: the two sides' 80-byte blobs must be
   constructed so `A`'s `[32:48]` (its decrypt key) equals whatever key `B`
   used to encrypt *to* `A`, and vice versa — see `build_permit_key_material()`
   in `engine.py`.

2. **Wrong idea of what's actually being ECB-decrypted (still `err=18`).**
   Live-hooking `SakeCrypto_AES_ECB_DecryptBlock` and
   `SakeCrypto_VerifyMessageHF` during the actual failing round (not
   reasoning about the decompile) showed the AES key/block/output registers
   directly: the wire payload arrives as a raw 16-byte value at the outer
   session-decrypted layer, and `SakeClient_DecryptValidateServerPermitHF`
   ECB-decrypts *that* using the receiver's own `[32:48]` key — confirming
   point 1's model was right, but only once the key routing itself
   (encrypt-key = *peer's* decrypt-key, not your own) was fixed did the ECB
   layer recover the intended plaintext at all.

3. **The real killer: decompiler misread a computed checksum as a hardcoded
   zero.** Even with (1) and (2) fixed, and the ECB layer now recovering
   exactly the intended plaintext, the handshake still failed. Ghidra's
   *decompile* of `SakeClient_DecryptValidateServerPermitHF` showed a check
   that looked like `plaintext[12:16] == 0`. Reading the **disassembly**
   directly (not the decompile) showed what's really compared:
   `SakeCrypto_VerifyMessageHF(mac_key, plaintext[0:12], 12)` computes a
   CMAC-style value into a *separate* stack slot, and the real check is
   `plaintext[12:16] == cmac_output[0:4]` — the permit's last 4 bytes are a
   **self-consistency checksum over its own first 12 bytes**, not padding.
   `build_permit_plaintext()` in `engine.py` computes this the only reliable
   way: by calling the real `SakeCrypto_VerifyMessageHF` itself, not by
   guessing the MAC construction.

   This is the third time in this project that Ghidra's C decompile of this
   library has actively misled rather than merely under-informed (see the
   three harness bugs above, and `GetEntryByType`'s off-by-`0x51` misread in
   the connector-history-adjacent notes) — every one of them was only
   resolved by either running the real code or reading raw disassembly.
   Treat this library's decompile as a *hypothesis*, always.

Full validated permit-field layout (`SakeClient_DecryptValidateServerPermitHF`,
`0x16f58`, confirmed via disassembly at `0x16f58`-`0x16fee`):

```
byte 0      : 0x00, required (a "status" byte)
byte 1      : sender's device type (checked against SakeError_IsValidCode)
bytes 2:12  : "proprietary bytes" (unvalidated payload)
bytes 12:16 : SakeCrypto_VerifyMessageHF(mac_key, bytes[0:12])[0:4]
```

And the per-peer 80-byte key-database entry layout
(`ClientHandshake_State7FinalizeEncrypt` @ `0x16438`,
`ServerHandshake_State5DecryptPermit` @ `0x17530`):

```
[0:32]  unused by the permit path
[32:48] this side's AES-ECB key for decrypting an incoming permit
[48:64] this side's CMAC key for verifying an incoming permit's checksum
[64:80] AES_ECB_Encrypt(this side's own permit plaintext, using the
        PEER's [32:48] key) -- embedded as this side's outgoing permit
```

### What's real vs. synthetic here

The SRP-6a core, the KDF, the AES-ECB/CMAC primitives, and the entire
handshake state machine above are the **real library**, byte-exact. What's
*not* real in `selftest_full_handshake.py`: the four 16-byte identity
secrets (`K_CLIENT_DECRYPT`/`K_SERVER_DECRYPT`/`MAC_CLIENT`/`MAC_SERVER`)
are placeholder values invented for the self-test, not a real pump's
provisioned key material. A real pump's `SAKE_KEY_DATABASE_S` entries carry
real, pump-specific secrets — most likely provisioned via the IDD Secure
Control Point (`0x0109`) / `PublicKeyExchangeApiImpl` flow this project's
`Documentation` repo describes, which is the actual candidate for *how* a
real phone obtains this material during pairing. That flow is not yet
connected to this engine — see `PythonPumpConnector`'s `idd/secure_control.py`
and its docstring for the reverse-engineered wire format of that
characteristic.

### Using this from other code

`engine.py` exposes `SakeV2Client`/`SakeV2Server` classes
(`.step(incoming_bytes_or_None) -> reply_bytes_or_None`, `.is_done`,
`.secure_link`, `.last_error`) plus the permit/key-database builder
functions, all driving the real library underneath. This is what
`PythonPumpConnector`'s `--sake-v2` path should be wired to next, once real
per-pump identity secrets are available.
