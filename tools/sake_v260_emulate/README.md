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

## Next step: the top-level handshake + secure link

`Sake_Client_Handshake`/`Sake_Server_Handshake` (the real public API,
`0x165a4`/`0x175e8`) wrap the SRP core above with an additional
challenge/IV/permit exchange layer and, on success, populate
`SAKE_CLIENT_S.pSecureLink`/`SAKE_SERVER_S.pSecureLink` (48 bytes each,
confirmed via Ghidra's struct database — `SAKE_CLIENT_S` is 124 bytes,
`SAKE_CLIENT_MEMORY_S` 952, `SAKE_SERVER_S` 172, `SAKE_SERVER_MEMORY_S`
948, all field-accurate) with the real AES-CTR+CMAC secure-link state. A
first drive through this API (client+server alternating, mirroring
`drive_handshake.py`'s pattern) got through 7 of what should be ~11-12
rounds before diverging — most likely because this layer's message
boundaries don't map 1:1 onto raw `SRPClient_Step`/`SRPServer_Step` calls
the way the lower-level drive assumed, not a new library bug (the same class
of bug that's been found each time so far). Finishing this — matching the
exact call/message sequence `Sake_Client_Handshake` expects — is what's left
to extract and verify the real, final secure-link keys.
