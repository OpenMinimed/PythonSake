# SAKE v260 (passkey / SRP-6a) — native library emulation harness

This is the actual foundation for a working SAKE protocol-v2 implementation.
Unlike `pysake/v2.py` (a self-consistent but **unvalidated** reimplementation
against a generic SRP library), this harness runs Medtronic's real, unmodified
`libandroid-sake-lib.so` (armeabi-v7a build, v260) inside a
[Unicorn](https://www.unicorn-engine.org/) CPU emulator, entirely in-process,
with no device or root required. It is the only way, short of a real device
capture, to get byte-exact protocol values (the real modulus N, generator g,
and the exact — non-standard — key-derivation hash construction; see the
status comment at the top of `pysake/v2.py`).

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
targets), resolves imported libc functions (calloc/memcpy/etc.) to Python
stubs, and falls back to a small software NEON emulator for the handful of
`vld1`/`vst1`/`vmov` instructions the compiler emits as bulk-copy idioms
(Unicorn's ARM core doesn't execute NEON). `SakeUtil_ReadRandomBytes` is
hooked directly (not via GOT) to real `os.urandom()`.

## Status (as of this commit)

**Working:** `SRPClient_Init` runs cleanly end-to-end and returns success
with a correctly populated struct — proves the harness correctly loads and
executes the real ARM code.

**Not working yet:** `drive_handshake.py` crashes inside `SRPServer_Init`,
in a `realloc()` call reached through the
`SRP_BignumCtx_Init → SRP_HashToBignum → BN_Grow`-ish call chain, with what
looks like an uninitialized/garbage pointer. This is very likely a harness
bug (an incompletely-modeled bignum-context lifecycle), not a bug in the
real library — needs more careful tracing of every write to the relevant
`SAKE_MP_INT` struct fields before the crashing `realloc`. `DEBUG_HOOKS = True`
in `harness.py` traces every hooked call with its arguments, which is the
fastest way to pick this back up.

Once the handshake runs cleanly, the next step is to dump the populated
modulus/generator bignums (their `SAKE_MP_INT{used,alloc,sign,dp}` — 28-bit
limbs, per `SakeLibraryRE/README.md` §24.2) at the offsets given in
`SRP_ComputeSharedSecret`'s decompile (modulus at bnCtx+0x18) and reconstruct
the big-endian byte value from the limb array.
