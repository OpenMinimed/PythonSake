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

**N and g are confirmed.** `SRPClient_Init` + `SRPClient_Step` (state 1) now
run end-to-end successfully, and reading back the populated modulus
`SAKE_MP_INT` at `bnCtx+0x18` (28-bit limbs, per `SakeLibraryRE/README.md`
§24.2) and reconstructing the big-endian value from them reproduces the
**standard RFC5054 1024-bit SRP prime, exactly**, with `g = 2` in the
neighboring slot. This settles it: the real pump's group genuinely is the
RFC5054 1024-bit group — `pysake/v2.py`'s `srp.NG_1024` choice was already
correct, by luck. What's real and still unmatched is that the wire
*truncates* public values to 64 of that group's 128 bytes (confirmed: the
real `SRPClient_Step` handed back exactly 64 bytes for `A`), and the private
exponent `x` is derived through embedded constants rather than vanilla
`H(salt||password)` — see the status comment at the top of `pysake/v2.py`
for the full, current picture.

Getting here required finding two real bugs in this harness's own software
NEON emulation (not the real library):

1. `vld1`/`vst1`'s `...]!` and `...],Rn` writeback addressing wasn't
   advancing the base register, so code right after a writeback-form load
   (e.g. reading a struct field just past a just-loaded array) used a stale
   base address.
2. The software NEON register file didn't alias `qN` with its `dN*2`/
   `dN*2+1` halves the way real hardware does. `vmov qN,#0` only cleared
   the `"qN"` dict entry; a later `vst1 {dN*2,dN*2+1}` read those *separate*
   dict keys, found them untouched, and silently wrote back whatever an
   earlier, unrelated `vld1` into those same `d` registers had left there.
   In `BN_InitMultiZero`, that meant a "zero this bignum" call was actually
   writing back leftover SHA-256 IV bytes from a `SHA256_Init` call a few
   instructions earlier — which is what a garbage `realloc()` pointer a few
   calls later was actually pointing at.

Both are fixed now (`_neon_set`/`_neon_get` in `harness.py` keep the alias
in sync; see the comments there).

**Still crashing:** `drive_handshake.py`'s `SRPServer_Init` call (a much
larger function than the client path — it also generates its own salt and
verifier) still faults, at a different point, with a garbage jump target.
Given the two bugs just fixed were both NEON-register-aliasing issues, the
same class of bug (or a `vpush`/`vpop` alignment/size issue — see the
`vpush`/`vpop` handlers added in this same commit, which are less
exercised) is the first thing to suspect. `DEBUG_HOOKS = True` in
`harness.py` traces every hooked call with its arguments, and adding a
targeted `UC_HOOK_CODE` entry-hook for whichever function the crash address
belongs to (see the `bn_grow_entry_hook`-style pattern used to find the
NEON bug, in this commit's history) is the fastest way to keep narrowing it
down. This crash does not block using the confirmed N/g above, though —
both SRP roles use the same group by definition.
