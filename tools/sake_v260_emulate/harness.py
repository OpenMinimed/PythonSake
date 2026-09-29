import struct
import capstone
from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn import arm_const
from unicorn.arm_const import *

import os
PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libsake_armv7.so")

f = open(PATH, "rb")
elf = ELFFile(f)

uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

MAP_BASE = 0x10000
MAP_SIZE = 0x40000
uc.mem_map(MAP_BASE, MAP_SIZE, UC_PROT_ALL)

for seg in elf.iter_segments():
    if seg['p_type'] == 'PT_LOAD':
        data = seg.data()
        uc.mem_write(MAP_BASE + seg['p_vaddr'], data)

# Well-separated regions -- the heap in particular needs real headroom since
# our free() is a no-op, and a modexp loop's repeated temp-bignum
# alloc/free cycles otherwise exhaust a small arena.
STACK_BASE = 0x01000000
STACK_SIZE = 0x00100000  # 1MB
uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
STACK_TOP = STACK_BASE + STACK_SIZE - 0x100

HEAP_BASE = 0x02000000
HEAP_SIZE = 0x04000000  # 64MB
uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
heap_off = [0]


def heap_alloc(nbytes):
    nbytes = (nbytes + 15) & ~15
    addr = HEAP_BASE + heap_off[0]
    heap_off[0] += nbytes
    assert heap_off[0] < HEAP_SIZE, "heap exhausted"
    uc.mem_write(addr, b"\x00" * nbytes)
    return addr


TRAMP_BASE = 0x07000000
uc.mem_map(TRAMP_BASE, 0x10000, UC_PROT_ALL)
BX_LR = struct.pack("<H", 0x4770)

hook_names = {}
next_tramp = [TRAMP_BASE]
DEBUG_HOOKS = False


def make_trampoline(name):
    addr = next_tramp[0]
    next_tramp[0] += 4
    uc.mem_write(addr, BX_LR)
    hook_names[addr] = name
    return addr | 1  # thumb bit, for GOT slot value


def hook_code(uc, address, size, user_data):
    name = hook_names.get(address)
    if name is None:
        return
    lr = uc.reg_read(UC_ARM_REG_LR)
    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R1)
    r2 = uc.reg_read(UC_ARM_REG_R2)
    r3 = uc.reg_read(UC_ARM_REG_R3)
    if DEBUG_HOOKS:
        print(f"  [hook] {name}(r0={hex(r0)}, r1={hex(r1)}, r2={hex(r2)}, r3={hex(r3)}) lr={hex(lr)}")
    ret = 0
    if name == "calloc":
        ret = heap_alloc(r0 * r1)
    elif name == "malloc":
        ret = heap_alloc(r0)
    elif name == "free":
        pass
    elif name == "realloc":
        newp = heap_alloc(r1)
        if r0:
            uc.mem_write(newp, bytes(uc.mem_read(r0, r1)))
        ret = newp
    elif name in ("memcpy", "__memcpy_chk", "__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8"):
        dst, src, n = r0, r1, r2
        uc.mem_write(dst, bytes(uc.mem_read(src, n)))
        ret = dst
    elif name == "memmove":
        dst, src, n = r0, r1, r2
        uc.mem_write(dst, bytes(uc.mem_read(src, n)))
        ret = dst
    elif name in ("memclr", "__aeabi_memclr", "__aeabi_memclr4", "__aeabi_memclr8"):
        uc.mem_write(r0, b"\x00" * r1)
    elif name == "memcmp":
        a = bytes(uc.mem_read(r0, r2))
        b = bytes(uc.mem_read(r1, r2))
        ret = (a > b) - (a < b)
    elif name in ("memset", "__memset_chk"):
        uc.mem_write(r0, bytes([r1 & 0xff]) * r2)
        ret = r0
    elif name == "__stack_chk_fail":
        raise RuntimeError("stack check failed (harness bug)")
    elif name == "fopen":
        ret = 0
    elif name in ("fclose", "fgetc", "close", "__read_chk", "read", "open", "open64", "__open_2"):
        ret = 0xffffffff
    elif name in ("strlen", "__strlen_chk"):
        s = r0
        n = 0
        while bytes(uc.mem_read(s + n, 1)) != b"\x00":
            n += 1
            if n > 0x1000:
                break
        ret = n
    elif name in ("abort", "raise"):
        raise RuntimeError(f"target called {name}()")
    elif name in ("snprintf", "fprintf", "fflush"):
        ret = 0
    elif name in ("__cxa_atexit", "__cxa_finalize"):
        ret = 0
    elif name == "SakeUtil_ReadRandomBytes":
        import os
        n, outbuf = r0, r1
        uc.mem_write(outbuf, os.urandom(n))
        ret = n if n != 0 else 1  # nonzero = success per caller checks
    else:
        raise RuntimeError(f"unhandled import: {name}")
    uc.reg_write(UC_ARM_REG_R0, ret & 0xffffffff)
    uc.reg_write(UC_ARM_REG_PC, lr)


uc.hook_add(UC_HOOK_CODE, hook_code)

dynsym = elf.get_section_by_name('.dynsym')
symbols = list(dynsym.iter_symbols())
patched = 0
for relsec_name in ('.rel.plt', '.rel.dyn'):
    relsec = elf.get_section_by_name(relsec_name)
    if relsec is None:
        continue
    for rel in relsec.iter_relocations():
        sym = symbols[rel['r_info_sym']]
        name = sym.name
        if not name:
            continue
        r_type = rel['r_info_type']
        if r_type in (22, 21, 2):  # JUMP_SLOT, GLOB_DAT, ABS32
            tramp = make_trampoline(name)
            uc.mem_write(MAP_BASE + rel['r_offset'], struct.pack("<I", tramp))
            patched += 1
print(f"patched {patched} GOT/PLT relocations")

# hook an internal (non-imported) function directly at its real address, by
# overwriting its entry instruction with a trampoline-style "bx lr" trap.
INTERNAL_HOOKS = {
    0x1eb54: "SakeUtil_ReadRandomBytes",
}
for addr, name in INTERNAL_HOOKS.items():
    uc.mem_write(addr, BX_LR)
    hook_names[addr] = name

HALT_ADDR = 0xE0000
uc.mem_map(HALT_ADDR, 0x1000, UC_PROT_ALL)
uc.mem_write(HALT_ADDR, BX_LR)


def hook_halt(uc, address, size, user_data):
    if address == HALT_ADDR:
        uc.emu_stop()


uc.hook_add(UC_HOOK_CODE, hook_halt, begin=HALT_ADDR, end=HALT_ADDR + 2)

cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
cs.detail = True
_neon_regfile = {}


def _reg_size(name):
    return 16 if name.startswith('q') else 8


def _parse_vld1_vst1_operands(ops):
    """
    Parse capstone's op_str for vld1/vst1, e.g.:
      "{d16, d17}, [r0]"        -- no writeback
      "{d16, d17}, [r1]!"       -- writeback: base += total bytes transferred
      "{d16, d17}, [r6], r0"    -- writeback: base += value of r0 (register form)
    Returns (reg_names, base_reg_name, writeback), where writeback is None (no
    writeback), "auto" (advance base by the total transferred size), or a
    register name (advance base by that register's current value).
    """
    regs_part, rest = ops.split('[', 1)
    reg_names = [r.strip().strip('{}') for r in regs_part.split(',') if r.strip().strip('{}')]
    inside, after = rest.split(']', 1)
    base_reg_name = inside.strip()
    after = after.strip()
    if after == '!':
        writeback = "auto"
    elif after.startswith(','):
        writeback = after.lstrip(',').strip()
    else:
        writeback = None
    return reg_names, base_reg_name, writeback


def _apply_writeback(base_reg_name, writeback, total_bytes):
    if writeback is None:
        return
    base_const = getattr(arm_const, f"UC_ARM_REG_{base_reg_name.upper()}")
    base_val = uc.reg_read(base_const)
    if writeback == "auto":
        delta = total_bytes
    else:
        delta = uc.reg_read(getattr(arm_const, f"UC_ARM_REG_{writeback.upper()}"))
    uc.reg_write(base_const, (base_val + delta) & 0xffffffff)


def _neon_set(rn, data):
    """Write a d/q register and keep its alias in sync (see the big comment
    in the vmov handler below for why this matters)."""
    _neon_regfile[rn] = data
    if rn.startswith('d'):
        dn = int(rn[1:])
        qn = dn // 2
        other = f'd{dn+1}' if dn % 2 == 0 else f'd{dn-1}'
        other_data = _neon_regfile.get(other, b'\x00' * 8)
        combined = data + other_data if dn % 2 == 0 else other_data + data
        _neon_regfile[f'q{qn}'] = combined
    elif rn.startswith('q'):
        qn = int(rn[1:])
        _neon_regfile[f'd{qn*2}'] = data[0:8]
        _neon_regfile[f'd{qn*2+1}'] = data[8:16]


def _neon_get(rn, sz):
    """Read a d/q register, falling back to deriving it from its alias if
    only that was ever written (see _neon_set)."""
    if rn in _neon_regfile:
        return _neon_regfile[rn]
    if rn.startswith('d'):
        dn = int(rn[1:])
        qn = dn // 2
        q_data = _neon_regfile.get(f'q{qn}')
        if q_data is not None:
            return q_data[0:8] if dn % 2 == 0 else q_data[8:16]
    elif rn.startswith('q'):
        qn = int(rn[1:])
        d_lo = _neon_regfile.get(f'd{qn*2}')
        d_hi = _neon_regfile.get(f'd{qn*2+1}')
        if d_lo is not None or d_hi is not None:
            return (d_lo or b'\x00' * 8) + (d_hi or b'\x00' * 8)
    return b"\x00" * sz


def emulate_one_neon(pc_thumb):
    pc = pc_thumb & ~1
    code = bytes(uc.mem_read(pc, 4))
    insns = list(cs.disasm(code, pc, count=1))
    if not insns:
        raise RuntimeError(f"capstone failed to decode at {hex(pc)}: {code.hex()}")
    insn = insns[0]
    mnem, ops = insn.mnemonic, insn.op_str
    if mnem.startswith("vld1"):
        reg_names, base_reg_name, writeback = _parse_vld1_vst1_operands(ops)
        base_reg = uc.reg_read(getattr(arm_const, f"UC_ARM_REG_{base_reg_name.upper()}"))
        off = 0
        for rn in reg_names:
            sz = _reg_size(rn)
            _neon_set(rn, bytes(uc.mem_read(base_reg + off, sz)))
            off += sz
        _apply_writeback(base_reg_name, writeback, off)
        return insn.size
    elif mnem.startswith("vst1"):
        reg_names, base_reg_name, writeback = _parse_vld1_vst1_operands(ops)
        base_reg = uc.reg_read(getattr(arm_const, f"UC_ARM_REG_{base_reg_name.upper()}"))
        off = 0
        for rn in reg_names:
            sz = _reg_size(rn)
            data = _neon_get(rn, sz)
            uc.mem_write(base_reg + off, data)
            off += sz
        _apply_writeback(base_reg_name, writeback, off)
        return insn.size
    elif mnem.startswith('vmov') and '#' in ops:
        reg_name, imm = [x.strip() for x in ops.split(',', 1)]
        val = int(imm.lstrip('#'), 0)
        sz = _reg_size(reg_name)
        # _neon_set keeps qN in sync with its dN*2/dN*2+1 halves (they're the
        # same physical storage on real hardware). This mattered here: a
        # bare dict write would leave BN_InitMultiZero's "vmov q8,#0" unseen
        # by the "vst1 {d16,d17}" that follows, so it would silently write
        # whatever SHA256_Init's earlier, unrelated "vld1 {d16,d17}" had left
        # behind instead of the zero q8 had just set.
        _neon_set(reg_name, val.to_bytes(sz, 'little'))
        return insn.size
    elif mnem == 'vpush':
        reg_names = [r.strip() for r in ops.strip('{}').split(',')]
        sp = uc.reg_read(UC_ARM_REG_SP)
        total = sum(_reg_size(rn) for rn in reg_names)
        sp -= total
        uc.reg_write(UC_ARM_REG_SP, sp)
        off = 0
        for rn in reg_names:
            sz = _reg_size(rn)
            uc.mem_write(sp + off, _neon_get(rn, sz))
            off += sz
        return insn.size
    elif mnem == 'vpop':
        reg_names = [r.strip() for r in ops.strip('{}').split(',')]
        sp = uc.reg_read(UC_ARM_REG_SP)
        off = 0
        for rn in reg_names:
            sz = _reg_size(rn)
            _neon_set(rn, bytes(uc.mem_read(sp + off, sz)))
            off += sz
        uc.reg_write(UC_ARM_REG_SP, sp + off)
        return insn.size
    else:
        raise RuntimeError(f"unhandled insn for NEON fallback @ {hex(pc)}: {mnem} {ops}")


def call(addr, args):
    # fresh zeroed stack each top-level call, so leftover frames from a
    # previous call can't leak in as "uninitialized" garbage
    uc.mem_write(STACK_BASE, b"\x00" * STACK_SIZE)
    args = list(args)
    regs = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
    for i in range(4):
        uc.reg_write(regs[i], args[i] if i < len(args) else 0)
    stack_args = args[4:]
    sp = STACK_TOP
    if stack_args:
        sp -= len(stack_args) * 4
        sp &= ~7
        for i, v in enumerate(stack_args):
            uc.mem_write(sp + i * 4, struct.pack("<I", v & 0xffffffff))
    uc.reg_write(UC_ARM_REG_SP, sp)
    uc.reg_write(UC_ARM_REG_LR, HALT_ADDR)
    target = addr | 1
    while True:
        try:
            uc.emu_start(target, HALT_ADDR | 1, timeout=0, count=0)
            break
        except UcError as e:
            pc = uc.reg_read(UC_ARM_REG_PC)
            if e.errno == UC_ERR_INSN_INVALID:
                size = emulate_one_neon(pc)
                target = (pc | 1) + size
                continue
            print("UcError:", e, "pc=", hex(pc))
            raise
    return uc.reg_read(UC_ARM_REG_R0)


if __name__ == "__main__":
    SRP_SIZE = 0x400
    srp_buf = heap_alloc(SRP_SIZE)
    passkey_buf = heap_alloc(20)
    passkey_bytes = (123456).to_bytes(4, "big")
    uc.mem_write(passkey_buf, passkey_bytes + b"\x00" * 12)
    uc.mem_write(passkey_buf + 16, struct.pack("<I", 4))

    ret = call(0x190c8, [srp_buf, passkey_buf])
    print("SRPClient_Init ret =", ret)
    dump = bytes(uc.mem_read(srp_buf, 0x40))
    print("srp struct first 64 bytes:", dump.hex())
