import struct, sys
sys.path.insert(0, __import__("os").path.dirname(__file__))
import harness as h
h.DEBUG_HOOKS = True

uc = h.uc
call = h.call
heap_alloc = h.heap_alloc

def mkmsg(payload=b""):
    buf = heap_alloc(0x60)
    if payload:
        uc.mem_write(buf, payload)
    uc.mem_write(buf + 0x50, struct.pack("<I", len(payload)))
    return buf

def msg_bytes(buf):
    n = struct.unpack("<I", bytes(uc.mem_read(buf+0x50, 4)))[0]
    return bytes(uc.mem_read(buf, n))

def mk_passkey(n):
    buf = heap_alloc(20)
    b = n.to_bytes(4, "big")
    uc.mem_write(buf, b + b"\x00"*12)
    uc.mem_write(buf+16, struct.pack("<I", 4))
    return buf

def dump_state(name, ctx):
    d = bytes(uc.mem_read(ctx+0x300, 20))
    bFlags, dwState, dwSubstate, dwErrorCode, dwResult = d[0], *struct.unpack("<iiii", d[4:20])
    print(f"  {name}: bFlags={bFlags} dwState={dwState} dwSubstate={dwSubstate} dwErrorCode={dwErrorCode} dwResult={dwResult}")

SRP_SIZE = 0x400
PASSKEY = 123456

client_ctx = heap_alloc(SRP_SIZE)
server_ctx = heap_alloc(SRP_SIZE)
pk_c = mk_passkey(PASSKEY)
pk_s = mk_passkey(PASSKEY)


last_sp = [None]
def sp_watch(uc, address, size, user_data):
    sp = uc.reg_read(h.UC_ARM_REG_SP)
    if last_sp[0] is not None and abs(sp - last_sp[0]) > 0x2000:
        print(f"    [SP jump] {hex(last_sp[0])} -> {hex(sp)} at pc={hex(address)}", flush=True)
    last_sp[0] = sp
from unicorn import UC_HOOK_CODE
uc.hook_add(UC_HOOK_CODE, sp_watch)
r = call(0x190c8, [client_ctx, pk_c]); print("SRPClient_Init:", r)
r = call(0x19568, [server_ctx, pk_s]); print("SRPServer_Init:", r)
dump_state("client", client_ctx); dump_state("server", server_ctx)

out = mkmsg()
r = call(0x197f0, [server_ctx, 0, out])
print("SRPServer_Step#1 ret=", r, "out=", msg_bytes(out).hex())
dump_state("server", server_ctx)
srv_hello = msg_bytes(out)

inp = mkmsg(srv_hello); out = mkmsg()
r = call(0x19184, [client_ctx, inp, out])
print("SRPClient_Step#1 ret=", r, "out=", msg_bytes(out).hex())
dump_state("client", client_ctx)
client_A = msg_bytes(out)

inp = mkmsg(client_A); out = mkmsg()
r = call(0x197f0, [server_ctx, inp, out])
print("SRPServer_Step#2 ret=", r, "out=", msg_bytes(out).hex())
dump_state("server", server_ctx)
server_B = msg_bytes(out)

inp = mkmsg(server_B); out = mkmsg()
r = call(0x19184, [client_ctx, inp, out])
print("SRPClient_Step#2 ret=", r, "out=", msg_bytes(out).hex())
dump_state("client", client_ctx)
client_M1 = msg_bytes(out)

inp = mkmsg(client_M1); out = mkmsg()
r = call(0x197f0, [server_ctx, inp, out])
print("SRPServer_Step#3 ret=", r, "out=", msg_bytes(out).hex())
dump_state("server", server_ctx)
server_msg3 = msg_bytes(out)

inp = mkmsg(server_msg3); out = mkmsg()
r = call(0x19184, [client_ctx, inp, out])
print("SRPClient_Step#3 ret=", r, "out=", msg_bytes(out).hex())
dump_state("client", client_ctx)
client_msg3 = msg_bytes(out)

inp = mkmsg(client_msg3); out = mkmsg()
r = call(0x197f0, [server_ctx, inp, out])
print("SRPServer_Step#4 ret=", r, "out=", msg_bytes(out).hex())
dump_state("server", server_ctx)

inp = mkmsg(msg_bytes(out)); out2 = mkmsg()  # feed server's M2-ish msg4 into client state4
r = call(0x19184, [client_ctx, inp, out2])
print("SRPClient_Step#4 ret=", r, "out=", msg_bytes(out2).hex())
dump_state("client", client_ctx)
client_final = msg_bytes(out2)

inp2 = mkmsg(client_final); out3 = mkmsg()
r = call(0x197f0, [server_ctx, inp2, out3])
print("SRPServer_Step#5 ret=", r, "out=", msg_bytes(out3).hex())
dump_state("server", server_ctx)

# secureLink is documented as +0x40, 0x30 bytes within SAKE_CLIENT_S/SAKE_SERVER_S
# (SakeLibraryRE README sec 24.1/8) -- NOT inside the SRP struct itself. We
# only have the SRP structs here (client_ctx/server_ctx ARE SAKE_SRP_CLIENT_S/
# SAKE_SRP_SERVER_S per the Ghidra struct, not the outer SAKE_CLIENT_S), so
# there's no secureLink to read directly at this layer -- print the raw
# session-key-bearing area of each SRP struct instead as a first look.
print("client ctx tail (last 0x60 bytes of 0x314):", bytes(uc.mem_read(client_ctx+0x314-0x60, 0x60)).hex())
print("server ctx tail (last 0x60 bytes of 0x310):", bytes(uc.mem_read(server_ctx+0x310-0x60, 0x60)).hex())
