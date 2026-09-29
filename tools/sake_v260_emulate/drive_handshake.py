import struct, sys
sys.path.insert(0, __import__("os").path.dirname(__file__))
import harness as h

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
