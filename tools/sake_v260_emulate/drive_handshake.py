import struct
import sys
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

SRP_SIZE = 0x400
PASSKEY = 123456

client_ctx = heap_alloc(SRP_SIZE)
server_ctx = heap_alloc(SRP_SIZE)
pk_c = mk_passkey(PASSKEY)
pk_s = mk_passkey(PASSKEY)

r = call(0x190c8, [client_ctx, pk_c])
print("SRPClient_Init:", r)
r = call(0x19568, [server_ctx, pk_s])
print("SRPServer_Init:", r)

out = mkmsg()
r = call(0x197f0, [server_ctx, 0, out])   # SRPServer_Step(server, NULL, out)
print("SRPServer_Step#1 ret=", r, "out=", msg_bytes(out).hex())
srv_hello = msg_bytes(out)

inp = mkmsg(srv_hello)
out = mkmsg()
r = call(0x19184, [client_ctx, inp, out])  # SRPClient_Step
print("SRPClient_Step#1 ret=", r, "out=", msg_bytes(out).hex())
client_A = msg_bytes(out)

inp = mkmsg(client_A)
out = mkmsg()
r = call(0x197f0, [server_ctx, inp, out])
print("SRPServer_Step#2 ret=", r, "out=", msg_bytes(out).hex())
server_B = msg_bytes(out)

inp = mkmsg(server_B)
out = mkmsg()
r = call(0x19184, [client_ctx, inp, out])
print("SRPClient_Step#2 ret=", r, "out=", msg_bytes(out).hex())
client_M1 = msg_bytes(out)

inp = mkmsg(client_M1)
out = mkmsg()
r = call(0x197f0, [server_ctx, inp, out])
print("SRPServer_Step#3 ret=", r, "out=", msg_bytes(out).hex())
server_msg3 = msg_bytes(out)

inp = mkmsg(server_msg3)
out = mkmsg()
r = call(0x19184, [client_ctx, inp, out])
print("SRPClient_Step#3 ret=", r, "out=", msg_bytes(out).hex())
client_msg3 = msg_bytes(out)

inp = mkmsg(client_msg3)
out = mkmsg()
r = call(0x197f0, [server_ctx, inp, out])
print("SRPServer_Step#4 ret=", r, "out=", msg_bytes(out).hex())

# dump error/state fields for both contexts to diagnose
def dump_ctx(name, ctx):
    d = bytes(uc.mem_read(ctx, 0x20))
    print(name, "flags/state/substate/errcode/result:", d.hex())

dump_ctx("client", client_ctx)
dump_ctx("server", server_ctx)
