import logging
from socket_client import SocketClient
from pysake.server import SakeServer
from pysake.constants import KEYDB_CUSTOM_SERVER

logging.basicConfig(level=logging.DEBUG)

sc = SocketClient("192.168.3.113")
server = SakeServer(KEYDB_CUSTOM_SERVER)


data = bytes(20)
for i in range(4):
    out = server.handshake(data)
    if out == None:
        print("done?, all ok??")
        break
    sc.send(out)
    data = sc.recv() # loop it
