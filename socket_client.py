import socket
import logging
import time

class SocketClient:
    PORT = 6969
    MSG_SIZE = 20

    def __init__(self, host:str):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, self.PORT))
        return

    def close(self):
        self.sock.close()

    def send(self, data: bytes):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"data must be bytes, not {type(data)}")

        if len(data) != self.MSG_SIZE:
            raise ValueError(f"data must be exactly {self.MSG_SIZE} bytes")

        total = 0
        while total < self.MSG_SIZE:
            sent = self.sock.send(data[total:])
            if sent == 0:
                raise ConnectionError("socket connection broken")
            total += sent
        logging.debug(f"sent on socket: {data.hex()}")
        time.sleep(0.05)
        return


    def recv(self) -> bytes:
        data = b''
        while len(data) < self.MSG_SIZE:
            chunk = self.sock.recv(self.MSG_SIZE - len(data))
            if not chunk:
                raise ConnectionError("connection closed")
            data += chunk

        if len(data) != self.MSG_SIZE:
            raise RuntimeError("invalid message size")

        logging.debug(f"received on socket: {data.hex()}")
        time.sleep(0.05)
        return data
