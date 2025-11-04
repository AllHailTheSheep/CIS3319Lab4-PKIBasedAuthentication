import socket

class BasicSocket:
    def __init__(self, addr, port, buffer_size=4096):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size
        self.s = None
        self.conn = None

    def listen(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.addr, self.port))
        self.s.listen(1)
        print(f"[LISTEN] Waiting on {self.addr}:{self.port}")
        self.conn, client_addr = self.s.accept()
        print(f"[CONNECTED] {client_addr}")
        return self.conn

    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.addr, self.port))
        self.conn = self.s
        print(f"[CONNECTED] to {self.addr}:{self.port}")
        return self.conn

    def send(self, msg_bytes: bytes):
        self.conn.sendall(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        data = self.conn.recv(buffer_size)
        return data

    def close(self):
        if self.conn:
            self.conn.close()
        if self.s:
            self.s.close()
