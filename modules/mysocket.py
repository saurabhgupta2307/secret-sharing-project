import socket

class mysocket:
    
    def __init__(self, sock=None):
        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

    def bind(self, (host, port)):
        self.sock.bind((host, port))

    def connect(self, (host, port)):
        self.sock.connect((host, port))

    @staticmethod
    def gethostname():
        return socket.gethostname()

    def accept(self):
        newSocket, addr = self.sock.accept()
        return (mysocket(newSocket), addr)

    def close(self):
        self.sock.close()

    def listen(self, backlog):
        self.sock.listen(backlog)

    def send(self, msg, separator):
        length = len(msg)
        totalsent = 0
        msg = str(length) + separator + msg

        while totalsent < length:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent

        return totalsent

    def recv(self, buffer, separator):
        chunk = self.sock.recv(buffer)
        length = int(chunk.partition(separator)[0])
        chunks = [chunk.partition(separator)[2]]
        bytes_recd = len(chunk) - len(str(length)) - 1

        while bytes_recd < length:
            chunk = self.sock.recv(min(length - bytes_recd, buffer))
            if chunk == '':
                raise RuntimeError("socket connection broken")
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)

        return ''.join(chunks)