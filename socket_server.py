import time

ClientSockets = []


class Socket:
    def __init__(self, id, conn):
        self.clientid = id
        self.connection = conn


class SocketClass:

    def add_client(self, client, connection):
        s = Socket(client, connection)
        ClientSockets.append(s)
        self.connect(connection)

    def decode_frame(self, data):
        frame = bytearray(data)
        framePayloadLen = frame[1] - 128
        mask = frame[2:6]
        encP = frame[6:6 + framePayloadLen]
        payload = bytearray()
        for i in range(framePayloadLen):
            payload.append(encP[i] ^ mask[i % 4])
        return payload

    def send_frame(self, data):
        sendFrame = bytearray()
        sendFrame.append(129)
        sendFrame.append(len(data))
        sendFrame.extend(data)
        for sockets in ClientSockets:
            print(sendFrame)
            sockets.connection.request.sendall(sendFrame)

    def connect(self, connection):
        while True:
            data = connection.request.recv(1024)
            if not data:
                break
            payload = self.decode_frame(data)
            if len(payload) > 0:
                self.send_frame(payload)
            time.sleep(1)
