import base64
import hashlib
import json
import time
import database

ClientSockets = {}


class SocketClass:
    def __init__(self, id, username, conn, status):
        self.clientid = id
        self.connection = conn
        self.user = username
        self.status = status

    def add_client(self):
        ClientSockets[self.clientid] = [self.user, self, self.status]
        self.connect(self.connection)

    def hash_user(self, obj):
        tokenbytes = base64.b64encode(hashlib.sha256((obj + "bcad35b6961a45159348ae8386c934cd").encode()).digest())
        hashedtoken = tokenbytes.decode('ascii')
        return hashedtoken

    def decode_frame(self, data):
        frame = bytearray(data)
        framePayloadLen = frame[1] - 128
        mask = frame[2:6]
        encP = frame[6:6 + framePayloadLen]
        payload = bytearray()
        for i in range(framePayloadLen):
            payload.append(encP[i] ^ mask[i % 4])
        return payload

    def send_all(self, data):
        sendFrame = bytearray()
        sendFrame.append(129)
        sendFrame.append(len(data))
        sendFrame.extend(data)
        for sockets in ClientSockets:
            ClientSockets[sockets][1].connection.request.sendall(sendFrame)

    def send_specific(self, data, user):
        sendFrame = bytearray()
        sendFrame.append(129)
        sendFrame.append(len(data))
        sendFrame.extend(data)
        user_id = self.hash_user(user)
        print(user)
        print(user_id)
        print(ClientSockets)
        if user_id in ClientSockets:
            ClientSockets[user_id][1].connection.request.sendall(sendFrame)
            self.connection.request.sendall(sendFrame)

    def send_specific2(self, data, user):
        sendFrame = bytearray()
        sendFrame.append(129)
        sendFrame.append(len(data))
        sendFrame.extend(data)
        user_id = self.hash_user(user)
        print(user)
        print(user_id)
        print(ClientSockets)
        if user_id in ClientSockets:
            ClientSockets[user_id][1].connection.request.sendall(sendFrame)

    def send_self(self, data):
        sendFrame = bytearray()
        sendFrame.append(129)
        sendFrame.append(len(data))
        sendFrame.extend(data)
        self.connection.request.sendall(sendFrame)

    def connect(self, connection):
        while True:
            data = connection.request.recv(1024)
            if not data:
                break
            payload = self.decode_frame(data)
            # print(payload)
            if len(payload) > 2:
                js = json.loads(payload.decode("utf-8"))
                if js["function"] == "message":
                    if "who" in js:
                        if js["who"] == "All":
                            database.insert_document("general_chat",
                                                     {"username": js["username"], "comment": js["comment"]})
                            self.send_all(payload)
                        else:
                            database.insert_document(js["username"] + "_" + js["who"],
                                                     {"username": js["username"], "comment": js["comment"]})
                            database.insert_document(js["who"] + "_" + js["username"],
                                                     {"username": js["username"], "comment": js["comment"]})
                            self.send_specific(payload, js["who"])
                elif js["function"] == "getusers":
                    send_json = {"function": "getusers"}
                    users = []
                    for sockets in ClientSockets:
                        users.append({"user": ClientSockets[sockets][0], "status": ClientSockets[sockets][2]})
                    send_json["users"] = users
                    self.send_self(json.dumps(send_json).encode('utf-8'))
                elif js["function"] == "challenge":
                    database.insert_document(js["username"] + "_" + js["who"],
                                             {"username": js["username"], "comment": "Sent a challenge"})
                    database.insert_document(js["who"] + "_" + js["username"],
                                             {"username": js["username"], "comment": "Sent a challenge"})
                    self.send_specific2(payload, js["who"])
                elif js["function"] == "play":
                    self.send_specific2(payload, js["who"])
                elif js["function"] == "won":
                    self.send_specific2(payload, js["who"])
                elif js["function"] == "lost":
                    self.send_specific2(payload, js["who"])
                elif js["function"] == "tie":
                    self.send_specific2(payload, js["who"])
            if len(payload) == 2:
                del ClientSockets[self.clientid]
                break
            time.sleep(1)
