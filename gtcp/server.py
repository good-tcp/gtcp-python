from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from uuid import uuid4
from threading import Thread
import socket
import json
from base64 import b64encode, b64decode
import struct

class partialserver:
    def __init__(self, base,includesockets=[]):
        self.__sockets = {i: base._server__sockets[i] for i in base._server__sockets}
        self.__include = [includesockets]
    def emit(self, event, *data):
        for socket in [i for i in self.__sockets if any([u in self.__include for u in self.__sockets[i]["rooms"]])]:
            encrypteddata = [event, []]
            for i in data:
                dtype = type(i)
                if not dtype in [str, float, int]:
                    raise Exception(f"Emit data type unsupported. {dtype}")
                bytev = bytearray(i, 'utf-8') if dtype == str else struct('i' if dtype == int else 'f', i)
                encrypted = [dtype.__name__, b64encode(self.__sockets[socket]["crypto"]["client"][1].encrypt(bytev)).decode()]
                encrypteddata[1].append(encrypted)
            self.__sockets[socket]["clientconn"][0].sendall(bytearray(json.dumps(encrypteddata), 'utf-8'))
    def to(self, room):
        self.__include.append(room)
        return self

class server:
    def __init__(self, port):
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__s.bind(('127.0.0.1', port))
        self.__s.listen(1)
        self.__sockets = {}
    def connection(self, callback):
        vsockref = self
        class vsock:
            def __init__(self, connection, id, crypto):
                self.id = id
                self.ip = connection[1]
                self.rooms = [id]
                self.__crypto = crypto
                self.__conn = connection
                self.__ehandler = {}
            def emit(self, event, *data):
                encrypteddata = [event, []]
                for i in data:
                    dtype = type(i)
                    if not dtype in [str, float, int]:
                        raise Exception(f"Emit data type unsupported. {dtype}")
                    bytev = bytearray(i, 'utf-8') if dtype == str else struct('i' if dtype == int else 'f', i)
                    encrypted = [dtype.__name__, b64encode(self.__crypto["client"][1].encrypt(bytev)).decode()]
                    encrypteddata[1].append(encrypted)
                self.__conn[0].sendall(bytearray(json.dumps(encrypteddata), 'utf-8'))
            def on(self, event, callback):
                self.__ehandler[event] = callback
            def join(self, room):
                vsockref._server__sockroom(0, self.id, room)
                self.rooms.append(room)
            def leave(self, room):
                vsockref._server__sockroom(1, self.id, room)
                if not room == self.id: self.rooms.remove(room)
            def clearrooms(self):
                vsockref._server__sockroom(2, self.id, "")
                self.rooms = [self.id]
        def startcon():
            while True:
                connection, client_address = self.__s.accept()
                def conngetdata():
                    key = RSA.generate(2048)
                    encryptor = PKCS1_OAEP.new(key)
                    socketid = str(uuid4())
                    self.__sockets[socketid] = {"clientconn": (connection, client_address), "crypto": {"server": (key, encryptor), "client": 0}, "rooms": [socketid]}
                    vsocket = vsock((connection, client_address), socketid, {"server": (key, encryptor)})
                    connection.sendall(key.publickey().exportKey(format='PEM', passphrase=None, pkcs=1))
                    while True:
                        data = connection.recv(1024)
                        print(data, self.__sockets[socketid]["crypto"]["client"], self.__sockets.keys())
                        if not self.__sockets[socketid]["crypto"]["client"]:
                            clientkey = RSA.importKey(data, passphrase=None)
                            clientencryptor = PKCS1_OAEP.new(clientkey)
                            self.__sockets[socketid]["crypto"]["client"] = (clientkey, clientencryptor)
                            vsocket._vsock__crypto["client"] = (clientkey, clientencryptor)
                            callback(vsocket)
                        else:
                            try:
                                datalist = [json.loads(str(data, 'utf-8'))[0], [str(self.__sockets[socketid]["crypto"]["server"][1].decrypt(b64decode(i[1])), 'utf-8') if i[0] == "str" else struct.unpack('i' if i[0] == 'int' else 'f', self.__sockets[socketid]["crypto"]["server"][1].decrypt(b64decode(i[1]))) for i in json.loads(str(data, 'utf-8'))[1]]]
                            except Exception:
                                raise Exception
                            else:
                                if datalist[0] in vsocket._vsock__ehandler.keys(): vsocket._vsock__ehandler[datalist[0]](*datalist[1])
                t1 = Thread(target=conngetdata)
                t1.start()
        t = Thread(target=startcon)
        t.start()
    def emit(self, event, *data):
        for socket in self.__sockets:
            encrypteddata = [event, []]
            for i in data:
                dtype = type(i)
                if not dtype in [str, float, int]:
                    raise Exception(f"Emit data type unsupported. {dtype}")
                bytev = bytearray(i, 'utf-8') if dtype == str else struct('i' if dtype == int else 'f', i)
                encrypted = [dtype.__name__, b64encode(self.__sockets[socket]["crypto"]["client"][1].encrypt(bytev)).decode()]
                encrypteddata[1].append(encrypted)
            self.__sockets[socket]["clientconn"][0].sendall(bytearray(json.dumps(encrypteddata), 'utf-8'))
    def to(self, room):
        modifieds = partialserver(self, includesockets=room)
        return modifieds
    def __sockroom(self, action, socket, room):
        if action == 0:
            self.__sockets[socket]["rooms"].append(room)
        elif action == 1 and not room == socket:
            self.__sockets[socket]["rooms"].remove(room)
        elif action == 2:
            self.__sockets[socket]["rooms"] = [socket]