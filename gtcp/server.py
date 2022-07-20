from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from uuid import uuid4
from threading import Thread
import socket
import struct

class partialserver:
    def __init__(self, base,includesockets=[]):
        self.__sockets = {i: base._server__sockets[i] for i in base._server__sockets}
        self.__include = [includesockets]
        self.__callbacks = base._server__callbacks
    def emit(self, *data):
        types = ""
        mdata = []
        for i in data:
            dtype = type(i)
            if not dtype in [str, float, int, type(lambda: None)]:
                raise Exception(f"Emit data type unsupported: {dtype}")
            if dtype == type(lambda: None):
                types += "51s"
                cbid = str(uuid4())
                for socket in [i for i in self.__sockets if any([u in self.__include for u in self.__sockets[i]["rooms"]])]:
                    self.__callbacks[f"{socket}:@gtcp:callback:{cbid}"] = i
                mdata.append(bytearray(f'@gtcp:callback:{cbid}', 'utf-8'))
            elif dtype == str:
                types += f"{len(i)}s"
                mdata.append(bytearray(i, 'utf-8'))
            else:
                types += "i" if dtype == int else "f"
                mdata.append(i)
        packeddata = struct.pack(types, *mdata)
        encodeddata = struct.pack(f'ii{len(types)}s{len(packeddata)}s', len(types), len(packeddata), bytearray(types, 'utf-8'), packeddata)
        for socket in [i for i in self.__sockets if any([u in self.__include for u in self.__sockets[i]["rooms"]])]:
            self.__sockets[socket]["clientconn"][0].sendall(self.__sockets[socket]["crypto"]["client"][1].encrypt(encodeddata))
    def to(self, room):
        self.__include.append(room)
        return self

class server:
    def __init__(self, port):
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__s.bind(('127.0.0.1', port))
        self.__s.listen(1)
        self.__sockets = {}
        self.__callbacks = {}
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
            def emit(self, *data):
                types = ""
                mdata = []
                for i in data:
                    dtype = type(i)
                    if not dtype in [str, float, int, type(lambda: None)]:
                        raise Exception(f"Emit data type unsupported: {dtype}")
                    if dtype == type(lambda: None):
                        types += "51s"
                        cbid = str(uuid4())
                        vsockref._server__callbacks[f"{self.id}:@gtcp:callback:{cbid}"] = i
                        mdata.append(bytearray(f'@gtcp:callback:{cbid}', 'utf-8'))
                    elif dtype == str:
                        types += f"{len(i)}s"
                        mdata.append(bytearray(i, 'utf-8'))
                    else:
                        types += "i" if dtype == int else "f"
                        mdata.append(i)
                packeddata = struct.pack(types, *mdata)
                encodeddata = struct.pack(f'ii{len(types)}s{len(packeddata)}s', len(types), len(packeddata), bytearray(types, 'utf-8'), packeddata)
                self.__conn[0].sendall(self.__crypto["client"][1].encrypt(encodeddata))
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
                    self.__sockets[socketid] = {"clientconn": (connection, client_address), "crypto": {"server": (key, encryptor), "client": 0}, "rooms": [socketid], "callbacks": {}}
                    vsocket = vsock((connection, client_address), socketid, {"server": (key, encryptor)})
                    connection.sendall(bytearray(socketid, 'utf-8') + key.publickey().exportKey(format='PEM', passphrase=None, pkcs=1))
                    data = connection.recv(1024)
                    clientkey = RSA.importKey(data, passphrase=None)
                    clientencryptor = PKCS1_OAEP.new(clientkey)
                    self.__sockets[socketid]["crypto"]["client"] = (clientkey, clientencryptor)
                    vsocket._vsock__crypto["client"] = (clientkey, clientencryptor)
                    callback(vsocket)
                    while True:
                        data = connection.recv(1024)
                        try:
                            decrypted = self.__sockets[socketid]["crypto"]["server"][1].decrypt(data)
                            datalist = struct.unpack(*struct.unpack("%ds%ss"%struct.unpack('ii', decrypted[:8]), decrypted[8:]))
                        except Exception:
                            del self.__sockets[socketid]
                            if "end" in vsocket._vsock__ehandler.keys(): vsocket._vsock__ehandler["end"]()
                            break
                        else:
                            datalist = [str(i, 'utf-8') if type(i) == bytes else i for i in datalist]
                            if datalist[0][37:52] == "@gtcp:callback:":
                                self.__callbacks[datalist[0]](*datalist[1:])
                                del self.__callbacks[datalist[0]]
                            elif datalist[0] in vsocket._vsock__ehandler.keys():
                                for i in range(len(datalist)):
                                    if type(datalist[i]) == str:
                                        if datalist[i][:15] == "@gtcp:callback:":
                                            cbeid = datalist[i]
                                            def vcallback(*args):
                                                self.emit(cbeid, *args)
                                            datalist[i] = vcallback
                                vsocket._vsock__ehandler[datalist[0]](*datalist[1:len(datalist)])
                t1 = Thread(target=conngetdata)
                t1.start()
        t = Thread(target=startcon)
        t.start()
    def emit(self, *data):
        types = ""
        mdata = []
        for i in data:
            dtype = type(i)
            if not dtype in [str, float, int, type(lambda: None)]:
                raise Exception(f"Emit data type unsupported: {dtype}")
            if dtype == type(lambda: None):
                types += "51s"
                cbid = str(uuid4())
                for socket in self.__sockets:
                    self.__callbacks[f"{socket}:@gtcp:callback:{cbid}"] = i
                mdata.append(bytearray(f'@gtcp:callback:{cbid}', 'utf-8'))
            elif dtype == str:
                types += f"{len(i)}s"
                mdata.append(bytearray(i, 'utf-8'))
            else:
                types += "i" if dtype == int else "f"
                mdata.append(i)
        packeddata = struct.pack(types, *mdata)
        encodeddata = struct.pack(f'ii{len(types)}s{len(packeddata)}s', len(types), len(packeddata), bytearray(types, 'utf-8'), packeddata)
        for socket in self.__sockets:
            self.__sockets[socket]["clientconn"][0].sendall(self.__sockets[socket]["crypto"]["client"][1].encrypt(encodeddata))
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