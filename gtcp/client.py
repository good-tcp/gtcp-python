from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import socket
from threading import Thread
import struct

class client:
    def __init__(self, conn, *callback):
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__s.connect(tuple(conn.split(":")[i] if i == 0 else int(conn.split(":")[i]) for i in range(2)))
        key = RSA.generate(2048)
        encryptor = PKCS1_OAEP.new(key)
        self.__crypto = {"server": 0, "client": (key, encryptor)}
        self.__s.sendall(key.publickey().exportKey(format='PEM', passphrase=None, pkcs=1))
        self.__ehandler = {}
        def handleincoming():
            while True:
                data = self.__s.recv(1024)
                if not self.__crypto["server"]:
                    serverkey = RSA.importKey(data, passphrase=None)
                    serverencryptor = PKCS1_OAEP.new(serverkey)
                    self.__crypto["server"] = (serverkey, serverencryptor)
                    if(len(callback) == 1):
                        callback[0](self)
                else:
                    try:
                        decrypted = self.__crypto["client"][1].decrypt(data)
                        datalist = struct.unpack(*struct.unpack("%ds%ss"%struct.unpack('ii', decrypted[:8]), decrypted[8:]))
                    except Exception:
                        raise Exception
                    else:
                        datalist = [str(i, 'utf-8') if type(i) == bytes else i for i in datalist]
                        if datalist[0] in self.__ehandler.keys(): self.__ehandler[datalist[0]](*datalist[1:len(datalist)])
        t = Thread(target=handleincoming)
        t.start()
    def emit(self, *data):
        if data[0] == "end":
            raise Exception('Unsupported emit event: "end"')
        types = ""
        mdata = []
        for i in data:
            dtype = type(i)
            if not dtype in [str, float, int]:
                raise Exception(f"Emit data type unsupported: {dtype}")
            types += f"{len(i)}s" if dtype == str else "i" if dtype == int else "f"
            mdata.append(bytearray(i, 'utf-8') if dtype == str else i)
            packeddata = struct.pack(types, *mdata)
        encodeddata = struct.pack(f'ii{len(types)}s{len(packeddata)}s', len(types), len(packeddata), bytearray(types, 'utf-8'), packeddata)
        try:
            self.__s.sendall(self.__crypto["server"][1].encrypt(encodeddata))
        except TypeError:
            raise Exception("Server credentials not recieved yet")
    def on(self, event, callback):
        self.__ehandler[event] = callback