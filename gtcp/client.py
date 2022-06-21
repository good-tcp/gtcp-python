from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import socket
from threading import *
import json
from base64 import b64encode, b64decode
import struct

class client:
    def __init__(self, conn):
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__s.connect(tuple(conn.split(":")[i] if i == 0 else int(conn.split(":")[i]) for i in range(2)))
        key = RSA.generate(2048)
        encryptor = PKCS1_OAEP.new(key)
        self.__crypto = {"server": 0, "client": (key, encryptor)}
        self.__s.sendall(key.publickey().exportKey(format='PEM', passphrase=None, pkcs=1))
        self.unready = True
        self.__ehandler = {}
        def handleincoming():
            while True:
                data = self.__s.recv(1024)
                if not self.__crypto["server"]:
                    serverkey = RSA.importKey(data, passphrase=None)
                    serverencryptor = PKCS1_OAEP.new(serverkey)
                    self.__crypto["server"] = (serverkey, serverencryptor)
                    self.unready = False
                else:
                    try:
                        datalist = [json.loads(str(data, 'utf-8'))[0], [str(self.__crypto["client"][1].decrypt(b64decode(i[1])), 'utf-8') if i[0] == "str" else struct.unpack('i' if i[0] == 'int' else 'f', self.__crypto["client"][1].decrypt(b64decode(i[1]))) for i in json.loads(str(data, 'utf-8'))[1]]]
                    except Exception:
                        raise Exception
                    else:
                        if datalist[0] in self.__ehandler.keys(): self.__ehandler[datalist[0]](*datalist[1])
        t = Thread(target=handleincoming)
        t.start()
        while self.unready:
            pass
    def emit(self, event, *data):
        encrypteddata = [event, []]
        for i in data:
            dtype = type(i)
            if not dtype in [str, float, int]:
                raise Exception(f"Emit data type unsupported. {dtype}")
            bytev = bytearray(i, 'utf-8') if dtype == str else struct('i' if dtype == int else 'f', i)
            encrypted = [dtype.__name__, b64encode(self.__crypto["server"][1].encrypt(bytev)).decode()]
            encrypteddata[1].append(encrypted)
        self.__s.sendall(bytearray(json.dumps(encrypteddata), 'utf-8'))
    def on(self, event, callback):
        self.__ehandler[event] = callback