from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import socket
from threading import Thread
import netstruct

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
                        decrypted = self.__crypto["client"][1].decrypt(data)
                        datalist = netstruct.unpack(*netstruct.unpack(b"b$b$", decrypted))
                    except Exception:
                        raise Exception
                    else:
                        datalist = [str(i, 'utf-8') if type(i) == bytes else i for i in datalist]
                        if datalist[0] in self.__ehandler.keys(): self.__ehandler[datalist[0]](*datalist[1:len(datalist)])
        t = Thread(target=handleincoming)
        t.start()
        while self.unready:
            pass
    def emit(self, *data):
        types = b""
        mdata = []
        for i in data:
            dtype = type(i)
            if not dtype in [str, float, int]:
                raise Exception(f"Emit data type unsupported. {dtype}")
            types += b"b$" if dtype == str else b"i" if dtype == int else b"f"
            mdata.append(bytearray(i, 'utf-8') if dtype == str else i)
        encodeddata = netstruct.pack(b'b$b$', types, netstruct.pack(types, *mdata))
        self.__s.sendall(self.__crypto["server"][1].encrypt(encodeddata))
    def on(self, event, callback):
        self.__ehandler[event] = callback