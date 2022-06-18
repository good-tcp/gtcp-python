from email import message
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import socket
from threading import *

class client:
    def __init__(self, conn, callback):
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__s.connect(tuple(conn.split(":")[i] if i == 0 else int(conn.split(":")[i]) for i in range(2)))
        key = RSA.generate(2048)
        encryptor = PKCS1_OAEP.new(key)
        self.__crypto = {"server": 0, "client": (key, encryptor)}
        self.__s.sendall(key.publickey().exportKey(format='PEM', passphrase=None, pkcs=1))
        while True:
            data = self.__s.recv(1024)
            if not self.__crypto["server"]:
                serverkey = RSA.importKey(data, passphrase=None)
                serverencryptor = PKCS1_OAEP.new(serverkey)
                self.__crypto["server"] = (serverkey, serverencryptor)
                callback()
            else:
                print(str(self.__crypto["client"][1].decrypt(data), 'utf-8'))
    def emit(self, event, *data):
        self.__s.sendall(self.__crypto["server"][1].encrypt(bytearray(data[0], 'utf-8')))
    def on(self, event, callback):
        pass

c = client("127.0.0.1:42069")