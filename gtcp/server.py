from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from uuid import uuid4
import socket
from threading import *

class server:
    def __init__(self, port):
        self.__s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__s.bind(('127.0.0.1', port))
        self.__s.listen(1)
        self.__sockets = {}
    def connection(self, callback):
        def startcon():
            while True:
                connection, client_address = self.__s.accept()
                key = RSA.generate(2048)
                encryptor = PKCS1_OAEP.new(key)
                socketid = uuid4()
                self.__sockets[socketid] = {"clientconn": (connection, client_address), "crypto": {"server": (key, encryptor), "client": 0}, "rooms": [socketid]}
                connection.sendall(key.publickey().exportKey(format='PEM', passphrase=None, pkcs=1))
                data = connection.recv(1024)
                if not self.__sockets[socketid]["crypto"]["client"]:
                    clientkey = RSA.importKey(data, passphrase=None)
                    clientencryptor = PKCS1_OAEP.new(clientkey)
                    self.__sockets[socketid]["crypto"]["client"] = (clientkey, clientencryptor)
                    callback("e")
                else:
                    print(self.__sockets[socketid]["crypto"]["server"][1].decrypt(data))
        t = Thread(target=startcon)
        t.start()
    def emit(self, message):
        for socket in self.__sockets:
            self.__sockets[socket]["clientconn"][0].sendall(self.__sockets[socket]["crypto"]["client"][1].encrypt(bytearray(message, 'utf-8')))

s = server(42069)
s.connection(lambda socket:
    s.emit("test")
)