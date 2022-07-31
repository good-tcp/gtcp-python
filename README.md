# GTCP
Simple and secure TCP framework

## Features
- TCP server and TCP client
- Simple event based messaging
- Secure automatic RSA encryption

## Installation
Using pip:
```shell
$ pip install gtcp
```
In Python:
```python
from gtcp import server, client
```
## Documentation
- [Server](#server)
  - [Initialization](#initialization)
  - [Handling connections](#handling-connections)
  - [Sending data](#sending-data)
  - [Recieving data](#recieving-data)
  - [Rooms](#rooms)
  - [Handling client disconnect](#handling-client-disconnect)
- [Client](#client)
  - [Initialization](#initialization-1)
  - [Sending data](#sending-data-1)
  - [Recieving data](#recieving-data-1)
- [Callbacks](#callbacks)

## Server
### Initialization
The server comes as a class. When creating a server with the class, the constructor takes 1 required parameter: the port the server will run on.
```python
from gtcp import server

# 's' is a TCP server that runs on port 8080
s = server(8080)
```
 Additionally, the server also takes 1 optional parameter: options. Options should be passed as a dictionary.
```python
from gtcp import server

# in this case, we are setting the "encrypted" option to true
s = server(8080, {"encrypted": True})
```

### Handling connections
Server objects have the ```.connection()``` method to handle new client connections. It takes 1 parameter: a callback function with a parameter for the socket.
```python
# The socket parameter will be set as an object that represents the connection
def connectionhandler(socket):
    pass
s.connect(connectionhandler)
```
The socket object is comprised of the IP address of the client, the socket id, the rooms the socket is in, methods for handling and sending data, and methods for handling rooms.
```python
def connectionhandler(socket):
    print(socket.id)
    # Output: A random UUIDv4 id
    print(socket.ip)
    # Output: 0.0.0.0
    print(socket.rooms)
    # Output: [<the id of the socket>, rooms, the, socket, is, in...]
s.connect(connectionhandler)
```

### Sending data
To send data, use the ```.emit()``` method. It takes at least two parameters: the event and any amount of data to be sent.

You can use the ```.emit()``` method with a server object or a socket object to send to all connected sockets or to a single socket respectively.
```python
def connectionhandler(socket):
    # This will send to the specific socket from the parameter
    socket.emit("login", username, password)
    # This will send to all sockets
    s.emit("login", username, password)
s.connect(connectionhandler)

# This will send to all sockets
s.emit("login", username, password)
```

### Recieving data
To recieve data from a socket, use it's ```.on()``` method. It takes two parameters: the event and a callback function with parameters for all the data.
```python
def connectionhandler(socket):
    def loginhandler(username, password):
        pass
    socket.on("login", loginhandler)
s.connect(connectionhandler)
```

### Rooms
To do certain interactions with specific sockets or to simple group and organize sockets, use rooms. Rooms are groups of sockets that you can adress seperately from others.

To get a socket to join a room, use the ```.join()``` method.
```python
def connectionhandler(socket):
    socket.join("room1")
    print(socket.rooms)
    #  Output: [<the id of the socket>, "room1"]
s.connect(connectionhandler)
```

To get a socket to leave a room (excluding the room of their own id), use the ```.leave()``` method.
```python
def connectionhandler(socket):
    socket.leave("room1")
    print(socket.rooms)
    # Output: [<the id of the socket>]
    socket.leave(socket.id)
    print(socket.rooms)
    # Output: [<the id of the socket>]
s.connect(connectionhandler)
```

To get a socket to leave all tooms except for the one is their own id, use the ```.clearrooms()``` method.
```python
def connectionhandler(socket):
    socket.clearrooms()
    print(socket.rooms)
    # Output: [<the id of the socket>]
s.connect(connectionhandler)
```

To send data to a specific room, use server object's ```.to()``` method. It takes one parameter (the room). The ```.to()``` methods can be chained to send to multiple rooms.
```python
def connectionhandler(socket):
    pass
socket.onconnection()

# This will emit to sockets in room1
socket.to("room1").emit("hello", "world")

# This will emit to both room1 and room2
socket.to("room1").to("room2").emit("hello", "world")
```

### Handling client disconnect
To a socket disconnect, listen with the ```.on()``` method for a the "end" event. The callback function takes no parameters
```python
def connectionhandler(socket):
    def endhandler():
        pass
    socket.on("end", endhandler)
s.connect(connectionhandler)
```

## Client
### Initialization
The client comes as a class. When creating a client with the class, the constructor takes 1 required parameters: the IP address and port of the server to connect to.
```python
from gtcp import client

# 'c' is a TCP client connected to a server ran on port 8080 
c = client("localhost:8080")
```
Additionally it takes 2 more optional parameters: a callback function to run when the client connects to the server and an options dictionary.
```python
from gtcp import client

# 'connectionhandler,' which is optional, is ran when it 'c' finishes connecting to the server
def clientcallback(c):
    pass

# 'c' is an encrypted TCP client connected to a server ran on port 8080
c = client("localhost:8080", {"encrypted": True}, clientcallback)
```

### Sending data
To send data to the server, use the ```.emit()``` method. It takes at least two parameters: the event and any amount of data to be sent.
```python
def clientcallback(c):
    # This will send to the server
    c.emit("login", username, password)

c = client("localhost:8080", clientcallback)

# This also sends to the server
c.emit("login", username, password)
```

### Recieving data
To recieve data from the server, use the client object's ```.on()``` method. It takes two parameters: the event and a callback function with parameters for all the data.
```python
def loginhandler(username, password):
    pass

def clientcallback(c):
    c.on("login", loginhandler)

c = client("localhost:8080", clientcallback)

# This also works
c.on("login", loginhandler)
```

## Callbacks
Sometimes, it is useful to have a more traditional request-response style API. In GTCP, this is achieved with callback functions.

Callback functions are any functions that are sent through an ```.emit()```. The function will be ran and supplied with parameters when it is called by the other side.
```python
# In client
def clientcallback(c):
    def loginCallback(confirm, userToken=""):
        if confirm:
            print(userToken)
    c.emit("login", username, password, loginCallback)
c = client("localhost:8080", clientcallback)

# In server
def connectionhandler(socket):
    def loginhandler(username, password, callback):
        if db.exists("username", username):
            if db.where("username", username)["password"] == password:
                callback(1, db.where("username", username)["userToken"])
            else:
                callback(0)
        else:
            callback(0)
    socket.on("login", loginhandler)
s.connect(connectionhandler)
```