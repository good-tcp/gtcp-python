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
    - [Sending Data](#sending-data)
    - [Recieving data](#recieving-data)
    - [Rooms](#rooms)
- [Client](#client)
    - [Initialization](#initialization-1)
    - [Sending Data](#sending-data-1)
    - [Recieving data](#recieving-data-1)

## Server
### Initialization
The server comes as a class. When creating a server with the class, the constructor takes 1 parameter: the port the server will run on.
```python
from gtcp import server

# 's' is a TCP server that runs on port 8080
s = server(8080)
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
    socket.emit("login", username, password, email)
    # This will send to all sockets
    s.emit("login", username, password, email)
s.connect(connectionhandler)

# This will send to all sockets
s.emit("login", username, password, email)
```

### Recieving data
To recieve data from a socket, use it's ```.on()``` method. It takes two parameters: the event and a callback function with parameters for all the data.
```python
def connectionhandler(socket):
    def loginhandler(username, password, email):
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

## Client
### Initialization
The client comes as a class. When creating a client with the class, the constructor takes 1 parameter: the IP address and port of the server to connect to.
```python
from gtcp import client

# 'c' is a TCP client connected to a server ran on port 8080 
c = client("localhost:8080")
```

### Sending data
To send data to the server, use the ```.emit()``` method. It takes at least two parameters: the event and any amount of data to be sent.
```python
c = client("localhost:8080")

# This will send to the server
c.emit("login", username, password, email)
```

### Recieving data
To recieve data from the server, use the client object's ```.on()``` method. It takes two parameters: the event and a callback function with parameters for all the data.
```python
c = client("localhost:8080")

def loginhandler(username, password, email):
    pass
c.on("login", loginhandler)
```