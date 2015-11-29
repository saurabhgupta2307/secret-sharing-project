#!/usr/bin/python

#############################################################
# CSE 539 (Applied Cryptography) Fall 2015 - Project        #
# Team: Saurabh Gupta, Omkar Kaptan                         #
# Instructor: Dr. Rida Bazzi                                #
#############################################################

"""Provides a socket wrapper module for communication involving
arbitrary length messages.

Class mysocket
~~~~~~~~~~~~~~
    Attributes: 
        sock - A socket object
    Constructor: 
        __init__(self, sock)
    Methods:
        bind(self, (host, port))
        getportnumber(self)
        connect(self, (host, port))
        listen(self, backlog)
        accept(self)
        send(self, msg, separator)
        recv(self, buffer, separator)
        close(self)
    Static Methods: 
        gethostname()
"""

#################### Import modules #########################
import socket

#################### Module Metadata ########################
__author__ = "Saurabh Gupta, Omkar Kaptan"
__email__ = "saurabhgupta@asu.edu, okaptan@asu.edu"
__license__ = "GPL"
__version__ = "1.0"

#############################################################
#                    Class: mysocket                        #
#############################################################
class mysocket:
    """A class for managing variable size message communication over sockets.

    Attributes:
        sock: A socket object."""

    def __init__(self, sock=None):
        """Initiates a stream socket object"""
        if sock == None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

    def bind(self, (host, port)):
        """Binds the socket to the given host and port.

        Args:
            (host, port): A tuple of string host and integer port values.

        Raises:
            TypeError: Error when port is not an integer value.
            ValueError: Error when port is not in range 1025 to 65535.
        """

        if type(port) not in [int, long]:
            raise TypeError("invalid port: int or long expected")
        elif port not in range(1025, 65535):
            raise ValueError("invalid port: value between 1025 and 65535 expected")

        self.sock.bind((host, port))

    def connect(self, (host, port)):
        """Connects to the socket given by host and port values.

        Args:
            (host, port): A tuple of string host and integer port values.
        """

        self.sock.connect((host, port))

    @staticmethod
    def gethostname():
        """Returns the current host name.

        Returns:
            An string value corresponding to the host name.
        """

        return socket.gethostname()

    def getportnumber(self):
        """Returns the socket port number.

        Returns:
            An integer value corresponding to the socket port number.
        """

        return self.sock.getsockname()[1]

    def accept(self):
        """ Accepts an incoming connection to the socket. """
        newSocket, addr = self.sock.accept()
        return (mysocket(newSocket), addr)

    def close(self):
        """ Closes the socket. """
        self.sock.close()

    def listen(self, backlog):
        """Listen for connections made to the socket. 

        Args:
            backlog: An integer value specifying the maximum number of queued 
                connections.
        """
        self.sock.listen(backlog)

    def send(self, msg, separator):
        """Sends the arbitrary length msg over the socket connection by 
        concatenating the message length at the beginning of the message 
        separated by the given separator. It sends the message in chunks 
        based on the number of bytes accepted by the receiver in preceding 
        transmission.

        Args:
            msg: A string message to be sent.
            separator: A string to be used as separator between message length and 
                message content.

        Returns:
            An integer corresponding to the total number of bytes sent.

        Raises:
            TypeError: Error when either msg or separator is not a string value.
        """

        if type(msg) != str:
            raise TypeError("invalid msg: str expected")
        elif type(separator) != str:
            raise TypeError("invalid separator: str expected")
        elif len(msg) == 0:
            return 0
       
        length = len(msg)
        totalsent = 0
        msg = str(length) + separator + msg

        while totalsent < length:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent

        return totalsent

    def recv(self, buffer, separator):
        """Receive an arbitrary length msg over the socket connection using 
        the message length concatenated at the beginning of the message 
        separated by the given separator. It receives the message in chunks 
        based on the buffer size.

        Args:
            buffer: A integer value specifying the buffer size for receiving data.
            separator: A string used as separator between message length and 
                message content.

        Returns:
            A string corresponding to the received message.

        Raises:
            RuntimeError: Error when no data received from the connection.
            TypeError: Error when buffer is not an integer, or when separator 
                is not a string.
            ValueError: Error when received message has invalid format.
        """

        if type(buffer) not in [int, long]:
            raise TypeError("invalid buffer: int or long expected")
        elif type(separator) != str:
            raise TypeError("invalid separator: str expected")

        chunk = self.sock.recv(buffer)
        if chunk == '':
            raise RuntimeError("socket connection broken")

        length = int(chunk.partition(separator)[0])
        if length == 0 or length == len(chunk):
            raise ValueError("invalid message received: separator or length not present")

        chunks = [chunk.partition(separator)[2]]
        bytes_recd = len(chunk) - len(str(length)) - 1

        while bytes_recd < length:
            chunk = self.sock.recv(min(length - bytes_recd, buffer))
            if chunk == '':
                raise RuntimeError("socket connection broken")
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)

        return ''.join(chunks)

##################### End of Code ###########################