#!/usr/bin/python

#############################################################
# CSE 539 (Applied Cryptography) Fall 2015 - Project        #
# Team: Saurabh Gupta, Omkar Kaptan                         #
# Instructor: Dr. Rida Bazzi                                #
#############################################################

"""Provides an intermediate node class for receiving a share from 
the sender node and sending it to the receiver node upon request. 

In case the intermediate node is selected as faulty, it manipulates 
the share by substituting the share value with another value before 
sending it to the receiver node.

Class node
~~~~~~~~~~
    Attributes: 
        host - the host name
		port - the port number
		sock - a socket object
		share - the share received from the sender
		debug - a boolean debug mode indicator
    Constructor: 
        __init__(self, port)
    Methods:
		getNode(self)
		receiveShare(self, client, buf)
		manipulateShare(self, mode)
		sendShare(self, client)
		isShareReceived(self)
		run(self, senderPorts, receiverPorts, buf, mode, honest)

Boilerplate
~~~~~~~~~~~
***Code for demonstration purpose.***
The algorithm used is as follows:
	1. Take the port number and a boolean indicating whether or 
		not the node is faulty as command-line arguments.
	2. Read nodes.txt file to retreive the mode of verification, 
		and the port numbers used by sender and receiver nodes.
	3. Initiate node object with the port number. The object is 
		constructed with a socket initiated and bound.
	4. Open the socket for listening to the incoming connection 
		requests, and accept connections only from sender and 
		receiver nodes. If receiver node connects before the share 
		has been received, wait for the share to be received.
	5. Receive share from the sender.
	6. If the node is faulty, manipulate the share by substituting
		the share value with a new value.
	7. Send the share to the receiver node. 

Usage:
~~~~~~
Execute the following format command in a linux/unix shell.
./node.py -p <port> [-f]
	-p <port> is an integer value representing the port number 
		of intermediate node socket.
	-f is a boolean switch representing whether or not the  
		node is faulty. If used, the node is executed as a 
		faulty node.
"""

#################### Import modules #########################
import sys
import argparse
from time import time
from modules.mysocket import mysocket
from modules.util import genRandNum, message, secureFail
from modules.secretSharing import NO_VERIFICATION
from modules.secretSharing import MAC_VERIFICATION
from modules.secretSharing import AUX_INFO_VERIFICATION

#################### Module Metadata ########################
__author__ = "Saurabh Gupta, Omkar Kaptan"
__email__ = "saurabhgupta@asu.edu, okaptan@asu.edu"
__license__ = "GPL"
__version__ = "1.0"

#############################################################
#                    Class: node	                        #
#############################################################

class node:
	"""A class for intermediate node operations.

	Attributes:
		host: A string value for the host name.
		port: An integer value for the port number.
		sock: A socket object.
		share: A string value for the share received from the sender.
		debug: A boolean value indicating debug mode. 
	"""

	def __init__(self, port, debug=False):
		"""Initializes the node object with a socket object using the port 
		number specified by the argument port.

		Args:
			port: An integer port number for the node.
			debug: A boolean value indicating debug mode. 

		Raises:
			TypeError: Error when port is not an integer.
		"""

		try:
			if type(port) not in [int, long]:
				raise TypeError("invalid port: int or long expected")

			self.host, self.port = mysocket.gethostname(), port
			self.sock = mysocket()
			self.sock.bind((self.host, self.port))
			self.share = None
			self.debug = debug
			print "Node (%s, %d) initiated" % (self.host, self.port)
		except:
			if debug == True:
				raise
			else:
				secureFail()
				sys.exit()

	def getNode(self):
		"""Returns the host name and port number bound to the node object
		socket. 

		Returns:
			A tuple (host, port) where host is the host name and port is 
				the port number bound to the node object socket.
		"""

		return (self.host, self.port)

	def receiveShare(self, client, buf):
		"""Receive share from the client socket using the input buffer size
		specified by the buf argument, and set the value of share instance 
		variable. 

		Args:
			client: A mysocket object corresponding to the client from which
				the share is to be received.
			buf: An integer value specifying the input buffer size.

		Raises:
			TypeError: Error when client is not an instance of mysocket, or 
				when buffer is not an integer.
		"""

		if not isinstance(client, mysocket):
			raise TypeError("invalid client: mysocket object expected")
		elif type(buf) not in [int, long]:
			raise TypeError("invalid buf: int or long expected")

		share = client.recv(buf, ',')
		self.share = share

	def manipulateShare(self, mode):
		"""Manipulate the share value by replacing it with a random integer
		value. The manipulation algorithm varies based on the mode of 
		verification because the message format is different for different
		modes of verification. 

		When mode is NO_VERIFICATION, the share is of the form "[x, y]". The 
		manipulation converts the share into a list, replaces the y value 
		with a random integer value and converts it back to a string.

		When mode is AUX_INFO_VERIFICATION, the share is of the form 
		"[[x, s], yList, bList, cList]". The manipulation converts the share 
		into a list, replaces the s value with a random integer value and 
		converts it back to a string.

		When mode is MAC_VERIFICATION, the share is of the form "['[x, y]', tag]".
		The manipulation converts the share into a list, extracts the first 
		element '[x, y]', converts it into a list, replaces the y value with a 
		random integer value, converts it back to a string, replaces the original 
		'[x, y]' string with the new string in the list form share and converts 
		it back to a string.

		** Invoked by faulty nodes only. **

		Args:
			mode: An integer value representing the mode of verification as defined
				in the module message.py

		Raises:
			TypeError: Error when mode is not an integer.
			ValueError: Error when mode is not a valid value.
		"""

		if type(mode) not in [int, long]:
			raise TypeError("invalid mode: int or long expected")
		elif mode not in [NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION]:
			modeRange = "%d, %d or %d" % (NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION)
			raise ValueError("invalid mode: " + modeRange + " expected")

		share = message.strToList(self.share)
		if mode == NO_VERIFICATION:
			share[1] = genRandNum(share[1])
		elif mode == AUX_INFO_VERIFICATION:
			share[0][1] = genRandNum(share[0][1])
		elif mode == MAC_VERIFICATION:
			shareStr = share[0]
			shareList = message.strToList(shareStr)
			shareList[1] = genRandNum(shareList[1])
			shareStr = message.listToStr(shareList)
			share[0] = shareStr

		self.share = message.listToStr(share)

	def sendShare(self, client):
		"""Send the share stored in the instance variable share value to the
		specified client socket. 

		Args:
			client: A mysocket object corresponding to the client to which
				the share is to be sent.

		Raises:
			TypeError: Error when client is not an instance of mysocket.
		"""

		if not isinstance(client, mysocket):
			raise TypeError("invalid client: mysocket object expected")

		client.send(self.share, ',')

	def isShareReceived(self):
		"""Returns whether the share has been received from the sender and 
		stored in the instance variable share.

		Returns:
			A boolean value corresponding to whether or not the instance 
				variable share is empty. True when share is a non-empty value, 
				false otherwise.
		"""

		return self.share != None

	def run(self, senderPorts, receiverPorts, buf, mode=NO_VERIFICATION, honest=True):
		"""Listens to incoming connections, accepts connections from sender and 
		receiver nodes specified by lists of port numbers in senderPorts and 
		receiverPorts respectively, receives the share from the sender, manipulates 
		the share if it is a dishonest node (honest=False) and sends the share to 
		the receiver node.

		If the receiver is connected before the node has received the share from the 
		sender, then the node waits for the share to be received before initiating 
		the sending of share to the receiver node.

		Args:
			senderPorts: A list of integer values representing port numbers used by
				the sender node.
			receiverPorts: A list of integer values representing port numbers used by
				the receiver node.
			buf: An integer value specifying the input buffer size.
			mode: An integer value representing the mode of verification as defined
				in the module message.py
			honest: A boolean value specifying whether the node is honest or faulty.

		Raises:
			TypeError: Error when either buf or mode is not an integer, or when 
				either senderPorts or receiverPorts is not a list, or when honest
				is not a boolean.
			ValueError: Error when the mode is invalid.
		"""

		try:
			if type(senderPorts) != list:
				raise TypeError("invalid senderPorts: list expected")
			elif type(receiverPorts) != list:
				raise TypeError("invalid receiverPorts: list expected")
			elif type(buf) not in [int, long]:
				raise TypeError("invalid buf: int or long expected")
			elif type(mode) not in [int, long]:
				raise TypeError("invalid mode: int or long expected")
			elif type(honest) != bool:
				raise TypeError("invalid honest: bool expected")
			elif mode not in [NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION]:
				modeRange = "%d, %d or %d" % (NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION)
				raise ValueError("invalid mode: " + modeRange + " expected")

			self.sock.listen(5)
			clients = [None, None]
			tasksDone = [False, False]

			while tasksDone.count(True) != 2:
				if clients.count(None) > 0:
					c, addr = self.sock.accept()
					port = addr[1]
					if port in senderPorts:
						clients[0] = c
						print "Sender (Port=%d) connected" % port
					elif port in receiverPorts:
						clients[1] = c
						print "Receiver (Port=%d) connected" % port
					else:
						print "Unknown node %s connected. Dropping connection!" % addr
						c.close()
					
				if clients[0] != None and tasksDone[0] != True:
					self.receiveShare(clients[0], buf)
					clients[0].close()
					print "Share received:", self.share, "\n"
					if honest == False:
						self.manipulateShare(mode)
						print "Share manipulated:", self.share, "\n"
					tasksDone[0] = True
					print "-" * 50

				if clients[1] != None and tasksDone[0] == True and self.isShareReceived():
					self.sendShare(clients[1])
					clients[1].close()
					print "Sent:", self.share, "\n"
					tasksDone[1] = True

			self.sock.close()
		except:
			if self.debug == True:
				raise
			else:
				secureFail()
				sys.exit()


#############################################################
#					Boilerplate Code						#
#############################################################

if __name__ == "__main__":		#code to execute if called from command-line
	parser = argparse.ArgumentParser()
	parser.add_argument("-p", "--port", type=int)
	parser.add_argument("-f", dest="faulty", action='store_true')
	parser.add_argument("-d", "--debug", dest="debug", action='store_true')
	parser.set_defaults(debug=False)
	parser.set_defaults(faulty=False)
	
	args = parser.parse_args()
	if args.port == None:
		parser.error("Missing -p <port>")

	try:
		fp = open("nodes.txt", "r")
		dictStr = fp.read()
		fp.close()

		nodeDict = message.strToList(dictStr)
		mode = nodeDict['mode']
		buf = nodeDict['buffer']
		senderPorts = nodeDict['sender']
		receiverPorts = nodeDict['receiver']
		port = args.port

		if args.faulty != None:
			honest = not args.faulty
		else:
			honest = True

		if honest == False:
			print "**** Faulty Node ****"

		startTime = time()
		currNode = node(port, args.debug)
		currNode.run(senderPorts, receiverPorts, buf, mode, honest)
		endTime = time()

		print "Time of operation:", endTime - startTime
		print "-" * 50

	except SystemExit:
		pass
	except:
		if args.debug == True:
			raise
		else:
			secureFail()

##################### End of Code ###########################