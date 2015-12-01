#!/usr/bin/python

#############################################################
# CSE 539 (Applied Cryptography) Fall 2015 - Project        #
# Team: Saurabh Gupta, Omkar Kaptan                         #
# Instructor: Dr. Rida Bazzi                                #
#############################################################

"""Provides a sender node class for generating n secrets using 
(n, k) secret sharing scheme and sending them to n intermediate 
nodes. 

In addition, the sender generates verification information based
of the mode selected from the below options.
	1. No verification 
	2. Information Theoretic Verification 
	3. MAC Verification 

The verification information and the share are packaged together
and send to an intermediate node as a single string message. 

Class sender
~~~~~~~~~~~~
    Attributes: 
        host - the host name
        ports - list of port numbers
		sock - list of socket objects
		key - shared key for MAC mode verification
    Constructor: 
        __init__(self, ports, key)
    Methods:		
		sendShares(self, msg, n, k, prime, nodes, mode)
		sendShareToNode(self, share, node, index)
		getSharesNoVrfy(self, shares)
		getSharesWithMac(self, shares)
		getSharesWithAuxInfo(self, shares, prime)

Boilerplate
~~~~~~~~~~~
***Code for demonstration purpose.***
The algorithm used is as follows:
	1. Read sender.txt file to retreive the secret message 
		to be shared, the number of shares to be generated (n),
		the number of shares requried for reconstruction (k), 
		the prime number to be used for modulo operations, 
		the mode of verification, the shared key to be used 
		for MAC mode verification and the port numbers to be 
		used for initiating sender node sockets for communication
		with the intermediate nodes.
	2. Initiate sender object with the port numbers list and the
		shared key. The object is constructed with the corresponding 
		sockets initiated and bound.
	3. Generate n shares for the secret message along with the 
		verification information corresponding to the mode selected.
	4. Send one share each to the intermediate nodes. Each share 
		contains the share of the message along with the verification 
		information pertaining to the share.
"""

#################### Import modules #########################
import sys
from time import time
from modules.mysocket import mysocket
from modules.util import message 
from modules.secretSharing import secretSharing
from modules.secretSharing import NO_VERIFICATION
from modules.secretSharing import MAC_VERIFICATION
from modules.secretSharing import AUX_INFO_VERIFICATION

#################### Module Metadata ########################
__author__ = "Saurabh Gupta, Omkar Kaptan"
__email__ = "saurabhgupta@asu.edu, okaptan@asu.edu"
__license__ = "GPL"
__version__ = "1.0"

#############################################################
#					Class: sender							#
#############################################################
class sender:
	"""A class for sender operations.

	Attributes:
		host: A string value for the host name.
		ports: A list of integer values for the port numbers.
		sock: A list of socket objects.
		key: A base64 format string key to be used for MAC tag generation.
	"""

	def __init__(self, ports, key=None):
		"""Initializes the sender object with a list of sockets containing 
		one socket for each port in the ports list.

		Args:
			ports: A list of integer port number values for the sender.
			key: A base64 format string key to be used for MAC tag generation.
				Default value = None.

		Raises:
			TypeError: Error when key is not a string value, or when ports is not 
			a list of integers.
		"""

		if type(ports) != list:
			raise TypeError("invalid ports: list expected")
		elif key != None and type(key) != str:
			raise TypeError("invalid key: str expected")

		self.host, self.ports = mysocket.gethostname(), ports
		self.sock = []
		self.key = key
		for port in ports:
			self.sock.append(mysocket())
			self.sock[-1].bind((self.host, port))
			print "Sender socket (%s, %d) initiated" % (self.host, port)

	def getSharesNoVrfy(self, shares):
		"""Generates a list of string format shares without any verification
		related information. 

		Args:
			shares: A list of [int, int] lists corresponding to the shares
				to be sent to intermediate nodes.

		Returns:
			A list of string value shares.

		Raises:
			TypeError: Error when shares is not a list.
		"""

		if type(shares) != list:
			raise TypeError("invalid shares: list expected")

		sharesToSend = []
		for share in shares:
			msg = message.listToStr(share)
			sharesToSend.append(msg)

		return sharesToSend

	def getSharesWithMac(self, shares):
		"""Generates a list of string format shares with MAC tags for verification.

		For each share [x, y] in the list shares, where x and y are integers, 
		it performs the following steps:
		1. Convert it into a string '[x, y]'
		2. Generate a MAC tag for the message '[x, y]'
		3. Create a list ['[x, y]', tag] and convert it into string "['[x, y]', tag]"

		Args:
			shares: A list of [int, int] lists corresponding to the shares
				to be sent to intermediate nodes.

		Returns:
			A list of string value shares including MAC tags.

		Raises:
			TypeError: Error when shares is not a list.
		"""

		if type(shares) != list:
			raise TypeError("invalid shares: list expected")

		sharesToSend = []
		for share in shares:
			shareStr = message.listToStr(share)
			mac = secretSharing.generateMac(shareStr, self.key)
			msg = message.listToStr([shareStr, mac])
			sharesToSend.append(msg)

		return sharesToSend

	def getSharesWithAuxInfo(self, shares, prime):
		"""Generates a list of string format shares with auxilliary information
		for verification using information theoretic technique.

		Let the number of shares is n. For each share[i] = [x, s] in the list shares, 
		where x and s are integers, it performs the following steps:
		1. Generate n-1 values y[i][j], b[j][i] and c[j][i] such that 
			c[j][i] = b[j][i]*s[i] + y[i][j] and i != j.
		2. Create lists y[i] = {y: y = y[i][j], j != i}, b[i] = {b: b = b[j][i], j != i}, 
			c[i] = {c: c = c[j][i], j != i}
		3. Create a list [[x, s], y[i], b[i], c[i]]
		4. Convert it into string "[[x, s], y[i], b[i], c[i]]"

		Args:
			shares: A list of [int, int] lists corresponding to the shares
				to be sent to intermediate nodes.
			prime: A integer value specifying the prime field for modulo operations.

		Returns:
			A list of string value shares including auxilliary information for 
				information theoretic verification.

		Raises:
			TypeError: Error when shares is not a list, or when prime is not integer.
		"""

		if type(shares) != list:
			raise TypeError("invalid shares: list expected")
		elif type(prime) not in [int, long]:
			raise TypeError("invalid prime: int or long expected")

		sharesToSend = []
		yList = []
		bList = []
		cList = []

		for i in range(0, len(shares)):
			for j in range(0, len(shares)):
				if i == j:
					continue
				c, b, y = secretSharing.generateAuxInfo(shares[i][1], prime)
				yList.append([i+1, j+1, y])
				bList.append([j+1, i+1, b])
				cList.append([j+1, i+1, c])

		for i in range(0, len(shares)):
			share = shares[i]
			y = [element for element in yList if element[0] == i+1]
			b = [element for element in bList if element[1] == i+1]
			c = [element for element in cList if element[1] == i+1]
			msg = message.listToStr([share, y, b, c])
			sharesToSend.append(msg)

		return sharesToSend

	def sendShareToNode(self, share, node, index):
		"""Sends the given string share to the given node by connecting through 
		the socket sock[index] and using separator = ','. 

		Args:
			share: A string share to be sent.
			node: A tuple (host, port) for the node to send the share to.
			index: An integer value specifying the index of socket to be used
				for connecting to the node.

		Raises:
			TypeError: Error when share is not a string value, or when port is not 
			a list or tuple, or when index is not an integer.
		"""

		if type(share) != str:
			raise TypeError("invalid share: str expected")
		elif type(node) not in [list, tuple]:
			raise TypeError("invalid node: list or tuple expected")
		elif type(index) not in [int, long]:
			raise TypeError("invalid index: int or long expected")

		print "-" * 50
		print "Attempting to connect to node (Port=%d)" % node[1]
		self.sock[index].connect(node)
		print "Node (Port=%d) connected" % node[1]
		self.sock[index].send(share, ',')
		self.sock[index].close()
		print "Share sent:", share

	def sendShares(self, msg, n, k, prime, nodes, mode=NO_VERIFICATION):
		"""Generates n shares for the msg such that any k shares can be 
		used for reconstruction of the msg. According to the specified mode, 
		the verification information is added to each share and they are sent 
		to the given list of nodes. The value prime is used for as the order 
		of modulo operations.

		Args:
			msg: A string message for which the shares are to be sent.
			n: An integer number representing the number of shares to be generated.
			k: An integer number representing the number of shares required for 
				reconstruction.
			prime: An integer value to be used as the order of modulo operations.
			nodes: A list of (host, port) tuples for the intermediate nodes.
			mode: An integer value representing the verification mode as per options 
				defined in the message.py module.

		Returns:
			A list of string value shares sent to the given nodes.

		Raises:
			TypeError: Error when msg is not a string, or when either n, k, prime 
				or mode is not an integer, or when nodes is not a list.
			ValueError: Error when msg is longer than 150 characters, or when the 
				mode is invalid.
		"""

		if type(msg) != str:
			raise TypeError("invalid msg: str expected")
		elif len(msg) > 150:
			raise ValueError("invalid msg: expected 150 characters or less")
		elif type(n) not in [int, long]:
			raise TypeError("invalid n: int or long expected")
		elif type(k) not in [int, long]:
			raise TypeError("invalid k: int or long expected")
		elif type(prime) not in [int, long]:
			raise TypeError("invalid prime: int or long expected")
		elif type(nodes) != list:
			raise TypeError("invalid nodes: list expected")
		elif type(mode) != type(NO_VERIFICATION):
			raise TypeError("invalid mode: int or long expected")
		elif mode not in [NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION]:
			modeRange = "%d, %d or %d" % (NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION)
			raise ValueError("invalid mode: " + modeRange + " expected")

		print "Secret message:", msg
		shares = secretSharing.generateShares(msg, n, k, prime)
		sharesToSend = []

		if mode == NO_VERIFICATION:
			sharesToSend = self.getSharesNoVrfy(shares)
		elif mode == MAC_VERIFICATION:
			sharesToSend = self.getSharesWithMac(shares)
		elif mode == AUX_INFO_VERIFICATION:
			sharesToSend = self.getSharesWithAuxInfo(shares, prime)

		for i in range(0, len(nodes)):
			self.sendShareToNode(sharesToSend[i], nodes[i], i)

		msgSize = sys.getsizeof(msg)
		shareSize = sys.getsizeof(sharesToSend[0])
		totalSharesSize = shareSize * n

		print "-" * 50
		print "Secret Message:", msg
		print "Message Size: %d bytes" % msgSize
		print "Share Size: %d bytes" % shareSize
		print "Total Shares Size: %d bytes" % totalSharesSize
		print "-" * 50
		return sharesToSend


#############################################################
#					Boilerplate Code						#
#############################################################

if __name__ == "__main__":		#code to execute if called from command-line
	try:
		fp = open("sender.txt", "r")
		dictStr = fp.read()
		fp.close()

		senderDict = message.strToList(dictStr)
		ports = senderDict['ports']
		msg = senderDict['msg']
		n = senderDict['n']
		k = senderDict['k']
		prime = senderDict['prime']
		key = senderDict['key']
		mode = senderDict['mode']
		nodePorts = senderDict['nodes']
		initStartTime = senderDict['startTime']
		addr = mysocket.gethostname()
		nodes = [(addr, portNum) for portNum in nodePorts]

		startTime = time()
		s = sender(ports, key)
		shares = s.sendShares(msg, n, k, prime, nodes, mode)
		endTime = time()

		print "Time elapsed since initialization:", endTime - initStartTime
		print "Time taken to send shares:", endTime - startTime
		print "-" * 50
	except:
		print "An error has occured. Please try again later."
	
##################### End of Code ###########################