#!/usr/bin/python

"""
Description goes here..
"""

#################### Import modules #########################
import argparse
from time import time
from modules.mysocket import mysocket
from modules.message import message, secretSharing
from modules.message import NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION

#################### Module Metadata ########################
__author__ = "Saurabh Gupta, Omkar Kaptan"
__email__ = "saurabhgupta@asu.edu, okaptan@asu.edu"
__license__ = "GPL"
__version__ = "1.0"

#############################################################
#                    Class: receiver                        #
#############################################################

class receiver:
	"""A class for receiver operations.

	Attributes:
		host: A string value for the host name.
		port: An integer value for the port number.
		sock: A list of socket objects.
		key: A base64 format string key to be used for MAC tag verification.
	"""

	def __init__(self, ports, key=None):
		"""Initializes the receiver object with a list of sockets containing 
		one socket for each port in the ports list.

		Args:
			ports: A list of integer port number values for the receiver.
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
			print "Receiver socket (%s, %d) initiated" % (self.host, port)

	def getShareFromNode(self, node, buffer, index):
		"""Connects to the given node and receives the corresponding share
		from it, and returns the share string. 

		Args:
			node: A tuple (host, port) for the node to connect.
			buffer: An integer value specifying the input buffer size.
			index: An integer value specifying the index of socket to be used
				for connecting to the node.

		Returns:
			A string share value received from the node.

		Raises:
			TypeError: Error when node is not a list or tuple, or when either 
				buffer or index is not an integer.
			ValueError: Error when index is an invalid index value for the 
				list of sockets sock.
		"""

		if type(node) not in [tuple, list]:
			raise TypeError("invalid node: list or tuple expected")
		elif type(buffer) not in [int, long]:
			raise TypeError("invalid buffer: int or long expected")
		elif type(index) not in [int, long]:
			raise TypeError("invalid index: int or long expected")

		if index >= len(self.sock):
			raise ValueError("invalid index: out of range")

		print "-" * 50
		print "Attempting to connect to node (Port=%d)" % node[1]
		self.sock[index].connect(node)
		print "Node (Port=%d) connected" % node[1]
		share = self.sock[index].recv(buffer, ',')
		self.sock[index].close()
		print "Share received:", share
		return share

	def getShares(self, nodes, buffer):
		"""Gets shares from each of the nodes using the given buffer size, 
		and returns the list of shares. 

		Args:
			node: A tuple (host, port) for the node to connect.
			buffer: An integer value specifying the input buffer size.

		Returns:
			A list of string share values received from the nodes.

		Raises:
			TypeError: Error when node is not a list or tuple, or when buffer 
				is not an integer.
		"""

		if type(nodes) not in [tuple, list]:
			raise TypeError("invalid node: list or tuple expected")
		elif type(buffer) not in [int, long]:
			raise TypeError("invalid buffer: int or long expected")

		shares = []
		index = 0
		for node in nodes:
			share = self.getShareFromNode(node, buffer, index)
			shares.append(share)
			index += 1

		return shares

	def unpackSharesMacMode(self, shares):
		"""Unpacks a list of string shares of the form "[msg, tag]"
		into a list of all msg values and a list of all tag values.

		Args:
			shares: A list of string shares of the form "[msg, tag]"
				where msg and tag are strings. 

		Returns:
			A list containing 2 lists: a list of all msg values and a list 
				of all tag values from the list shares.

		Raises:
			TypeError: Error when shares is not a list.
		"""

		if type(shares) != list:
			raise TypeError("invalid shares: list expected")

		sList = []
		macList = []

		for share in shares:
			shareList = message.strToList(share)
			sList.append(shareList[0])
			macList.append(shareList[1])
			
		return [sList, macList]

	def unpackSharesAuxMode(self, shares):
		"""Unpacks a list of string shares of the form "[msg, y, b, c]"
		into 4 separate lists of msg, y, b and c values.

		Args:
			shares: A list of string shares of the form "[msg, y, b, c]"
				where msg, y, b and c are lists. 

		Returns:
			A list containing 4 lists, one list for each of msg, y, b and c 
				values extracted from the shares.

		Raises:
			TypeError: Error when shares is not a list.
		"""

		if type(shares) != list:
			raise TypeError("invalid shares: list expected")

		sList = []
		yList = []
		bList = []
		cList = []

		for share in shares:
			shareList = message.strToList(share)
			sList.append(shareList[0])
			yList += shareList[1]
			bList += shareList[2]
			cList += shareList[3]
			
		return [sList, yList, bList, cList]

	def verifyMac(self, sList, macList):
		"""Verifies the MAC tags in macList for corresponding share strings 
		in sList and returns a list of booleans representing the verification 
		status of each share.

		Args:
			sList: A list of string shares. 
			macList: A list of base64 string format MAC tags.

		Returns:
			A list of boolean values, one corresponding to each share in 
				sList. If acceptMac[i] = True, then macList[i] is a valid 
				MAC tag for sList[i], otherwise it is invalid.

		Raises:
			TypeError: Error when either sList or macList is not a list.
		"""

		if type(sList) != list:
			raise TypeError("invalid sList: list expected")
		elif type(macList) != list:
			raise TypeError("invalid macList: list expected")

		acceptMac = []
		for i in range(0, len(sList)):
			result = message.verifyMac(sList[i], self.key, macList[i])
			acceptMac.append(result)

		return acceptMac

	def verifyAuxInfo(self, sList, yList, bList, cList, t, prime):
		"""Verifies the auxilliary information specified by the yList, bList
		and cList lists for each share in sList list, and returns a list of 
		booleans representing the verification status of each share.

		Args:
			sList: A list of shares of the form [x, s] where x and s are 
				integers.
			yList: A list of lists of the form [i, j, y] where i, j and y 
				are integers.
			bList: A list of lists of the form [j, i, b] where i, j and b 
				are integers.
			cList: A list of lists of the form [j, i, c] where i, j and c 
				are integers.
			t: An integer representing the maximum number of faulty nodes.
			prime: A integer value specifying the prime field for modulo operations.

		Returns:
			A list of boolean values, one corresponding to each share in 
				sList. If acceptMac[i] = True, then sList[i] is a valid 
				share, otherwise it is invalid.

		Raises:
			TypeError: Error when any of sList, yList, bList or cList is not a 
				list, or when either t or prime is not an integer.
		"""

		if type(sList) != list:
			raise TypeError("invalid sList: list expected")
		elif type(yList) != list:
			raise TypeError("invalid yList: list expected")
		elif type(bList) != list:
			raise TypeError("invalid bList: list expected")
		elif type(cList) != list:
			raise TypeError("invalid cList: list expected")
		elif type(t) not in [int, long]:
			raise TypeError("invalid t: int or long expected")
		elif type(prime) not in [int, long]:
			raise TypeError("invalid prime: int or long expected")

		acceptAuxInfo = [True] * len(sList) 
		resultMatrix = [[True] * len(sList) for i in range(len(sList))]
		
		for i in range(0, len(sList)):
			si = sList[i][1]
			yiList = [element for element in yList if element[0] == i+1]
			biList = [element for element in bList if element[1] == i+1]
			ciList = [element for element in cList if element[1] == i+1]
			yiList = sorted(yiList, key=lambda x: x[1])
			biList = sorted(biList, key=lambda x: x[0])
			ciList = sorted(ciList, key=lambda x: x[0])

			for j in range(0, len(yiList)):
				yij = yiList[j][2]
				bij = biList[j][2]
				cij = ciList[j][2]
				if j < i:
					z = j
				else:
					z = j+1
				resultMatrix[i][z] = message.verifyAuxInfo(si, yij, bij, cij, prime)

			if t > 0 and resultMatrix[i].count(False) >= t:
				acceptAuxInfo[i] = False

		return acceptAuxInfo

	def getReconSharesMacMode(self, sList, honestNodes, k):
		"""Returns a list of k valid shares, of the form [x, y] where x and y 
		are integers, for reconstruction of the secret. Validity of shares is 
		ascertained by the corresponding boolean value in the list honestNodes 
		such that honestNodes[i] = True iff sList[i] is a valid share.

		Args:
			sList: A list of string shares of the form "[x, y]" where x and y 
				are integers.
			honestNodes: A list of booleans corresponding to each share in sList
				such that honestNodes[i] = True iff sList[i] is a valid share.
			k: An integer representing the number of shares required for 
				reconstructing the secret message.

		Returns:
			A list of k shares of the form [x, y] where x and y are integers.

		Raises:
			TypeError: Error when either sList or honestNodes is not a list, 
				or when k is not an integer.
			ValueError: Error when k is greater than the number of shares, or 
				when number of shares is not the same as the size of list 
				honestNodes.
		"""

		if type(sList) != list:
			raise TypeError("invalid sList: list expected")
		elif type(honestNodes) != list:
			raise TypeError("invalid honestNodes: list expected")
		elif type(k) not in [int, long]:
			raise TypeError("invalid k: int or long expected")
		elif k > len(sList):
			raise ValueError("invalid sList: expected %d or more shares" % k)
		elif len(sList) != len(honestNodes):
			raise ValueError("invalid sList or honestNodes: list counts expected to match")
		
		sharesForRecon = []

		for i in range(0, len(honestNodes)):
			if honestNodes[i] == True:
				share = message.strToList(sList[i]) 
				sharesForRecon.append(share)

		return sharesForRecon[0:k]


	def getReconSharesAuxMode(self, sList, honestNodes, k):
		"""Returns a list of k valid shares, of the form [x, y] where x and y 
		are integers, for reconstruction of the secret. Validity of shares is 
		ascertained by the corresponding boolean value in the list honestNodes 
		such that honestNodes[i] = True iff sList[i] is a valid share.

		Args:
			sList: A list of shares of the form [x, y] where x and y are integers.
			honestNodes: A list of booleans corresponding to each share in sList
				such that honestNodes[i] = True iff sList[i] is a valid share.
			k: An integer representing the number of shares required for 
				reconstructing the secret message.

		Returns:
			A list of k shares of the form [x, y] where x and y are integers.

		Raises:
			TypeError: Error when either sList or honestNodes is not a list, 
				or when k is not an integer.
			ValueError: Error when k is greater than the number of shares, or 
				when number of shares is not the same as the size of list 
				honestNodes.
		"""

		if type(sList) != list:
			raise TypeError("invalid sList: list expected")
		elif type(honestNodes) != list:
			raise TypeError("invalid honestNodes: list expected")
		elif type(k) not in [int, long]:
			raise TypeError("invalid k: int or long expected")
		elif k > len(sList):
			raise ValueError("invalid sList: expected %d or more shares" % k)
		elif len(sList) != len(honestNodes):
			raise ValueError("invalid sList or honestNodes: list counts expected to match")
		
		sharesForRecon = []

		for i in range(0, len(honestNodes)):
			if honestNodes[i] == True:
				sharesForRecon.append(sList[i])

		return sharesForRecon[0:k]

	def getReconSharesNoVrfy(self, sList, k):
		"""Returns a list of k shares, of the form [x, y] where x and y are 
		integers, for reconstruction of the secret.

		Args:
			sList: A list of string shares of the form "[x, y]" where x and y 
				are integers.
			k: An integer representing the number of shares required for 
				reconstructing the secret message.

		Returns:
			A list of k shares of the form [x, y] where x and y are integers.

		Raises:
			TypeError: Error when sList is not a list, or when k is not an integer.
			ValueError: Error when k is greater than the number of shares.
		"""

		if type(sList) != list:
			raise TypeError("invalid sList: list expected")
		elif type(k) not in [int, long]:
			raise TypeError("invalid k: int or long expected")
		elif k > len(sList):
			raise ValueError("invalid sList: expected %d or more shares" % k)

		sharesForRecon = []

		for share in sList:
			sharesForRecon.append(message.strToList(share))

		return sharesForRecon[0:k]

	def getFaultyNodes(self, nodes, honestNodes):
		"""Returns a list of integer values corresponding to the port numbers, 
		from list nodes, of faulty nodes using the boolean values in honestNodes
		such that if honestNodes[i] = false, nodes[i] is a faulty node. If list 
		honestNodes is empty, then the list of faulty nodes is also empty 
		because it signifies that the shares were not verified.

		Args:
			nodes: A list of tuples (host, port) where host is the host name and 
				port is the port number of the corresponding node.
			honestNodes: A list of booleans such that honestNodes[i] = true if 
				the share received from nodes[i] is valid. honestNodes is empty
				if the shares are not verified.

		Returns:
			A list of k shares of the form [x, y] where x and y are integers.

		Raises:
			TypeError: Error when either nodes or honestNodes is not a list.
			ValueError: Error when honestNodes is not empty and the number of 
				nodes is not equal to the size of honestNodes list.
		"""

		if type(nodes) != list:
			raise TypeError("invalid nodes: list expected")
		elif type(honestNodes) != list:
			raise TypeError("invalid honestNodes: list expected")
		elif len(honestNodes) != 0 and len(nodes) != len(honestNodes):
			raise ValueError("invalid nodes or honestNodes: size mismatch")

		faultyNodes = []
		if len(honestNodes) == 0:
			return faultyNodes

		for i in range(0, len(nodes)):
			if honestNodes[i] == False:
				faultyNodes.append(nodes[i][1])

		return faultyNodes


	def reconstructSecret(self, nodes, buffer, k, t, prime, mode=NO_VERIFICATION):
		"""Reconstruct the secret message and calculate the set of faulty nodes 
		based on the shares received from the nodes using the input buffer size
		specified by buffer argument.

		It uses the following steps:
		1. Connect to each node in nodes and receive corresponding shares using the
			input buffer size specified by buffer.
		2. Based on the mode argument, verify the validity of each share.
		3. Use k valid shares to reconstruct the secret message.
		4. Use the list of invalid shares to calculate the list of faulty nodes. 

		Args:
			nodes: A list of tuples (host, port) where host is the host name and 
				port is the port number of the corresponding node.
			buffer: An integer value specifying the input buffer size.
			k: An integer value representing the number of shares required for 
				reconstructing the secret message.
			t: An integer value representing the maximum number of faulty nodes.
			prime: An integer value specifying the prime field for modulo operations.
			mode: An integer value representing the mode of verification as defined
				in the module message.py

		Returns:
			A list containing the secret message string and a list of port numbers
				of faulty nodes.

		Raises:
			TypeError: Error when any of k, t, prime, buffer or mode is not an 
				integer, or when nodes is not a list.
			ValueError: Error when the mode is invalid.
		"""

		if type(nodes) != list:
			raise TypeError("invalid nodes: list expected")
		elif type(buffer) not in [int, long]:
			raise TypeError("invalid buffer: int or long expected")
		elif type(k) not in [int, long]:
			raise TypeError("invalid k: int or long expected")
		elif type(t) not in [int, long]:
			raise TypeError("invalid t: int or long expected")
		elif type(prime) not in [int, long]:
			raise TypeError("invalid prime: int or long expected")
		elif type(mode) not in [int, long]:
			raise TypeError("invalid mode: int or long expected")
		elif mode not in [NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION]:
			modeRange = "%d, %d or %d" % (NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION)
			raise ValueError("invalid mode: " + modeRange + " expected")

		shares = self.getShares(nodes, buffer)
		sharesForRecon = []
		honestNodes = []

		if mode == NO_VERIFICATION:
			sharesForRecon = self.getReconSharesNoVrfy(shares, k)
		elif mode == MAC_VERIFICATION:
			sList, macList = self.unpackSharesMacMode(shares)
			honestNodes = self.verifyMac(sList, macList)
			sharesForRecon = self.getReconSharesMacMode(sList, honestNodes, k)
		elif mode == AUX_INFO_VERIFICATION:
			sList, yList, bList, cList = self.unpackSharesAuxMode(shares)
			honestNodes = self.verifyAuxInfo(sList, yList, bList, cList, t, prime)
			sharesForRecon = self.getReconSharesAuxMode(sList, honestNodes, k)

		print "-" * 50
		print "Reconstructing Secret from Shares", sharesForRecon
		secretNum = secretSharing.reconstructSecret(sharesForRecon, k, prime)
		try:
			secret = message.numToStr(secretNum)
		except TypeError:
			secret = None
		faultyNodes = self.getFaultyNodes(nodes, honestNodes)

		return [secret, faultyNodes]


#############################################################
#					Boilerplate Code						#
#############################################################

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--verbose", dest="verbose", action='store_true')
	parser.set_defaults(verbose=False)
	args = parser.parse_args()

	fp = open("receiver.txt", "r")
	dictStr = fp.read()
	fp.close()

	recvrDict = message.strToList(dictStr)
	ports = recvrDict['ports']
	t = recvrDict['t']
	k = recvrDict['k']
	prime = recvrDict['prime']
	key = recvrDict['key']
	mode = recvrDict['mode']
	buf = recvrDict['buffer']
	nodePorts = recvrDict['nodes']
	initStartTime = recvrDict['startTime']
	addr = mysocket.gethostname()
	nodes = [(addr, portNum) for portNum in nodePorts]

	startTime = time()
	r = receiver(ports, key)
	secret, faultyNodes = r.reconstructSecret(nodes, buf, k, t, prime, mode)
	if len(faultyNodes) == 0:
		faultyNodes = None

	endTime = time()
	print "-" * 50
	print "Reconstructed message:", secret
	print "Faulty nodes:", faultyNodes
	print "-" * 50
	print "Time elapsed since initialization:", endTime - initStartTime
	print "Time taken to reconstruct secret :", endTime - startTime
	print "-" * 50

##################### End of Code ###########################