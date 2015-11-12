from modules.mysocket import mysocket
from modules.message import message, secretSharing
from modules import NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION
from time import time

class receiver:

	def __init__(self, ports, key=None):
		self.host, self.ports = mysocket.gethostname(), ports
		self.sock = []
		self.key = key
		for port in ports:
			self.sock.append(mysocket())
			self.sock[-1].bind((self.host, port))
			print "Receiver socket (%s, %d) initiated" % (self.host, port)

	def getShareFromNode(self, node, buffer, index):
		print "-" * 50
		print "Attempting to connect to node (Port=%d)" % node[1]
		self.sock[index].connect(node)
		print "Node (Port=%d) connected" % node[1]
		share = self.sock[index].recv(buffer, ',')
		self.sock[index].close()
		print "Share received:", share
		return share

	def getShares(self, nodes, buffer):
		shares = []
		index = 0
		for node in nodes:
			share = self.getShareFromNode(node, buffer, index)
			shares.append(share)
			index += 1

		return shares

	def unpackSharesMacMode(self, shares):
		sList = []
		macList = []

		for share in shares:
			shareList = message.strToList(share)
			sList.append(shareList[0])
			macList.append(shareList[1])
			
		return [sList, macList]

	def unpackSharesAuxMode(self, shares):
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
		acceptMac = []
		for i in range(0, len(sList)):
			result = message.verifyMac(sList[i], self.key, macList[i])
			acceptMac.append(result)

		return acceptMac

	def verifyAuxInfo(self, sList, yList, bList, cList, t, prime):
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
		sharesForRecon = []

		for i in range(0, len(honestNodes)):
			if honestNodes[i] == True:
				share = message.strToList(sList[i]) 
				sharesForRecon.append(share)

		return sharesForRecon[0:k]


	def getReconSharesAuxMode(self, sList, honestNodes, k):
		sharesForRecon = []

		for i in range(0, len(honestNodes)):
			if honestNodes[i] == True:
				sharesForRecon.append(sList[i])

		return sharesForRecon[0:k]

	def getReconSharesNoVrfy(self, sList, k):
		sharesForRecon = []

		for share in sList:
			sharesForRecon.append(message.strToList(share))

		return sharesForRecon[0:k]

	def getFaultyNodes(self, nodes, honestNodes):
		faultyNodes = []
		if len(honestNodes) == 0:
			return faultyNodes

		for i in range(0, len(nodes)):
			if honestNodes[i] == False:
				faultyNodes.append(nodes[i][1])

		return faultyNodes


	def reconstructSecret(self, nodes, buffer, k, t, prime, mode=NO_VERIFICATION):
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
		else:
			print "invalid mode"

		print "-" * 50
		print "Reconstructing Secret from Shares", sharesForRecon
		secretNum = secretSharing.reconstructSecret(sharesForRecon, k, prime)
		try:
			secret = message.numToStr(secretNum)
		except TypeError:
			secret = None
		faultyNodes = self.getFaultyNodes(nodes, honestNodes)

		return [secret, faultyNodes]


#------------------------------------------------------------
if __name__ == "__main__":
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