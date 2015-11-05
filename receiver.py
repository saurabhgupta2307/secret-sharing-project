from modules.mysocket import mysocket
from modules.message import message, secretSharing
from modules import NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION

class receiver:

	def __init__(self, port, key=None):
		self.host, self.port = mysocket.gethostname(), port
		self.sock = mysocket()
		self.sock.bind((self.host, self.port))
		self.key = key
		print "Receiver (%s, %d) initiated" % (self.host, self.port)

	def getShareFromNode(self, node, buffer):
		self.sock.connect(node)
		print "-" * 50
		print "Node (Port=%d) connected" % node[1]
		share = self.sock.recv(buffer, ',')
		self.sock.close()
		print "Share received:", share
		return share

	def getShares(self, nodes, buffer):
		shares = []
		
		######### Test Code ################
		if len(nodes) == 1:
			self.sock.listen(5)
			c, addr = self.sock.accept()
			shares = c.recv(buffer, ',')
			c.close()
			self.sock.close()
			return message.strToList(shares)
		######## To be removed ##############
		
		for node in nodes:
			share = self.getShareFromNode(node, buffer)
			shares.append(share)

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

			if resultMatrix[i].count(False) >= t:
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
		for i in range(0, len(nodes)):
			if honestNodes[i] == True:
				faultyNodes.append(nodes[i][1])


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

		secretNum = secretSharing.reconstructSecret(sharesForRecon, k, prime)
		secret = message.numToStr(secretNum)
		faultyNodes = self.getFaultyNodes(nodes, honestNodes)
		print "-" * 50
		print "Reconstructed message:", secret
		print "Faulty nodes:", faultyNodes
		return [shares, secret, honestNodes]


#------------------------------------------------------------
if __name__ == "__main__":
	fp = open("receiver.txt", "r")
	dictStr = fp.read()
	fp.close()

	recvrDict = message.strToList(dictStr)
	port = recvrDict['port']
	t = recvrDict['t']
	k = recvrDict['k']
	prime = recvrDict['prime']
	key = recvrDict['key']
	mode = recvrDict['mode']
	buf = recvrDict['buffer']
	nodePorts = recvrDict['nodes']
	addr = mysocket.gethostname()
	nodes = [(addr, portNum) for portNum in nodePorts]

	'''
	r = receiver(12340, key)
	nodes = [(mysocket.gethostname(), 12341)]
	shares, secret, honestNodes = r.reconstructSecret(nodes, buffer, k, t, prime, mode)
	print secret
	'''