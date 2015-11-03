from mysocket import mysocket
from message import message, secretSharing

NO_VERIFICATION = 1
AUX_INFO_VERIFICATION = 2
MAC_VERIFICATION = 3
SIGNATURE_VERIFICATION = 4

class receiver:

	def __init__(self, port, key):
		self.host, self.port = mysocket.gethostname(), port
		self.sock = mysocket()
		self.sock.bind((self.host, port))
		self.key = key

	def getShares(self, nodes, buffer):
		shares = []
		for node in nodes:
			self.sock.connect(node)
			share = self.sock.recv(buffer, ',')
			self.sock.close()
			shares.append([node, share])

		return shares

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

	def verifyMac(self, shares):
		acceptMac = []
		for share in shares:
			shareList = message.strToList(share)
			result = message.verifyMac(shareList[0], self.key, shareList[1])
			acceptMac.append(result)

		return acceptMac

	def verifyAuxInfo(self, shares):
		acceptAuxInfo = []
		sList, yList, bList, cList = self.unpackSharesAuxMode(shares)

		for share in shares:
			acceptAuxInfo.append(True)
			
		# TODO Verify shares and update acceptAuxInfo

		return [sList, acceptAuxInfo]

	def getReconSharesMacMode(self, shares, honestNodes, k):
		sharesForRecon = []

		for i in range(0, len(honestNodes)):
			if honestNodes[i] == True:
				shareList = message.strToList(shares[i]) #Unpack [shareStr, mac] from string
				share = message.strToList(shareList[0]) #Unpack share from shareStr
				sharesForRecon.append(share)

		return sharesForRecon[0:k]


	def getReconSharesAuxMode(self, shares, honestNodes, k):
		sharesForRecon = []

		for i in range(0, len(honestNodes)):
			if honestNodes[i] == True:
				sharesForRecon.append(shares[i])

		return sharesForRecon[0:k]


	def reconstructSecret(self, nodes, buffer, k, prime, mode=NO_VERIFICATION):
		shares = self.getShares(nodes, buffer)
		sharesForRecon = []

		if mode == MAC_VERIFICATION:
			honestNodes = self.verifyMac(shares)
			sharesForRecon = self.getReconSharesMacMode(shares, honestNodes, k)
		elif mode == AUX_INFO_VERIFICATION:
			sharesList, honestNodes = self.verifyAuxInfo(shares)
			sharesForRecon = self.getReconSharesAuxMode(sharesList, honestNodes, k)

		secretNum = secretSharing.reconstructSecret(sharesForRecon, k, prime)
		secret = message.numToStr(secretNum)
		return [secret, honestNodes]

