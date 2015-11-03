from mysocket import mysocket
from message import message, secretSharing

class receiver:

	def __init__(self, port, key):
		self.host, self.port = mysocket.gethostname(), port
		self.sock = mysocket()
		self.sock.bind((self.host, port))
		self.key = key

	def verifyMac(self, shares):
		acceptMac = []
		for share in shares:
			shareList = message.strToList(share[1])
			result = message.verifyMac(shareList[0], self.key, shareList[1])
			acceptMac.append(result)

		return acceptMac

	def reconstructSecret(self, nodes, buffer, k, prime, useMac=False):
		shares = self.getShares(nodes, buffer)

		sharesForRecon = []
		if useMac == True:
			acceptMac = self.verifyMac(shares)
			for i in range(0, len(acceptMac)):
				if acceptMac[i] == True:
					shareList = message.strToList(shares[i][1])
					sharesForRecon.append(shares[i][1])


	def getShares(self, nodes, buffer):
		shares = []
		for node in nodes:
			self.sock.connect(node)
			share = self.sock.recv(buffer, ',')
			self.sock.close()
			shares.append([node, share])

		return shares