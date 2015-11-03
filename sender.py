from mysocket import mysocket
from message import message, secretSharing

NO_VERIFICATION = 1
AUX_INFO_VERIFICATION = 2
MAC_VERIFICATION = 3
SIGNATURE_VERIFICATION = 4

class sender:

	def __init__(self, port, key):
		self.host, self.port = mysocket.gethostname(), port
		self.sock = mysocket()
		self.sock.bind((self.host, port))
		self.key = key

	def sendSharesNoVrfy(self, shares, nodes):
		for i in range(0, len(shares)):
			share = message.listToStr(shares[i])
			msg = message.listToStr(share)
			self.sock.connect(node[i])
			self.sock.send(msg, ',')
			self.sock.close()

	def sendSharesMac(self, shares, nodes):
		for i in range(0, len(shares)):
			share = message.listToStr(shares[i])
			mac = generateMac(share, self.key)
			msg = message.listToStr([share, mac])
			self.sock.connect(node[i])
			self.sock.send(msg, ',')
			self.sock.close()

	def sendSharesAuxInfo(self, shares, nodes):
		yList = []
		bList = []
		cList = []

		for i in range(0, len(shares)):
			for j in range(0, len(shares)):
				if i == j:
					continue
				c, b, y = message.generateAuxInfo(shares[i][1])
				yList.append([i+1, j+1, y])
				bList.append([i+1, j+1, b])
				cList.append([i+1, j+1, c])

		for i in range(0, len(nodes)):
			share = shares[i]
			y = [element for element in yList if element[0] == i+1]
			b = [element for element in bList if element[1] == i+1]
			c = [element for element in cList if element[1] == i+1]
			msg = message.listToStr([share, y, b, c])
			self.sock.connect(node[i])
			self.sock.send(msg, ',')
			self.sock.close()


	def sendShares(self, msg, n, k, prime, nodes, mode=NO_VERIFICATION):
		shares = secretSharing.generateShares(msg, n, k, prime)

		if mode == NO_VERIFICATION:
			self.sendSharesNoVrfy(shares, nodes)
		elif mode == MAC_VERIFICATION:
			self.sendSharesMac(shares, nodes)
		elif mode == AUX_INFO_VERIFICATION:
			self.sendSharesAuxInfo(shares, nodes)
		elif mode == SIGNATURE_VERIFICATION:
			print "mode not defined yet"
		else:
			print "invalid mode"


