from mysocket import mysocket
from message import message, secretSharing

class sender:

	def __init__(self, port, key):
		self.host, self.port = mysocket.gethostname(), port
		self.sock = mysocket()
		self.sock.bind((self.host, port))
		self.key = key

	def sendSharesMac(self, shares, nodes):
		for i in range(0, len(shares)):
			share = message.listToStr(shares[i])
			mac = generateMac(share, self.key)
			self.sock.connect(node[i])
			msg = message.listToStr([share, mac])
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


	def sendShares(self, msg, n, k, prime, nodes, useMac=False):
		shares = secretSharing.generateShares(msg, n, k, prime)

		if useMac == True:
			self.sendSharesMac(shares, nodes)
		else:
			self.sendSharesAuxInfo(shares, nodes)


