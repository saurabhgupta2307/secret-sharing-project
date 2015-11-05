from modules.mysocket import mysocket
from modules.message import message, secretSharing
from modules import NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION

class sender:

	def __init__(self, port, key=None):
		self.host, self.port = mysocket.gethostname(), port
		self.sock = mysocket()
		self.sock.bind((self.host, self.port))
		self.key = key
		print "Sender (%s, %d) initiated" % (self.host, self.port)

	def getSharesNoVrfy(self, shares):
		sharesToSend = []
		for share in shares:
			msg = message.listToStr(share)
			sharesToSend.append(msg)

		return sharesToSend

	def getSharesWithMac(self, shares):
		sharesToSend = []
		for share in shares:
			shareStr = message.listToStr(share)
			mac = message.generateMac(shareStr, self.key)
			msg = message.listToStr([shareStr, mac])
			sharesToSend.append(msg)

		return sharesToSend

	def getSharesWithAuxInfo(self, shares, prime):
		sharesToSend = []
		yList = []
		bList = []
		cList = []

		for i in range(0, len(shares)):
			for j in range(0, len(shares)):
				if i == j:
					continue
				c, b, y = message.generateAuxInfo(shares[i][1], prime)
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

	def sendShareToNode(self, share, node):
		self.sock.connect(node)
		print "-" * 50
		print "Node (Port=%d) connected" % node[1]
		self.sock.send(share, ',')
		self.sock.close()
		print "Share sent:", share

	def sendShares(self, msg, n, k, prime, nodes, mode=NO_VERIFICATION):
		if len(msg) > 150:
			raise RuntimeError("invalid message: too long")

		print "Secret message:", msg
		shares = secretSharing.generateShares(msg, n, k, prime)
		sharesToSend = []

		if mode == NO_VERIFICATION:
			sharesToSend = self.getSharesNoVrfy(shares)
		elif mode == MAC_VERIFICATION:
			sharesToSend = self.getSharesWithMac(shares)
		elif mode == AUX_INFO_VERIFICATION:
			sharesToSend = self.getSharesWithAuxInfo(shares, prime)

		########## Test Code ########################################
		if len(nodes) == 1:
			self.sendShareToNode(message.listToStr(sharesToSend), nodes[0])
			################# To be removed ############################
		else:
			for i in range(0, len(nodes)):
				self.sendShareToNode(sharesToSend[i], nodes[i])

		return sharesToSend


#------------------------------------------------------------
if __name__ == "__main__":
	# Test code
	key = 'MTM2MTUyODcyOTQwNDA2MzQwMQ=='
	r = sender(12341, key)
	nodes = [(mysocket.gethostname(), 12340)]
	n = 5
	k = 5
	msg = "lets try one really long message to see if it works for all messages."
	prime = 531137992816767098689588206552468627329593117727031923199444138200403559860852242739162502265229285668889329486246501015346579337652707239409519978766587351943831270835393219031728127
	mode = NO_VERIFICATION
	shares = r.sendShares(msg, n, k, prime, nodes, mode)
	print msg