#!/usr/bin/python

#################### Import modules #########################
from modules.mysocket import mysocket
from modules.message import message, secretSharing
from modules import NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION
import sys
import argparse
from time import time


#############################################################
#                    Class: sender	                        #
#############################################################
class sender:

	def __init__(self, ports, key=None):
		self.host, self.ports = mysocket.gethostname(), ports
		self.sock = []
		self.key = key
		for port in ports:
			self.sock.append(mysocket())
			self.sock[-1].bind((self.host, port))
			print "Sender socket (%s, %d) initiated" % (self.host, port)

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

	def sendShareToNode(self, share, node, index):
		print "-" * 50
		print "Attempting to connect to node (Port=%d)" % node[1]
		self.sock[index].connect(node)
		print "Node (Port=%d) connected" % node[1]
		self.sock[index].send(share, ',')
		self.sock[index].close()
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


#------------------------------------------------------------
if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--verbose", dest="verbose", action='store_true')
	parser.set_defaults(verbose=False)
	args = parser.parse_args()

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
	
##################### End of Code ###########################