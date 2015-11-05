from modules.mysocket import mysocket
from modules import NO_VERIFICATION, MAC_VERIFICATION, AUX_INFO_VERIFICATION
from modules.message import message
import random
import argparse

class node:

	def __init__(self, port):
		self.host, self.port = mysocket.gethostname(), port
		self.sock = mysocket()
		self.sock.bind((self.host, self.port))
		self.share = None
		print "Node (%s, %d) initiated" % (self.host, self.port)

	def getNode(self):
		return (self.host, self.port)

	def receiveShare(self, client, buf):
		share = client.recv(buf, ',')
		self.setShare(share)

	def manipulateShare(self, mode):
		share = message.strToList(self.share)
		if mode in NO_VERIFICATION:
			share[1] = random.randint(0, share[1])
		elif mode == AUX_INFO_VERIFICATION:
			share[0][1] = random.randint(0, share[0][1])
		elif mode == MAC_VERIFICATION:
			shareStr = share[0]
			shareList = message.strToList(shareStr)
			shareList[1] = random.randint(0, shareList[1])
			shareStr = message.listToStr(shareList)
			share[0] = shareStr

		self.share = message.listToStr(share)

	def sendShare(self, client):
		client.send(self.share, ',')

	def isShareReceived(self):
		return self.share != None

	def getShare(self):
		return self.share

	def setShare(self, share):
		self.share = share

	def run(self, senderPort, receiverPort, buf, mode=NO_VERIFICATION, honest=True):
		self.sock.accept(5)
		clients = [None, None]
		tasksDone = [False, False]

		while tasksDone.count(True) != 2:
			if clients.count(None) > 0:
				c, addr = self.sock.accept()
				port = c.getportnumber()
				if port == senderPort:
					clients[0] = c
					print "Sender (Port=%d) connected" % port
				elif port == receiverPort:
					clients[1] = c
					print "Receiver (Port=%d) connected" % port
				else:
					print "Unknown node (%s, %d) connected. Dropping connection!" % (addr, port)
					c.close()
				
			if clients[0] != None:
				self.receiveShare(clients[0], buf)
				clients[0].close()
				print "Share received:", self.getShare(), "\n"
				if honest == False:
					self.manipulateShare(mode)
					print "Share manipulated:", self.getShare(), "\n"
				tasksDone[0] = True
				print "-" * 50

			if clients[1] != None and tasksDone[0] == True and self.isShareReceived():
				self.sendShare(clients[1])
				clients[1].close()
				print "Sent:", self.getShare(), "\n"
				tasksDone[1] = True

		self.sock.close()


#------------------------------------------------------------
if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-p", "--port", type=int)
	parser.add_argument("-f", "--faulty", type=bool)
	args = parser.parse_args()

	if args.port == None:
		raise RuntimeError("No port specified")

	fp = open("nodes.txt", "r")
	dictStr = fp.read()
	fp.close()

	nodeDict = message.strToList(dictStr)
	mode = nodeDict['mode']
	buf = nodeDict['buffer']
	senderPort = nodeDict['sender']
	receiverPort = nodeDict['receiver']
	port = args.port
	if args.faulty != None:
		honest = not args.faulty
	else:
		honest = True
