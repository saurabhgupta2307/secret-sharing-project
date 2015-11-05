from mysocket import mysocket

class node:
	share = None

	def __init__(self, port):
		self.host, self.port = mysocket.gethostname(), port
		self.sock = mysocket()
		self.sock.bind((self.host, self.port))

	def receiveShare(self, client):
		self.share = client.recv(buffer, ',')

	def sendShare(self, client):
		client.send(self.share, ',')

	def run(self, senderPort, receiverPort):
		self.sock.accept(5)
		clients = [None, None]
		tasksDone = [False, False]

		while tasksDone.count(True) != 2:
			if clients.count(None) > 0:
				c, addr = self.sock.accept()
				if c.getportnumber() == senderPort:
					clients[0] = c
				elif c.getportnumber() == receiverPort:
					clients[1] = c
				else:
					c.close()
				
			if clients[0] != None:
				self.receiveShare(clients[0])
				clients[0].close()
				tasksDone[0] = True

			if clients[1] != None and tasksDone[0] == True and self.share != None:
				self.sendShare(clients[1])
				clients[1].close()
				tasksDone[1] = True

		self.sock.close()
