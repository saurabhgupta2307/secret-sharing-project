from modules import generatekey, generatePrimes, getLargePrime
from modules.message import message
import argparse
import random
import os

parser = argparse.ArgumentParser()
parser.add_argument("-n", "--nodes", type=int)
parser.add_argument("-k", "--klimit", type=int)
parser.add_argument("-t", "--tolerance", type=int)
args = parser.parse_args()

if args.nodes == None:
	raise RuntimeError("Missing n (number of nodes)")
elif args.klimit == None:
	raise RuntimeError("Missing k")

n = args.nodes
k = args.klimit

if args.tolerance == None:
	t = 0
else: 
	t = min(args.tolerance, k-1, n-k-1)

secret = None
mode = 0

print "-" * 50
while secret == None or len(secret) not in range(1, 151):
	secret = raw_input("Enter the secret message (Max length 150): ")
	if len(secret) > 150:
		print "Message too long!"
	elif len(secret) < 1:
		print "Invalid message: empty input!"

print "-" * 50
print "Select a mode of verification:"
print "1. No Verification"
print "2. Information Theoretic Verification"
print "3. MAC Verification"
while mode not in range(1, 4):
	modeStr = raw_input("[1-3]: ")
	mode = int(modeStr)

print "-" * 50

secretNum = message.strToNum(secret)
primes = generatePrimes()
prime = getLargePrime(primes, secretNum, n)

key = generatekey(256)
buf = 1024

minPort = random.randint(12345, 23456)
senderPorts = range(minPort, minPort + n)
receiverPorts = range(minPort + n, minPort + 2*n)
nodePorts = range(minPort + 2*n, minPort + 3*n)

senderDict = {'msg': secret, 'n': n, 'k': k, 'mode': mode,
			  'prime': prime, 'key': key, 'ports': senderPorts,
			  'nodes': nodePorts}

recvrDict = {'k': k, 'mode': mode, 't': t, 'buffer': buf,
			  'prime': prime, 'key': key, 'ports': receiverPorts,
			  'nodes': nodePorts}

nodeDict = {'mode': mode, 'buffer': buf, 'sender': senderPorts,
			  'receiver': receiverPorts}

print "n = %d, k = %d, t = %d" % (n, k, t)
print "Sender ports:", senderPorts
print "Receiver ports:", receiverPorts
print "Server node ports:", nodePorts

fp = open("sender.txt", "w")
fp.write(str(senderDict))
fp.close()

fp = open("receiver.txt", "w")
fp.write(str(recvrDict))
fp.close()

fp = open("nodes.txt", "w")
fp.write(str(nodeDict))
fp.close()

cmdStr1 = "gnome-terminal -x sh -c \"python "
cmdStr2 = "; bash\""
nodePy = "node.py"
senderPy = "sender.py"
receiverPy = "receiver.py"
portOption = " -p "
faultyOption = " -f"
count_t = 0
faultyNodes = []

for nodePort in nodePorts:
	i = random.randint(0, n)
	nodePy2 = nodePy + portOption + str(nodePort)
	if i < t and count_t < t:
		nodePy2 += faultyOption
		count_t += 1
		faultyNodes.append(nodePort)
	
	commandString = cmdStr1 + nodePy2 + cmdStr2
	nodeFile = os.popen(commandString)

print "Faulty Nodes:", faultyNodes

commandString = cmdStr1 + senderPy + cmdStr2
senderFile = os.popen(commandString)

commandString = cmdStr1 + receiverPy + cmdStr2
receiverFile = os.popen(commandString)