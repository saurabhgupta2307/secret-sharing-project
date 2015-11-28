#!/usr/bin/python

#################### Import modules #########################
from modules import generatekey, generatePrimes, getLargePrime
from modules.message import message
import argparse
import random
import os
from time import time

parser = argparse.ArgumentParser()
parser.add_argument("-n", "--nodes", type=int)
parser.add_argument("-k", "--klimit", type=int)
parser.add_argument("-t", "--tolerance", type=int)
parser.add_argument("-v", "--verbose", dest="verbose", action='store_true')
parser.set_defaults(verbose=False)
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

startTime = time()

secretNum = message.strToNum(secret)
primes = generatePrimes()
prime = getLargePrime(primes, secretNum)

key = generatekey(256)
buf = 1024

minPort = random.randint(12345, 23456)
senderPorts = range(minPort, minPort + n)
receiverPorts = range(minPort + n, minPort + 2*n)
nodePorts = range(minPort + 2*n, minPort + 3*n)

senderDict = {'msg': secret, 'n': n, 'k': k, 'mode': mode,
			  'prime': prime, 'key': key, 'ports': senderPorts,
			  'nodes': nodePorts, 'startTime': startTime}

recvrDict = {'k': k, 'mode': mode, 't': t, 'buffer': buf,
			  'prime': prime, 'key': key, 'ports': receiverPorts,
			  'nodes': nodePorts, 'startTime': startTime}

nodeDict = {'mode': mode, 'buffer': buf, 'sender': senderPorts,
			  'receiver': receiverPorts, 'startTime': startTime}

print "n = %d, k = %d, t = %d" % (n, k, t)

fp = open("sender.txt", "w")
fp.write(str(senderDict))
fp.close()

fp = open("receiver.txt", "w")
fp.write(str(recvrDict))
fp.close()

fp = open("nodes.txt", "w")
fp.write(str(nodeDict))
fp.close()

cmdStr1 = "gnome-terminal -x sh"
cmdStr2 = " -c \"python "
cmdStr3 = "; bash"
cmdStr4 = "\""

nodePy = "node.py"
senderPy = "sender.py"
receiverPy = "receiver.py"
portOption = " -p "
faultyOption = " -f"
verboseOption = " -v"

faultyNodes = []

for nodePort in nodePorts:
	i = random.randint(0, n)
	nodePy2 = nodePy + portOption + str(nodePort)
	if i < t and len(faultyNodes) < t:
		nodePy2 += faultyOption
		faultyNodes.append(nodePort)
	
	commandString = cmdStr1 + cmdStr2 + nodePy2 
	if args.verbose == True:
		commandString += verboseOption
		commandString += cmdStr3 
	commandString += cmdStr4
	nodeFile = os.popen(commandString)

if len(faultyNodes) == 0:
	faultyNodes = None

print "Faulty Nodes:", faultyNodes

commandString = cmdStr1 + cmdStr2 + senderPy 
if args.verbose == True:
	commandString += verboseOption
commandString += cmdStr3 + cmdStr4
senderFile = os.popen(commandString)

commandString = cmdStr1 + cmdStr2 + receiverPy 
if args.verbose == True:
	commandString += verboseOption
commandString += cmdStr3 + cmdStr4
receiverFile = os.popen(commandString)

endTime = time()
print "Time taken to initiate nodes:", endTime - startTime
print "-" * 50

##################### End of Code ###########################