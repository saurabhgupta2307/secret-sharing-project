from modules import generatekey, generatePrimes, getLargePrime
from modules.message import message
import argparse
import random

parser = argparse.ArgumentParser()
parser.add_argument("-n", "--nodes", type=int)
parser.add_argument("-k", "--klimit", type=int)
parser.add_argument("-t", "--tolerance", type=int)
args = parser.parse_args()

n = args.nodes
k = args.klimit
t = args.tolerance

secret = None
mode = 0

while secret == None or len(secret) not in range(1, 151):
	secret = raw_input("Enter the secret message (Max length 150):")
	if len(secret) > 150:
		print "Message too long!"
	elif len(secret) < 1:
		print "Invalid message: empty input!"

print "Select a mode of verification:"
print "1. No Verification"
print "2. Information Theoretic Verification"
print "3. MAC Verification"
while mode not in range(1, 4):
	modeStr = raw_input("[1-3]:")
	mode = int(modeStr)

secretNum = message.strToNum(secret)
primes = generatePrimes()
prime = getLargePrime(primes, secretNum, n)

key = generatekey(len(str(prime)))
buf = 1024

minPort = random.randint(12345, 23456)
senderPort = minPort
receiverPort = minPort + 1
nodePorts = range(minPort + 2, minPort + n + 2)

senderDict = {'msg': secret, 'n': n, 'k': k, 'mode': mode,
			  'prime': prime, 'key': key, 'port': senderPort,
			  'nodes': nodePorts}

recvrDict = {'k': k, 'mode': mode, 't': t, 'buffer': buf,
			  'prime': prime, 'key': key, 'port': receiverPort,
			  'nodes': nodePorts}

nodeDict = {'mode': mode, 'buffer': buf, 'sender': senderPort,
			  'receiver': receiverPort}

fp = open("sender.txt", "w")
fp.write(str(senderDict))
fp.close()

fp = open("receiver.txt", "w")
fp.write(str(recvrDict))
fp.close()

fp = open("nodes.txt", "w")
fp.write(str(nodeDict))
fp.close()