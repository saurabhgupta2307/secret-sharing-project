#!/usr/bin/python

#############################################################
# CSE 539 (Applied Cryptography) Fall 2015 - Project        #
# Team: Saurabh Gupta, Omkar Kaptan                         #
# Instructor: Dr. Rida Bazzi                                #
#############################################################

"""Code for demonstration purpose.

The algorithm used is as follows:
	1. Takes the number of intermediate nodes (n), the number 
		of shares required for reconstruction (k) and the 
		number of faulty nodes (t) as command line arguments.
	2. Accepts secret message (maximum length 150 characters) 
		and verification mode (1, 2 or 3) as console input.
	3. Generates a prime number larger than the integer 
		equivalent of the secret message as the order of 
		modulo operations.
	4. Generates a 256-bit cryptographically secure random 
		key to be shared with sender and receiver nodes for 
		MAC mode verification.
	5. Generates lists of random port numbers to be used by
		all the nodes for socket communication.
	6. Writes the appropriate data values into 3 files, 
		sender.txt, receiver.txt and nodes.txt, for the 
		corresponding nodes to use during secret sharing 
		operations.
	7. Constructs unix command strings to initiate one bash
		shell for each node for multi-threaded execution,
		while randomly selecting, at most t, intermediate 
		nodes as dishonest.

Global Methods:
~~~~~~~~~~~~~~~
	getSecretMessage(limit)
	getVerificationMode()
	generateFile(data, fileName)
	initNodes(n, t, nodePorts, verbose)
	initClient(clientPy, verbose)

Usage:
~~~~~~
Execute the following format command in a linux/unix shell.
./main.py -n <nodes> -k <shares> [-t <faulty-nodes>] [-v] 
	-n <nodes> is an integer value representing the number 
		of intermediate nodes and number of shares to be 
		generated.
	-k <shares> is an integer value representing the number 
		of shares requried for reconstruction in the 
		(n, k) secret sharing scheme.
	-t <faulty-nodes> is an integer value representing the 
		maximum number of faulty nodes allowed. Default 
		Value is 0.
	-v is for verbose mode. If used, the intermediate node 
		shell windows remain open after the execution is 
		complete. Otherwise, they terminate.
"""

#################### Import modules #########################
import argparse
import random
import os
from time import time
from modules.util import generatekey, getLargePrime, message

#################### Module Metadata ########################
__author__ = "Saurabh Gupta, Omkar Kaptan"
__email__ = "saurabhgupta@asu.edu, okaptan@asu.edu"
__license__ = "GPL"
__version__ = "1.0"

######### Global variables for command strings ##############
cmdStr1 = "gnome-terminal -x sh"
cmdStr2 = " -c \"python "
cmdStr3 = "; bash"
cmdStr4 = "\""

nodePy = "node.py"
senderPy = "sender.py"
receiverPy = "receiver.py"
portOption = " -p "
faultyOption = " -f"

#################### Method Definitions #####################

def getSecretMessage(limit):
	"""Gets a secret message from the user such that the message is not 
	longer than the limit, and returns the message. 

	Args:
		limit: An integer defining the maximum message length allowed. 

	Returns:
		A string secret as per valid user input.
	"""

	secret = None
	while secret == None or len(secret) not in range(1, limit+1):
		secret = raw_input("Enter the secret message (Max length %d): " % limit)
		if len(secret) > limit:
			print "Invalid message: too long!"
		elif len(secret) < 1:
			print "Invalid message: empty input!"

	return secret

def getVerificationMode():
	"""Gets an integer value in the range [1-3], corresponding to the verification 
	modes, from the user and returns the value. 

	Returns:
		An integer in the range [1-3] for the corresponding verification mode.
	"""

	mode = 0
	print "Select a mode of verification:"
	print "1. No Verification"
	print "2. Information Theoretic Verification"
	print "3. MAC Verification"

	while mode not in range(1, 4):
		modeStr = raw_input("[1-3]: ")
		try:
			mode = int(modeStr)
			if mode not in range(1, 4):
				raise ValueError()
		except:
			print "Invalid input: integer in range [1-3] expected."
			mode = 0

	return mode

def generateFile(data, fileName):
	"""Writes a dictionary object data into the file with specified fileName. 

	Args:
		data: A dictionary object to be written to the file.
		fileName: A string representing the name of the file to write into.

	Raises:
		TypeError: Error when data is not a dictionary, or when fileName is
			not a string.
	"""

	if type(data) != dict:
		raise TypeError("invalid data: dict expected")
	elif type(fileName) != str:
		raise TypeError("invalid fileName: str expected")

	fp = open(fileName, "w")
	fp.write(str(data))
	fp.close()

def initNodes(n, t, nodePorts, verbose):
	"""Initializes n intermediate nodes, while selecting at most t of them 
	as faulty, and invokes bash shell windows for each node by constructing 
	command strings for them. When verbose is true, the windows stay active 
	after completion, else they terminate. 

	Args:
		n: An integer defining the number of nodes. 
		t: An integer defining the maximum number of faulty nodes.
		nodePorts: A list of integers representing the port numbers for nodes.
		verbose: A boolean specifying whether or not the verbose option is 
			selected in the command string.

	Returns:
		A list of integers representing port numbers of faulty nodes.
	"""

	faultyNodes = []

	for nodePort in nodePorts:
		i = random.randint(0, 2)
		nodePy2 = nodePy + portOption + str(nodePort)
		
		if i == 1 and len(faultyNodes) < t:
			nodePy2 += faultyOption
			faultyNodes.append(nodePort)
		
		commandString = cmdStr1 + cmdStr2 + nodePy2 
		if verbose == True:
			commandString += cmdStr3 
		
		commandString += cmdStr4
		nodeFile = os.popen(commandString)

	if len(faultyNodes) == 0:
		faultyNodes = None

	return faultyNodes

def initClient(clientPy, verbose):
	"""Initializes a client node using the clientPy code and invokes a bash 
	shell window by constructing a command string for it. Verbose option is 
	passed to the clientPy for reference. 

	Args:
		clientPy: A string representing the file name of code script to be 
			executed for the client.
		verbose: A boolean specifying whether or not the verbose option is 
			selected in the command string.
	"""

	commandString = cmdStr1 + cmdStr2 + clientPy 
	commandString += cmdStr3 + cmdStr4
	senderFile = os.popen(commandString)


#############################################################
#					Boilerplate Code						#
#############################################################

if __name__ == "__main__":		#code to execute if called from command-line
	parser = argparse.ArgumentParser(description="Initiate secret sharing demo")
	parser.add_argument("-n", "--nodes", type=int)
	parser.add_argument("-k", "--klimit", type=int)
	parser.add_argument("-t", "--tolerance", type=int)
	parser.add_argument("-v", "--verbose", dest="verbose", action='store_true')
	parser.set_defaults(verbose=False)

	args = parser.parse_args()

	if args.nodes == None:
		parser.error("Missing -n <nodes>")
	elif args.klimit == None:
		parser.error("Missing -k <klimit>")

	n = args.nodes
	k = args.klimit

	if args.tolerance == None:
		t = 0
	else: 
		t = min(args.tolerance, k-1, n-k-1)

	print "-" * 50
	secret = getSecretMessage(150)
	print "-" * 50
	mode = getVerificationMode()
	print "-" * 50

	startTime = time()

	secretNum = message.strToNum(secret)
	prime = getLargePrime(secretNum)
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

	generateFile(senderDict, "sender.txt")
	generateFile(recvrDict, "receiver.txt")
	generateFile(nodeDict, "nodes.txt")

	faultyNodes = initNodes(n, t, nodePorts, args.verbose)
	initClient(senderPy, args.verbose)
	initClient(receiverPy, args.verbose)

	endTime = time()

	print "n = %d, k = %d, t = %d" % (n, k, t)
	print "Faulty Nodes:", faultyNodes
	print "Time taken to initiate nodes:", endTime - startTime
	print "-" * 50

##################### End of Code ###########################