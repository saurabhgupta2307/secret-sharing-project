import binascii
import random
import hmac
import hashlib
import base64
import ast

NO_VERIFICATION = 1
AUX_INFO_VERIFICATION = 2
MAC_VERIFICATION = 3

def generatekey(length=256):
	if type(length) not in [int, long]:
		raise RuntimeError("invalid message: int or long expected")
	elif length < 1:
		length = 256
	return message.numToBase64(random.randint(0, 2**length - 1))


def generatePrimes():
	prime257Bit = 2**256 + 297
	prime321Bit = 2**320 + 27
	prime385Bit = 2**384 + 231
	primes = [prime257Bit, prime321Bit, prime385Bit]
	mersennePrimeExponents = [
		2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279]

	for exp in mersennePrimeExponents:
		primes.append(2 ** exp - 1)
	
	primes.sort() 
	return primes


def getLargePrime(primes, msgNum, n):
	largePrimes = [num for num in primes if num > max(msgNum, n)]
	if len(largePrimes) > 0:
		return largePrimes[0]
	else:
		return None


def extendedGCD(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = extendedGCD(b % a, a)
		return (g, x - (b // a) * y, y)


class message:

	@staticmethod
	def strToNum(msgString):
		if type(msgString) != str:
			raise RuntimeError("invalid message: string expected")
		return int(binascii.hexlify(msgString), 16)

	@staticmethod
	def numToStr(msgNum):
		if type(msgNum) not in [int, long]:
			raise RuntimeError("invalid message: int or long expected")
		return binascii.unhexlify('%x' % msgNum)

	@staticmethod
	def listToStr(msgList):
		if type(msgList) != list:
			raise RuntimeError("invalid message: list expected")
		return str(msgList)
		
	@staticmethod
	def strToBase64(msg):
		if type(msg) != str:
			raise RuntimeError("invalid message: string expected")
		return base64.b64encode(msg)

	@staticmethod
	def base64ToStr(b64Msg):
		try:
			return base64.b64decode(b64Msg)
		except binascii.Error:
			print "invalid operation: string not in base64"

	@staticmethod
	def numToBase64(msgNum):
		if type(msg) not in [int, long]:
			raise RuntimeError("invalid message: int or long expected")
		return message.strToBase64(bytes(msgNum))

	@staticmethod
	def strToList(msg):
		if type(msg) != str:
			raise RuntimeError("invalid message: str expected")
		
		msgList = ast.literal_eval(msg)
		return msgList


	@staticmethod
	def listToStr(msgList):
		if type(msgList) != list:
			raise RuntimeError("invalid message: list expected")
		
		return str(msgList)

	@staticmethod
	def generateHash(msg):
		if type(msg) != str:
			raise RuntimeError("invalid msg: string expected")
		dig = hashlib.sha256(msg).digest()
		hashValue = base64.b64encode(dig)
		return hashValue

	@staticmethod
	def verifyHash(msg, hashValue):
		if type(msg) != str or type(hashValue) != str:
			raise RuntimeError("invalid msg or hash: string expected")
		return message.generateHash(msg) == hashValue

	@staticmethod
	def generateMac(msg, key):
		if type(msg) != str or type(key) != str:
			raise RuntimeError("invalid msg or key: string expected")
		dig = hmac.new(key, msg, hashlib.sha256).digest()
		tag = base64.b64encode(dig)
		return tag

	@staticmethod
	def verifyMac(msg, key, tag):
		if type(msg) != str or type(key) != str or type(tag) != str:
			raise RuntimeError("invalid msg or key or tag: string expected")
		return message.generateMac(msg, key) == tag

	@staticmethod
	def generateAuxInfo(msgNum):
		if type(msgNum) not in [int, long]:
			raise RuntimeError("invalid msg: int or long expected")

		length = len(bin(msgNum)[2:])
		b = random.randint(0, 2**length - 1)
		y = random.randint(0, 2**length - 1)
		c = b * msgNum + y
		return [c, b, y]

	
	@staticmethod
	def verifyAuxInfo(s, y, b, c):
		if type(c) not in [int, long] or type(s) not in [int, long] or type(b) not in [int, long] or type(y) not in [int, long]:
			raise RuntimeError("invalid a or b or c or d: int or long expected")
		return c == s * b + y
	

class secretSharing:

	@staticmethod
	def modularInverse(num, prime):
		num = num % prime
		if num < 0:
			r = extendedGCD(prime, -num)[2]
		else:
			r = extendedGCD(prime, num)[2]
		return (prime + r) % prime


	@staticmethod
	def evaluatePolynomial(msgNum, coefficients, n, prime):
		if type(msgNum) not in [int, long]:
			raise ValueError("invalid msg: int or long expected")
		elif type(coefficients) != list:
			raise ValueError("invalid coefficients: list expected")
		elif type(n) not in [int, long]:
			raise ValueError("invalid x: int or long expected")
		
		shares = []
		for x in range(1, n+1):
			y = msgNum
			for i in range(1, len(coefficients) + 1):
				exp = (x ** i) % prime
				term = (exp * coefficients[i-1]) % prime
				y = (y + term) % prime
			
			shares.append([x, y])
		
		return shares

	@staticmethod
	def randomPolynomial(k, prime):
		coefficients = []
		for i in range(1, k):
			coefficients.append(random.randint(0, prime))	
		return coefficients	

	@staticmethod
	def generateShares(msg, n, k, prime):
		if type(n) not in [int, long] or type(k) not in [int, long]:
			raise ValueError("invalid n or k: int or long expected")
		elif n < k or n < 2 or k < 2:
			raise ValueError("invalid n or k value")

		if type(msg) in [int, long]:
			msgNum = msg
		elif type(msg) == str:
			msgNum = message.strToNum(msg)

		coefficients = secretSharing.randomPolynomial(k, prime)
		shares = secretSharing.evaluatePolynomial(msgNum, coefficients, n, prime)
		return shares

	@staticmethod
	def reconstructSecret(shares, k, prime):
		if type(shares) != list:
			raise ValueError("invalid shares: list expected")
		elif type(k) not in [int, long] or k < 2:
			raise ValueError("invalid k: int or long greater than 1 expected")
		elif k > len(shares):
			k = len(shares)

		xList, yList = zip(*shares)
		secret = 0

		for [xi, yi] in shares:
			numerator, denominator = 1, 1

			for xj in xList:
				if xi != xj:
					numerator = (numerator * -xj) % prime
					denominator = (denominator * (xi - xj)) % prime

			term = numerator * secretSharing.modularInverse(denominator, prime)
			secret = (secret + prime + (yi * term)) % prime

		return secret


#------------------------------------------------------------
'''
msg = "hello"
secretNum = message.strToNum(msg)
n, k = 4, 4

primes = generatePrimes()
prime = getLargePrime(primes, secretNum, n)
if prime is None:
	raise ValueError("message too long")

shares = secretSharing.generateShares(secretNum, n, k, prime)
#shares = sorted(shares, key=lambda x: x[0])
secret = secretSharing.reconstructSecret(shares, k, prime)

print len(msg), len(str(secretNum)), (secretNum == secret) 

#------------------------------------------------------------

shareStr = message.listToStr(shares)
shareNum = message.strToNum(shareStr)
shareBase64 = message.strToBase64(shareStr)

share2 = message.strToList(message.numToStr(shareNum))
share3 = message.strToList(message.base64ToStr(shareBase64))

print len(shareStr), len(str(shareNum)), len(shareBase64), shares == share2, shares == share3
print shareBase64
'''