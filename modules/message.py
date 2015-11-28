#!/usr/bin/python


#################### Import modules #########################
import binascii
import random
import hmac
import hashlib
import base64
import ast

########### Global Variables for Verification Modes #########
NO_VERIFICATION = 1
AUX_INFO_VERIFICATION = 2
MAC_VERIFICATION = 3

#################### Method Definitions #####################

def generatekey(length=256):
	"""Generates a random base64 key of given length.

	Checks if the given length is a valid int or long, enforces
	the length to be of minimum value 256, generates the key of 
	corresponding bit length and returns it in base64 format.

	Args:
		length: An integer defining the bit length of the key. 
				Default value: 256

	Returns:
		A randomly generated key of given length in base64 format.

	Raises:
		TypeError: Error when the provided length is not an int or long.
	"""

	if type(length) not in [int, long]:
		raise TypeError("invalid message: int or long expected")
	elif length < 256:
		length = 256

	return message.numToBase64(random.randint(0, 2**length - 1))


def generatePrimes():
	"""Generates set of prime numbers using Marsenne Primes and 
	known large primes.

	Returns:
		A list of generated prime numbers.
	"""

	prime257Bit = 2**256 + 297
	prime321Bit = 2**320 + 27
	prime385Bit = 2**384 + 231
	primes = [prime257Bit, prime321Bit, prime385Bit]
	mersennePrimeExponents = [
		13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279]

	for exp in mersennePrimeExponents:
		primes.append(2 ** exp - 1)
	
	primes.sort() 
	return primes


def getLargePrime(num):
	"""Returns a prime number larger than the given num.

	Generates the list of prime numbers using generatePrimes, and returns
	the smallest prime in primes list larger than num. If num is larger
	than all primes, return None.

	Args:
		num: An integer value corresponding to which the required prime 
			 should be larger.

	Returns:
		A integer prime value larger than the given num.

	Raises:
		TypeError: Error when num is not an integer. 
	"""

	if type(num) not in [int, long]:
		raise TypeError("invalid num: int or long expected")

	primes = generatePrimes()
	largePrimes = [n for n in primes if n > num]
	if len(largePrimes) > 0:
		return largePrimes[0]
	else:
		return None


def extendedGCD(a, b):
	"""Recursively calculates and returns the extended Euclidean GCD 
	of the given values of a and b.

	Validates the types of a and b to be integers. Recursively calculates 
	the extended Euclidean GCD using ax + by = g equation and returns the 
	tuple (g, x, y).

	Args:
		a: An integer specifying the first number for GCD calculation.
		b: An integer specifying the second number for GCD calculation.

	Returns:
		A tuple (g, x, y) where g, x and y are integers such that they
		satisfy the equation ax + by = g

	Raises:
		TypeError: Error when either a or b is not an integer value. 
	"""

	if type(a) not in [int, long]:
		raise TypeError("invalid a: int or long expected")
	elif type(b) not in [int, long]:
		raise TypeError("invalid b: int or long expected")

	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = extendedGCD(b % a, a)
		return (g, x - (b // a) * y, y)


#############################################################
#					 Class: message		 					#
#############################################################

class message:
	"""A class of static methods for message manipulations."""

	@staticmethod
	def strToNum(msgString):
		"""Converts a string message to corresponding integer value.

		Args:
			msgString: A string message to be converted.

		Returns:
			An integer corresponding to the string message.

		Raises:
			TypeError: Error when msgString is not a string value.
		"""

		if type(msgString) != str:
			raise TypeError("invalid message: str expected")
		return int(binascii.hexlify(msgString), 16)

	@staticmethod
	def numToStr(msgNum):
		"""Converts a integer message to corresponding string value.

		Args:
			msgNum: An integer message to be converted.

		Returns:
			A string corresponding to the given integer msgNum.

		Raises:
			TypeError: Error when msgNum is not an integer value.
		"""

		if type(msgNum) not in [int, long]:
			raise TypeError("invalid message: int or long expected")
		return binascii.unhexlify('%x' % msgNum)

	@staticmethod
	def listToStr(msgList):
		"""Converts a list form message to corresponding string value.

		Args:
			msgList: A list message to be converted.

		Returns:
			A string corresponding to the given list msgList.

		Raises:
			TypeError: Error when msgList is not a list.
		"""

		if type(msgList) != list:
			raise TypeError("invalid message: list expected")
		return str(msgList)
		
	@staticmethod
	def strToBase64(msg):
		"""Converts a string to base64.

		Args:
			msg: A string message to be converted.

		Returns:
			A base64 string corresponding to the given string msg.

		Raises:
			TypeError: Error when msg is not a string value.
		"""

		if type(msg) != str:
			raise TypeError("invalid message: string expected")
		return base64.b64encode(msg)

	@staticmethod
	def base64ToStr(b64Msg):
		"""Converts a base64 message string to base-256 string.

		Args:
			msg: A base64 string message to be converted.

		Returns:
			A string corresponding to the given base64 string b64Msg.

		Raises:
			TypeError: Error when b64Msg is not a string.
			ValueError: Error when b64Msg is not a value base64 string value.
		"""

		if type(b64Msg) != str:
			raise TypeError("invalid b64Msg: str expected")

		try:
			return base64.b64decode(b64Msg)
		except binascii.Error:
			raise ValueError("invalid b64Msg: base64 format string expected")

	@staticmethod
	def numToBase64(msgNum):
		"""Converts a integer message to base64 string.

		Args:
			msgNum: An integer message to be converted.

		Returns:
			A base64 string corresponding to the given integer msgNum.

		Raises:
			TypeError: Error when msgNum is not an integer value.
		"""

		if type(msgNum) not in [int, long]:
			raise TypeError("invalid message: int or long expected")
		return message.strToBase64(bytes(msgNum))

	@staticmethod
	def strToList(msg):
		"""Converts a string message encapsulating a list to the 
		correspodning list.

		Args:
			msg: An list encapsulating string to be converted.

		Returns:
			A list encapsulated in the string msg.

		Raises:
			TypeError: Error when msg is not an string.
			ValueError: Error when msg is not an string encapsulating a list.
		"""

		if type(msg) != str:
			raise TypeError("invalid msg: str expected")
		
		try:
			msgList = ast.literal_eval(msg)
			return msgList
		except ValueError:
			raise ValueError("invalid msg: can not be converted to list")


	@staticmethod
	def listToStr(msgList):
		"""Converts a list type message to a string.

		Args:
			msgList: An list message to be converted.

		Returns:
			A string corresponding to the given msgList.

		Raises:
			TypeError: Error when msgList is not a list.
		"""

		if type(msgList) != list:
			raise TypeError("invalid msgList: list expected")
		
		return str(msgList)

	@staticmethod
	def generateHash(msg):
		"""Generate a base64 SHA256 hash for the given msg. 

		Args:
			msg: A string for which the hash is required.

		Returns:
			A base64 string SHA256 hash for the given msg.

		Raises:
			TypeError: Error when msg is not a string value.
		"""

		if type(msg) != str:
			raise TypeError("invalid msg: str expected")
		dig = hashlib.sha256(msg).digest()
		hashValue = base64.b64encode(dig)
		return hashValue

	@staticmethod
	def verifyHash(msg, hashValue):
		"""Canonically verifies the given hashValue for the given msg. 

		Args:
			msg: A string message for which the hash is to be verified.
			hashValue: A string hash value to be verified.

		Returns:
			A boolean corresponding to the verification. True if hashValue
			is a valid hash for the msg, and False otherwise.

		Raises:
			TypeError: Error when either the msg or hashValue is not a string.
		"""

		if type(msg) != str:
			raise TypeError("invalid msg: string expected")
		elif type(hashValue) != str:
			raise TypeError("invalid hash: string expected")
		return message.generateHash(msg) == hashValue

	@staticmethod
	def generateMac(msg, key):
		"""Generates a base64 SHA256 based HMAC tag for the given msg using the 
		given key. 

		Args:
			msg: A string message for which the MAC tag is to be generated.
			key: A string key to be used for generating the MAC tag.

		Returns:
			A base64 format string representing the MAC tag for the msg.

		Raises:
			TypeError: Error when either the msg or key is not a string.
		"""

		if type(msg) != str:
			raise TypeError("invalid msg: string expected")
		elif type(key) != str:
			raise TypeError("invalid key: string expected")
		dig = hmac.new(key, msg, hashlib.sha256).digest()
		tag = base64.b64encode(dig)
		return tag

	@staticmethod
	def verifyMac(msg, key, tag):
		"""Canonically verifies the given MAC tag for the given msg using the 
		given key. 

		Args:
			msg: A string message for which the MAC tag is to be verified.
			key: A string key to be used for verifying the MAC tag.
			tag: A string tag to be verified.

		Returns:
			A boolean corresponding to the verification. True if tag is a valid 
			MAC tag for the msg using the key, and False otherwise.

		Raises:
			TypeError: Error when either the msg, key or tag is not a string.
		"""

		if type(msg) != str:
			raise TypeError("invalid msg: str expected")
		elif type(key) != str:
			raise TypeError("invalid msg: str expected")
		elif type(tag) != str:
			raise TypeError("invalid msg: str expected")
		return message.generateMac(msg, key) == tag

	@staticmethod
	def generateAuxInfo(s, prime):
		"""Generates auxilliary information for a msg integer s to satisfy the quation
		c = bs + y where b and y are randomly generated numbers. Each of c, b and y are
		values module prime. 

		Args:
			s: A integer message for which the auxilliary information is to be generated.
			prime: A integer value specifying the prime field for modulo operations.

		Returns:
			A list consisting of values [c, b, y] that satisfies the equation c = bs + y.

		Raises:
			TypeError: Error when either the s or prime is not a integer.
			ValueError: Error when prime is not greater than the given value of s.
		"""

		if type(s) not in [int, long]:
			raise TypeError("invalid msg: int or long expected")
		elif type(prime) not in [int, long]:
			raise TypeError("invalid prime: int or long expected")
		elif s >= prime:
			raise ValueError("invalid prime: value larger than s expected")

		b = random.randint(0, prime)
		y = random.randint(0, prime)
		c = (b * s + y) % prime
		return [c, b, y]

	@staticmethod
	def verifyAuxInfo(s, y, b, c, prime):
		"""Verifies the given values of s, y, b and c for the equation c = bs + y using 
		prime as the order of modulo operations. 

		Args:
			s: An integer value.
			y: An integer value.
			b: An integer value.
			c: An integer value.
			prime: An integer value to be used as the order of modulo operations.

		Returns:
			A boolean corresponding to the verification. True if the given values 
			satisfy the equation c = bs + y using prime modulo operation, and 
			False otherwise.

		Raises:
			TypeError: Error when either of the arguments is not an integer.
			ValueError: Error when prime is not greater than each of s, y, b and c.
		"""

		if type(c) not in [int, long]:
			raise TypeError("invalid c: int or long expected")
		elif type(s) not in [int, long]:
			raise TypeError("invalid s: int or long expected")
		elif type(b) not in [int, long]:
			raise TypeError("invalid b: int or long expected")
		elif type(y) not in [int, long]:
			raise TypeError("invalid y: int or long expected")
		elif type(prime) not in [int, long]:
			raise TypeError("invalid prime: int or long expected")
		elif prime <= max(s, y, b, c):
			raise ValueError("invalid prime: value larger than s, y, b, c expected")
		return c == (s * b + y) % prime
	

#############################################################
#					 Class: secretSharing 					#
#############################################################

class secretSharing:
	"""A class of static methods for secret sharing related operations."""

	@staticmethod
	def modularInverse(num, prime):
		"""Calculates the modular inverse using extended Euclidean GCD method for 
		the given num using the given prime as the order of modulo operations.

		Args:
			num: An integer value for which modular inverse is to be calculated.
			prime: An integer value to be used as the order of modulo operations.

		Returns:
			An integer value representing the modular inverse of the given num.

		Raises:
			TypeError: Error when either num or prime is not an integer.
		"""		

		if type(num) not in [int, long]:
			raise TypeError("invalid num: int or long expected")
		elif type(prime) not in [int, long]:
			raise TypeError("invalid prime: int or long expected")
		
		num = num % prime
		if num < 0:
			r = extendedGCD(prime, -num)[2]
		else:
			r = extendedGCD(prime, num)[2]
		return (prime + r) % prime


	@staticmethod
	def evaluatePolynomial(msgNum, coefficients, n, prime):
		"""Generates shares of the integer msgNum by evaluating the polynomial 
		y = msgNum + c[0]*x + c[1]*x^2 + ... + c[n-2]*x^(n-1) using the list coefficients 
		as the list of c[i] values for n different values of x and returns a list of 
		n pairs [x, y]. The prime value is used as the order of modulo operations is 
		all the evaluations.

		Args:
			msgNum: An integer value specifying the message for which the shares are 
					to be generated.
			coefficients: A list if integer values to be used as coefficients in the 
					polynomial evaluation.
			n: An integer value representing the number of shares to be generated.
			prime: An integer value to be used as the order of modulo operations.

		Returns:
			A list of n shares of the form [x, y] generated by polynomial evaluations
			for different values of x.

		Raises:
			TypeError: Error when either num, n or prime is not an integer, or when 
			coefficients is not a list of integers.
		"""	

		if type(msgNum) not in [int, long]:
			raise TypeError("invalid msg: int or long expected")
		elif type(n) not in [int, long]:
			raise TypeError("invalid n: int or long expected")
		elif type(prime) not in [int, long]:
			raise TypeError("invalid prime: int or long expected")
		elif type(coefficients) != list:
			raise TypeError("invalid coefficients: list expected")
		else:
			for coeff in coefficients:
				if type(coeff) not in [int, long]:
					raise TypeError("invalid coefficients: list of int or long expected")
		
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
		"""Generates a random polynomial y = msgNum + c[0]*x + c[1]*x^2 + ... + c[k-2]*x^(k-1) 
		by ranadomly generating the list of coefficients c[i] using prime as the order of
		modulo operations.

		Args:
			k: An integer value representing the number of coefficients to be generated.
			prime: An integer value to be used as the order of modulo operations.

		Returns:
			A list of k-1 randomly generated coefficients for the polynomial 
			y = msgNum + c[0]*x + c[1]*x^2 + ... + c[k-2]*x^(k-1) 

		Raises:
			TypeError: Error when either k or prime is not an integer.
		"""

		if type(k) not in [int, long]:
			raise TypeError("invalid k: int or long expected")
		elif type(prime) not in [int, long]:
			raise TypeError("invalid prime: int or long expected")

		coefficients = []
		for i in range(1, k):
			coefficients.append(random.randint(0, prime))	
		return coefficients	

	@staticmethod
	def generateShares(msg, n, k, prime):
		"""Generates n shares for the msg such that any k shares can be used for 
		reconstructing the msg. The prime value is used as the order of modulo operations.

		Args:
			msg: A string message for which the shares are to be generated.
			n: An integer value representing the number of shares to be generated.
			k: An integer value representing the number of shares that are required for 
				reconstructing the msg.
			prime: An integer value to be used as the order of modulo operations.

		Returns:
			A list of n shares of the form [x, y] generated by the evaluatePolynomial method.

		Raises:
			TypeError: Error when either n, k or prime is not an integer, or when msg is 
				not a string.
			ValueError: Error when n and k do not satisfy n > k > 1.
		"""

		if type(n) not in [int, long]:
			raise TypeError("invalid n: int or long expected")
		elif type(k) not in [int, long]:
			raise TypeError("invalid k: int or long expected")
		elif n < 2 or k < 2:
			raise ValueError("invalid n or k: value greater than or equal to 2 expected")
		elif n < k:
			raise ValueError("invalid k: value less than or equal to n expected")
		elif type(prime) not in [int, long]:
			raise TypeError("invalid prime: int or long expected")

		if type(msg) == str:
			msgNum = message.strToNum(msg)
		else:
			raise TypeError("invalid msg: str expected")

		coefficients = secretSharing.randomPolynomial(k, prime)
		shares = secretSharing.evaluatePolynomial(msgNum, coefficients, n, prime)
		return shares

	@staticmethod
	def reconstructSecret(shares, k, prime):
		"""Reconstruct secret message using 

		Args:
			msg: A string message for which the shares are to be generated.
			n: An integer value representing the number of shares to be generated.
			k: An integer value representing the number of shares that are required for 
				reconstructing the msg.
			prime: An integer value to be used as the order of modulo operations.

		Returns:
			A list of n shares of the form [x, y] generated by the evaluatePolynomial method.

		Raises:
			TypeError: Error when either k or prime is not an integer, or when shares is not
				a list of [int, int] lists.
			ValueError: Error when k < 2 or when number of shares is less than k.
		"""

		if type(shares) != list:
			raise TypeError("invalid shares: list expected")
		elif type(k) not in [int, long]:
			raise TypeError("invalid k: int or long expected")
		elif k < 2:
			raise ValueError("invalid k: value greater than 1 expected")
		elif type(prime) not in [int, long]:
			raise TypeError("invalid prime: int or long expected")
		elif k > len(shares):
			raise ValueError("insufficient number of shares: expected k or more")

		if len(shares) > k:
			shares = shares[:k]

		try:
			xList, yList = zip(*shares)
		except TypeError:
			raise TypeError("invalid shares: list of lists expected")

		secret = 0

		try:
			for [xi, yi] in shares:
				numerator, denominator = 1, 1

				for xj in xList:
					if xi != xj:
						numerator = (numerator * -xj) % prime
						denominator = (denominator * (xi - xj)) % prime

				term = numerator * secretSharing.modularInverse(denominator, prime)
				secret = (secret + prime + (yi * term)) % prime
		except [ValueError, TypeError]:
			raise TypeError("invalid shares: list of [int, int] lists expected")

		return secret

##################### End of Code ###########################