#!/usr/bin/python

#############################################################
# CSE 539 (Applied Cryptography) Fall 2015 - Project        #
# Team: Saurabh Gupta, Omkar Kaptan                         #
# Instructor: Dr. Rida Bazzi                                #
#############################################################

"""Provides a socket wrapper module for communication involving
arbitrary length messages.

Class mysocket
~~~~~~~~~~~~~~
    Attributes: 
        sock
    Constructor: 
        __init__(self, sock=None)
    Methods:
        bind(self, (host, port))
        connect(self, (host, port))
        getportnumber(self)
        accept(self)
        close(self)
        listen(self, backlog)
        send(self, msg, separator)
        recv(self, buffer, separator)
    Static Methods: 
        gethostname()
"""

#################### Import modules #########################
import binascii
import hmac
import hashlib
import base64
import ast
import os
import math

#################### Module Metadata ########################
__author__ = "Saurabh Gupta, Omkar Kaptan"
__email__ = "saurabhgupta@asu.edu, okaptan@asu.edu"
__license__ = "GPL"
__version__ = "1.0"

#################### Method Definitions #####################

def generatekey(length=256):
    """Generates a cryptographically secure random base64 key of 
    given length.

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
        raise TypeError("invalid length: int or long expected")
    elif length < 256:
        length = 256

    return message.strToBase64(os.urandom(length/8))

def genRandNum(maximum=2):
    """Generates a cryptographically secure random number less than 
    given maximum value. The method enforces the maximum value to be
    at least 2. 

    Args:
        maximum: An integer defining the value corresponding to which 
            the generated number should be smaller. Default value = 2

    Returns:
        A randomly generated integer less than given maximum value.

    Raises:
        TypeError: Error when the provided maximum is not an int or long.
    """

    if type(maximum) not in [int, long]:
        raise TypeError("invalid maximum: int or long expected")
    elif maximum < 2:
        maximum = 2

    length = int(math.ceil(float(len(bin(maximum)[2:])) / 8))
    num = maximum

    while num >= maximum:
        num = message.strToNum(os.urandom(length))

    return num

def generatePrimes():
    """Generates set of prime numbers using Mersenne Primes and 
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


#############################################################
#                    Class: message                         #
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

        keyString = message.base64ToStr(key)    
        dig = hmac.new(keyString, msg, hashlib.sha256).digest()
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
        """Generates auxilliary information for a msg integer s to satisfy the 
        quation c = bs + y where b and y are randomly generated numbers. Each 
        of c, b and y are values module prime. 

        Args:
            s: A integer message for which the auxilliary information is to be 
                generated.
            prime: A integer value specifying the prime field for modulo operations.

        Returns:
            A list consisting of values [c, b, y] that satisfies the equation 
                c = bs + y.

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

        b = genRandNum(prime)
        y = genRandNum(prime)
        c = (b * s + y) % prime
        return [c, b, y]

    @staticmethod
    def verifyAuxInfo(s, y, b, c, prime):
        """Verifies the given values of s, y, b and c for the equation c = bs + y 
        using prime as the order of modulo operations. 

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


##################### End of Code ###########################