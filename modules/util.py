#!/usr/bin/python

#############################################################
# CSE 539 (Applied Cryptography) Fall 2015 - Project        #
# Team: Saurabh Gupta, Omkar Kaptan                         #
# Instructor: Dr. Rida Bazzi                                #
#############################################################

"""Provides a utility module for useful methods.

Global Methods
~~~~~~~~~~~~~~
    generatekey(length)
    genRandNum(maximum)
    generatePrimes()
    getLargePrime(num)
    secureFail()

Class message
~~~~~~~~~~~~~~
    Static Methods: 
        strToNum(msgString)
        numToStr(msgNum)
        listToStr(msgList)
        strToList(msg)
        strToBase64(msg)
        base64ToStr(b64Msg)
        numToBase64(msgNum)
"""

#################### Import modules #########################
import binascii
import base64
import ast
import os
import math
from time import sleep
from random import random

#################### Module Metadata ########################
__author__ = "Saurabh Gupta, Omkar Kaptan"
__email__ = "saurabhgupta@asu.edu, okaptan@asu.edu"
__license__ = "GPL"
__version__ = "1.0"

#################### Method Definitions #####################

def secureFail():
    """Prints a secure message after waiting a random amount
    of time, upto 5 seconds, and terminates.
    """
    randWait = random() * 5
    sleep(randWait)
    print "An error has occurred. Please try again later."

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

    numBytes = int(math.ceil(float(length)/8))
    return message.strToBase64(os.urandom(numBytes))

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
    known large primes (https://primes.utm.edu/lists/2small/).

    Returns:
        A list of generated prime numbers.
    """

    mersennePrimes = [31, 61, 89, 107, 127, 521, 607, 1279]
    prime192Bit = 2**192 - 237
    prime256Bit = 2**256 - 189
    prime320Bit = 2**320 - 197
    prime384Bit = 2**384 - 317
    
    primes = [prime192Bit, prime256Bit, prime320Bit, prime384Bit]
    for exp in mersennePrimes:
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

##################### End of Code ###########################