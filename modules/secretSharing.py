#!/usr/bin/python

#############################################################
# CSE 539 (Applied Cryptography) Fall 2015 - Project        #
# Team: Saurabh Gupta, Omkar Kaptan                         #
# Instructor: Dr. Rida Bazzi                                #
#############################################################

"""Provides an (n, k) secret sharing module for generating n
shares from a secret message, and reconstructing the secret 
message from k shares. Additional methods include the generation
and verification of MAC tags and auxilliary information for 
information theoretic verification.

Class secretSharing
~~~~~~~~~~~~~~~~~~~
    Static Methods:
        extendedGCD(a, b)
        modularInverse(num, prime)
        generateShares(msg, n, k, prime)
        randomPolynomial(k, prime)
        evaluatePolynomial(msgNum, coefficients, n, prime)
        generateMac(msg, key)
        generateAuxInfo(s, prime)
        reconstructSecret(shares, k, prime) 
        verifyMac(msg, key, tag)
        verifyAuxInfo(s, y, b, c, prime)
"""

#################### Import modules #########################
import hmac
import hashlib
import base64
from util import genRandNum, message

#################### Module Metadata ########################
__author__ = "Saurabh Gupta, Omkar Kaptan"
__email__ = "saurabhgupta@asu.edu, okaptan@asu.edu"
__license__ = "GPL"
__version__ = "1.0"

########### Global Variables for Verification Modes #########
NO_VERIFICATION = 1
AUX_INFO_VERIFICATION = 2
MAC_VERIFICATION = 3

#############################################################
#                    Class: secretSharing                   #
#############################################################

class secretSharing:
    """A class of static methods for secret sharing related operations."""

    @staticmethod
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
            g, y, x = secretSharing.extendedGCD(b % a, a)
            return (g, x - (b // a) * y, y)

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
            r = secretSharing.extendedGCD(prime, -num)[2]
        else:
            r = secretSharing.extendedGCD(prime, num)[2]
        return (prime + r) % prime


    @staticmethod
    def evaluatePolynomial(msgNum, coefficients, n, prime):
        """Generates shares of the integer msgNum by evaluating the polynomial 
        y = msgNum + c[0]*x + c[1]*x^2 + ... + c[n-2]*x^(n-1) using the list 
        coefficients as the list of c[i] values for n different values of x and 
        returns a list of n pairs [x, y]. The prime value is used as the order 
        of modulo operations is all the evaluations.

        Args:
            msgNum: An integer value specifying the message for which the shares 
                are to be generated.
            coefficients: A list if integer values to be used as coefficients in 
                the polynomial evaluation.
            n: An integer value representing the number of shares to be generated.
            prime: An integer value to be used as the order of modulo operations.

        Returns:
            A list of n shares of the form [x, y] generated by polynomial 
            evaluations for different values of x.

        Raises:
            TypeError: Error when either num, n or prime is not an integer, or 
                when coefficients is not a list of integers.
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
        """Generates a random polynomial y = msgNum + c[0]*x + c[1]*x^2 + ... 
        + c[k-2]*x^(k-1) by generating the list of cryptographically secure 
        coefficients c[i] using prime as the order of modulo operations.

        Args:
            k: An integer value representing the number of coefficients to be 
                generated.
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
            coefficients.append(genRandNum(prime))  
        
        return coefficients 

    @staticmethod
    def generateShares(msg, n, k, prime):
        """Generates n shares for the msg such that any k shares can be used 
        for reconstructing the msg. The prime value is used as the order of 
        modulo operations.

        Args:
            msg: A string message for which the shares are to be generated.
            n: An integer value representing the number of shares to be generated.
            k: An integer value representing the number of shares that are 
                required for reconstructing the msg.
            prime: An integer value to be used as the order of modulo operations.

        Returns:
            A list of n shares of the form [x, y] generated by the 
            evaluatePolynomial method.

        Raises:
            TypeError: Error when either n, k or prime is not an integer, or 
                when msg is not a string.
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
            k: An integer value representing the number of shares that are 
                required for reconstructing the msg.
            prime: An integer value to be used as the order of modulo operations.

        Returns:
            A list of n shares of the form [x, y] generated by the 
            evaluatePolynomial method.

        Raises:
            TypeError: Error when either k or prime is not an integer, or when 
                shares is not a list of [int, int] lists.
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

        return hmac.compare_digest(secretSharing.generateMac(msg, key), tag)

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