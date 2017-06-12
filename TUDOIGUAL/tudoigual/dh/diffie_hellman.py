#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
"""
from __future__ import division, print_function, absolute_import

from hashlib import sha256
from utils.decorators import requires_private_key
from utils.exceptions import MalformedPublicKey, RNGError
from utils.primes import PRIMES

__author__ = "rcoliveira"
__copyright__ = "rcoliveira"
__license__ = "none"

try:
    from ssl import RAND_bytes
    rng = RAND_bytes
except(AttributeError, ImportError):
    raise RNGError


class DiffieHellman:
    """
    Diffie-Hellman key exchange protocol.
    """

    def __init__(self, group=18, key_length=640):
        """
        """
        self.key_length = max(200, key_length)
        self.generator = PRIMES[group]["generator"]
        self.prime = PRIMES[group]["prime"]
        # self.__dict__={}

    def generate_private_key(self):
        key_length = self.key_length // 8 + 8
        key = 0
        try:
            key = int.from_bytes(rng(key_length), byteorder='big')
        except:
            key = int(hex(rng(key_length)), base=16)

        self.__private_key = key

    def verify_public_key(self, other_public_key):
        return self.prime - 1 > other_public_key > 2 and pow(other_public_key, (self.prime - 1) // 2, self.prime) == 1

    def get_public_key(self):
        return self.public_key

    def get_shared_key(self):
        return self.shared_key

    @requires_private_key
    def generate_public_key(self):
        self.public_key = pow(self.generator, self.__private_key, self.prime)

    @requires_private_key
    def generate_shared_secret(self, other_public_key, echo_return_key=False):
        if self.verify_public_key(other_public_key) is False:
            raise MalformedPublicKey

        self.shared_secret = pow(other_public_key, self.__private_key, self.prime)

        shared_secret_as_bytes = self.shared_secret.to_bytes(self.shared_secret.bit_length() // 8 + 1, byteorder='big')

        _h = sha256()
        _h.update(bytes(shared_secret_as_bytes))

        self.shared_key = _h.hexdigest()

        if echo_return_key is True: 
            return self.shared_key
