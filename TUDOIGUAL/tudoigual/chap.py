#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
"""

from __future__ import division, print_function, absolute_import
import os
from Crypto.Hash import *
from rsa.rsa import RSA_PKC, public_key_from_certificate

class CHAP(object):
    def __init__(self, rsa_priv = None, rsa_pub = None, nr_bytes = 32):
        super(CHAP, self).__init__()
        self.nonce = os.urandom(nr_bytes)
        self.rsa_priv = rsa_priv
        self.rsa_pub = rsa_pub
        self.secret = os.urandom(nr_bytes)

    def challenge(self):
        enc = self.rsa_pub.encrypt(self.secret)

        return [self.nonce, enc]

    def verify(self, chap):
        return SHA256.new(self.nonce + self.secret).digest() == chap

    def response(self, nonce, secret):
        dec = self.rsa_priv.decrypt(secret)
        chap = SHA256.new(nonce + dec).digest()
        return chap
