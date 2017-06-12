#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
"""

from __future__ import division, print_function, absolute_import

import sys
import getopt
import codecs
import hashlib
import os
from binascii import hexlify, unhexlify

from tudoigual.ec.hkdf import hkdf_extract, hkdf_expand
from tudoigual.ciphers.AES import AES_Cipher
from tudoigual.utils.ec_curves import EC_curve_secp192r1, EC_curve_secp256r1
from tudoigual.utils.number_theory import modInverse, bit_length

__author__ = "rcoliveira"
__copyright__ = "rcoliveira"
__license__ = "none"

class ECPoint:
  """A class defining a point for the EC"""
  x = 0
  y = 0
  ec = EC_curve_secp256r1

  def __init__(self, x, y, ec = EC_curve_secp256r1):
    self.x = x
    self.y = y
    self.ec = ec

  def doublePoint(self):
    s = ((3 * (self.x * self.x)) + self.ec.a ) * (modInverse(2 * self.y, self.ec.p)) % self.ec.p
    x3 = (s * s - self.x - self.x) % self.ec.p
    y3 = (s * (self.x - x3) - self.y) % self.ec.p
    return ECPoint(x3,y3, self.ec)
      # no entanto o ponto pode não pertencer à curva

  def sum(self,p2):
    # se o A = B
    if self.x == p2.x:
      if self.y == p2.y:
        return self.doublePoint()
      return ECPoint(null, null)

    s  = 0
    x3 = 0
    y3 = 0

    s  = ((p2.y - self.y) * (modInverse(p2.x - self.x + self.ec.p, self.ec.p))) % self.ec.p
    x3 = (s * s - self.x - p2.x) % self.ec.p
    y3 = (s * (self.x - x3) - self.y) % self.ec.p
    return ECPoint(x3,y3,self.ec)

  def multiplyPointByScalar(self, n):
    nbits = n.bit_length()
    result = ECPoint(self.x,self.y,self.ec)

    for i in range(1, nbits):
      result = result.doublePoint() # T = T + T mod P
      bit = (n >> (nbits-i-1)) & 1
      if bit == 1:
        result = result.sum(self)

    return result;
