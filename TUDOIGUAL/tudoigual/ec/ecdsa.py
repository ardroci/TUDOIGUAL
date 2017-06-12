#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
"""

from __future__ import division, print_function, absolute_import

import codecs
import hashlib
import hmac
import os
from binascii import hexlify, unhexlify

from tudoigual.ec.gen import ECPoint, modInverse, bit_length
from tudoigual.ec.hkdf import hkdf_extract, hkdf_expand, HKDF
from tudoigual.ciphers.AES import AES_Cipher
from tudoigual.utils.ec_curves import EC_curve_secp192r1, EC_curve_secp256r1
from tudoigual.utils.exceptions import MACError, InvalidSignatureParameter, InvalidSignature


__author__ = "rcoliveira"
__copyright__ = "rcoliveira"
__license__ = "none"

class Signature(object):
  """
  """
  def __init__(self, r, s):
    self.r = r
    self.s = s

def sign(self, data, sk , hash = hashlib.sha256, k = None):
  """
  """
  try:
    G = ECPoint(self.ec.G['x'], self.ec.G['y'], ec = self.ec)
    nr_bytes = self.ec.fieldSize//8
    # 1. Select a random or pseudorandom integer k, k ∈ [1, n - 1]
    if k is None:
      k = int.from_bytes(os.urandom(nr_bytes), byteorder = 'big', signed = False)
      if (1 < k > self.ec.n - 1):
        raise InvalidSignatureParameter
    # 2. Compute point P = (x, y) = kG and r = x mod n.
    P = G.multiplyPointByScalar(k)
    r = P.x % self.ec.n
    # If r = 0 then goto step 1
    if r == 0:
      print('r = 0')
      exit(1)
    # 4. Compute e = H(m), where H is a one way hash function, which produces a n-bit hash value
    hash().update(data)
    e = int(hash().hexdigest(), 16)
    # 5. Compute s = k^(-1) * (e + sk * r) mod n.
    s = modInverse(k, self.ec.n) * (e + (sk * r) % self.ec.n) % self.ec.n
    # If s = O then goto step 1
    if s == 0:
      print('s = 0')
      exit(1)
    # 6. The signature of message m is the pair (r, s).
  except TypeError as err:
    print('Excepting an integer value.')
    exit(1)
  except InvalidSignatureParameter as err:
    print('Invalid signature parameter k.')
    exit(1)
  return Signature(r,s)

def verify_signature(self, signature, pk, data,  hash = hashlib.sha256):
  """
  """
  r = signature.r
  s = signature.s
  # 1. Verify that r and s are integers in the range 1 through n - 1
  if (1 < r > self.ec.n - 1) or (1 < s > self.ec.n - 1):
    raise InvalidSignatureParameter #REJECT SIGNATURE
  G = ECPoint(self.ec.G['x'], self.ec.G['y'], ec = self.ec)
  # 2. Using a one way hash function, compute the n-bit hash value e = H(m)
  hash().update(data)
  e = int(hash().hexdigest(), 16)
  # 3. Compute w = s-1 mod n
  w = modInverse(s, self.ec.n)
  # 4. Compute u1 = e*w and u2 = r*w
  u_1, u_2 = e * w % self.ec.n, r * w % self.ec.n
  # 5. Compute the point X = (x1, y1) = u1 * G + u2 * pk
  X = G.multiplyPointByScalar(u_1).sum(pk.multiplyPointByScalar(u_2))
  # 6. If X = O, reject the signature else compute v = x1 mod n
  if (X.x == 0) and (X.y == 0):
    raise InvalidSignature #REJECT SIGNATURE
  # else compute v = x1 mod n
  v = X.x % self.ec.n
  # 7. Accept signature if and only if v = r
  r_digest, v_digest= hashlib.new('sha256'), hashlib.new('sha256')
  r_digest.update(str(r).encode())
  v_digest.update(str(v).encode())
  if hmac.compare_digest(v_digest.hexdigest(), r_digest.hexdigest()):
    return True  #ACCEPT SIGNATURE
  else:
        raise InvalidSignature #REJECT SIGNATURE