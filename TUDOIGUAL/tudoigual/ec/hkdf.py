# !/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
      HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

This document specifies a simple Hashed Message Authentication Code
(HMAC)-based key derivation function (HKDF), which can be used as a building
block in various protocols and applications.  The key derivation function (KDF)
is intended to support a wide range of applications and requirements, and is
conservative in its use of cryptographic hash functions.
"""

from __future__ import division, print_function, absolute_import

import hmac
import hashlib
import sys
import codecs
from binascii import unhexlify, hexlify

__author__ = "rcoliveira"
__copyright__ = "rcoliveira"
__license__ = "none"

if sys.version_info[0] == 3:
    buffer = lambda x: x

def decode_hex(s):
  return codecs.decode(s, "hex_codec")

def hkdf_extract(salt, input_key_material, hash = hashlib.sha256):
  """
  The goal of the "extract" stage is to "concentrate" the possibly dispersed
  entropy of the input keying material into a short, but cryptographically
  strong, pseudorandom key.

  HKDF-Extract(salt, IKM) -> PRK
  Options:
    Hash	a hash function; HashLen denotes the length of the hash function output in octets
  Inputs:
    salt	optional salt value (a non-secret random value); if not provided, it is set to a string of HashLen zeros.
    IKM		input keying material
  Output:
    PRK		a pseudorandom key (of HashLen octets)
  The output PRK is calculated as follows:
  PRK = HMAC-Hash(salt, IKM)
  """
  Hash_len = hash().digest_size
  if salt == None or len(salt) == 0:
    salt = bytearray((0,) * Hash_len)
  return hmac.new(salt, msg = input_key_material, digestmod = hash).digest()

def hkdf_expand(pseudo_random_key, info = b'', length = 32, hash = hashlib.sha256):
  """
  "expands" the pseudorandom key and info to the desired length in bytes; the number and
  lengths of the output keys depend on the specific cryptographic algorithms
  for which the keys are needed.

  HKDF-Expand(PRK, info, L) -> OKM
  Options:
    Hash	a hash function; HashLen denotes the length of the hash function output in octets
  Inputs:
  PRK		a pseudorandom key of at least HashLen octets (usually, the output from the extract step)
  info	optional context and application specific information
  L		length of output keying material in octets (<= 255*HashLen)

  Output:
    OKM		output keying material (of L octets)

  The output OKM is calculated as follows:
  N = ceil(L/HashLen)
  T = T(1) | T(2) | T(3) | ... | T(N)
  OKM = first L octets of T
  where:
  T(0) = empty string (zero length)
  T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
  T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
  T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
  ...
  (where the constant concatenated to the end of each T(n) is a single octet.)
  """
  Hash_len = hash().digest_size
  length = int(length)
  if length > 255 * Hash_len:
    raise Exception("Cannot expand to more than 255 * %d = %d bytes using the specified hash function" % (Hash_len, 255 * hash_len))
  blocks_needed = length // Hash_len + (0 if length % Hash_len == 0 else 1) # ceil
  OKM = b""
  output_block = b""
  for counter in range(blocks_needed):
    output_block = hmac.new(pseudo_random_key, output_block + info + bytearray((counter + 1,)), hash).digest()
    OKM += output_block
  return OKM[:length]

class HKDF():
  """
  HKDF follows the "extract-then-expand" paradigm, where the KDF logically
  consists of two modules.  The first stage takes the input keying material
  and "extracts" from it a fixed-length pseudorandom key K.  The second stage
  "expands" the key K into several additional pseudorandom keys (the output
  of the KDF).
  """

  def __init__(self, salt, input_key_material, hash = hashlib.sha256):
    self._hash = hash
    self._prk  = hkdf_extract(salt, input_key_material, self._hash)

  def expand(self, info = b'', length = 32):
    return hkdf_expand(self._prk, info, length, self._hash)