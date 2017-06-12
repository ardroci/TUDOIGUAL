#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
"""

from __future__ import division, print_function, absolute_import

__author__ = "rcoliveira"
__copyright__ = "rcoliveira"
__license__ = "none"

def bit_length(self):
  """This function returns the number of bits of self"""
  s = bin(self)       # binary representation:  bin(-37) --> '-0b100101'
  s = s.lstrip('-0b') # remove leading zeros and minus sign
  return len(s)       # len('100101') --> 6

# -- Modular Inverse --#
def modInverse(a, n):
  """This function calculates the inverse of a modulo n"""
  i = n
  v = 0
  d = 1
  while a > 0 :
    t = i//a # changed / to // for python3 compability
    x = a
    a = i % x
    i = x
    x = d
    d = v - t*x
    v = x

    v %= n
    if v < 0 :
      v = (v+n)%n
  return v
#----------------------#


# -- Modular Inverse --#
def egcd(value, mod):
  if value == 0:
    return mod, 0, 1
  else:
    g, x, y = egcd(mod % value, value)
    return g, y - (mod // value) * x, x


def mulinv(value, mod):
    g, x, _ = egcd(value, mod)
    if g == 1:
        return x % mod

# returns the inverse of a value mod 'mod'
# example: eea(7,40) returns the inverse of : 7 mod 40; which is 23.
def eea(value, mod):
  return mulinv(value, mod)
#----------------------#

# -- Modular Inverse --#
def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

def modinv(a, m):
  g, x, y = extended_gcd(a, m)
  if g != 1:
    raise ValueError
  return x % m

#----------------------#
