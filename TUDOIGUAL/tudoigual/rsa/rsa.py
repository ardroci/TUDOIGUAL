#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
"""
from __future__ import division, print_function, absolute_import

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import *
from binascii import a2b_base64
from Crypto.Util.asn1 import DerSequence
import hashlib

from tudoigual.utils.exceptions import InvalidSignature, InvalidHashFunction

__author__ = "rcoliveira"
__copyright__ = "rcoliveira"
__license__ = "none"

def public_key_from_certificate(cert = None):
  """
  Get public key from certificate.
  """
  # Convert from PEM to DER
  try:
    pem = open(cert).read()
  except FileNotFoundError as error:
    print('Could not find given certificate.')
    exit(1)
  lines = pem.replace(" ",'').split()
  der = a2b_base64(''.join(lines[1:-1]))

  # Extract subjectPublicKeyInfo field from X.509 certificate (see RFC3280)
  cert = DerSequence()
  cert.decode(der)
  tbsCertificate = DerSequence()
  tbsCertificate.decode(cert[0])
  subjectPublicKeyInfo = tbsCertificate[6]
  return subjectPublicKeyInfo

def __digest_message(message, hash):
  """
  """
  __hash = [SHA,SHA224,SHA256,SHA512]
  if hash in __hash:
    digest = hash.new()
  else:
    raise InvalidHashFunction
  digest.update(message)
  return digest

def import_Key(key_file):
  """
  Import an RSA key (public or private half), encoded in standard form.
  :param string:
    Path to the RSA key to be imported.
  :return:
    An RSA key object.
  """
  try:
      key = RSA.importKey(open(key_file).read())
  except (ValueError, IndexError, TypeError) as err:
      pass
  except (FileNotFoundError) as err:
      pass
  return key

class RSA_PKC(object):
  """
  """

  def __init__(self, gen = False, key_in = None, path = '.keys', pub_in = None, form = 'PEM'):
    if gen:
        self.gen_rsa_key(key_length = 2048, path = path, form = form)

    if pub_in:
        self.pk = RSA.importKey(pub_in)
    else:
        try:
            self.pk = import_Key(path + '/pk.pem')
        except:
            pass

    if key_in:
        self.sk = import_Key(key_in)
    else:
        try:
            self.sk = import_Key(path + '/sk-and-pk.pem')
        except:
            pass

  def gen_rsa_key(self, key_length = 2048, path = '.keys', form = 'PEM'):
    """
    Generate RSA key object with an exponent 65537 in PEM format
    :param int key_length:
      Key length, or size (in bits) of the RSA modulus. It must be a multiple of 256, and no smaller than 1024.
      Default is 2048 bits.
    :param string out:
      Output directory.
      Default .keys.
    :param string form:
      Specifies the output format.
      Default is PEM.
    :return:
      Private key and public key (sk,pk)
    """

    try:
      key = RSA.generate(key_length, randfunc = None, progress_func = None, e = 65537)
    except (ValueError) as err:
      print('Key length is too little or not a multiple of 256.')

    f_sk = open(path + '/sk-and-pk.pem','wb')
    f_pk = open(path + '/pk.pem', 'wb')

    private_key = key.exportKey(format='PEM', passphrase=None, pkcs=1)
    public_key  = key.publickey().exportKey(format='PEM', passphrase=None, pkcs=1)

    f_sk.write(private_key)
    f_pk.write(public_key)

    f_sk.close
    f_pk.close
    return private_key, public_key

  def encrypt(self, message, key = None):
    """
    :param byte string message:
      The message to encrypt, also known as plaintext. It can be of variable
      length, but not longer than the RSA modulus (in bytes) minus 2, minus twice the hash output size.
    :param byte string key:
      RSA key.
    :return:
      A string, the ciphertext in which the message is encrypted. It is as long as the RSA modulus (in bytes).
    """

    # Initialize RSA key
    rsa_key = self.pk

    if (key is None) and (rsa_key is None):
      print('RSA key needed for encryption.')
      exit(1)
    cipher = PKCS1_OAEP.new(rsa_key)
    try:
      byte_str = message
      # type(byte_str) # ensure it is byte representation
      ciphertext = cipher.encrypt(byte_str)
    except (ValueError) as err:
      print('RSA key length is not sufficiently long to deal with the given message.')
      exit(1)
    return ciphertext

  def decrypt(self, ciphertext):
    """
    :param byte string message:
      Ciphertext to be decrypted, an octet string of length k (k denotes the length in octets of the RSA modulus n).
    :return:
      Message, an octet string of length mLen, where mLen <= k - 2hLen - 2.
    """
    cipher = PKCS1_OAEP.new(self.sk)
    try:
      message = cipher.decrypt(ciphertext)
    except (ValueError, TypeError) as err:
      print('Ciphertext length is incorrect, or decryption does not succeed.')
      exit(1)
    except (TypeError) as err:
      print('RSA key has no private half.')
      exit(1)
    return message

  def sign(self, message, hash = SHA256):
    """
    Produce the PKCS#1 v1.5 signature of a message.
    :param byte string message:
      The message to be signed.
    :param string hash:
      Cryptographic hash function used to compress the message.
    :return:
      The signature encoded as an octet string of length k, where k is the length in octets of the RSA modulus n.
    """

    try:
      digest = hash.new()
      digest.update(message)#digest_message(message, hash)
      signer = PKCS1_v1_5.new(self.sk)
      signature = signer.sign(digest)
    except (ValueError) as err:
      print('RSA key length is not sufficiently long to deal with the given hash algorithm.')
      exit(1)
    except (TypeError) as err:
      print('RSA key has no private half.')
      exit(1)
    except (InvalidHashFunction) as err:
      print('Invalid Hash Function.')
      exit(1)

    return signature

  def verify(self, message, signature, hash = SHA256):
    """
    Verify that a certain PKCS#1 v1.5 signature is authentic.
    This function checks if the party holding the private half of the key really signed the message.
    :param byte string message:
      Message whose signature is to be verified.
    :param string signature:
      The signature that needs to be validated.
    :param string hash:
      Cryptographic hash function used to compress the message.
    :return:
        True if the signature is authentic.
        Raises InvalidSignature if the sgnature is not authentic.
    """

    try:
      digest = hash.new()
      digest.update(message)#digest_message(message, hash)
    except (InvalidHashFunction) as err:
      print('Invalid Hash Function.')
      exit(1)

    verifier = PKCS1_v1_5.new(self.pk)

    if verifier.verify(digest, signature):
        return True
    else:
        return False#raise InvalidSignature
