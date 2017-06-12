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

import sys
from tudoigual.ec.gen import ECPoint, modInverse, bit_length
from tudoigual.ec.hkdf import hkdf_extract, hkdf_expand, HKDF
from tudoigual.ciphers.AES import AES_Cipher
from tudoigual.utils.ec_curves import EC_curve_secp192r1, EC_curve_secp256r1
from tudoigual.utils.exceptions import MACError, InvalidSignatureParameter, InvalidSignature


from tudoigual.x509.ca import (do_output, new_ec_key, load_password, key_to_pem, as_unicode,
                as_bytes, CertInfo, parse_dn, parse_list, load_key,create_x509_req,
                req_to_pem, load_cert,load_req, ec, EC_CURVES, same_pubkey,
                create_x509_cert, cert_to_pem, new_rsa_key, rsa, MIN_RSA_BITS, MAX_RSA_BITS)

__author__ = "rcoliveira"
__copyright__ = "rcoliveira"
__license__ = "none"


class EC_ElGamal:
  """
  """

  def __init__(self, ec = EC_curve_secp256r1, key = None, cert = None, password_file = ''):
    self.ec = ec
    if key is None or cert is None:
      self.sk, self.pk , self.G  = self.gen_keys()
    else:
      self._sk, self._pk , self.G  = self.gen_keys()
      sk = load_key(key, load_password(password_file))
      self.sk =  sk.private_numbers()._private_value
      # The public key associated with the certificate.
      pkey =  load_cert(cert).public_key()
      # Allows serialization of the key to bytes. Encodes an elliptic curve point to a byte string as described in SEC 1 v2.0 section 2.3.3.
      # This method only supports uncompressed points.
      self.pk = pkey.public_numbers().encode_point()

  def gen_keys(self):
    """
    """
    G = ECPoint(self.ec.G['x'], self.ec.G['y'], ec = self.ec)
    # gerar numero aleatorio da
    nr_bytes = self.ec.fieldSize//8
    d = os.urandom(nr_bytes)
    dA = int.from_bytes(d, byteorder = 'big', signed = False)
    if 1 < dA > (self.ec.n - 1):
      print('Invalid private key')
      exit(1)
    # calcular X = da * G
    X = G.multiplyPointByScalar(dA)
    return dA, X, G

  def encrypt(self, message):
    """
    ECIES
    """
    # 1.Escolhe um número aleatório dB em {1,...,n − 1} e calcula Y = (x2,y2) = dB*G;
    #secret key
    nr_bytes = self.ec.fieldSize//8
    dB = int.from_bytes(os.urandom(nr_bytes), byteorder = 'big', signed = False)
    # Y=xP as public key.
    Y = (self.G).multiplyPointByScalar(dB)
    # 2.Calcula também K = (x3,y3) = dB*X – o segredo S entre os dois passa a ser x3;
    K = (self.pkB).multiplyPointByScalar(dB)
    # 3. Calcula k1 = H(X, x3) e cifra a mensagem com esta chave, i.e., c ← E(k1, m);
    # Ideally, the salt value is a random (or pseudorandom) string of the length HashLen.
    _hash = hashlib.sha256
    _hash_len = _hash().digest_size
    salt = os.urandom(_hash_len)
    k1 = HKDF(salt = salt, input_key_material = format(K.x, 'x').encode(), hash=hashlib.sha256).expand(info  = b'', length = 16)
    k2 = HKDF(salt = salt, input_key_material = format(K.y, 'x').encode(), hash=hashlib.sha256).expand(info  = b'', length = 16)

    cipher = AES_Cipher()
    iv, ciphertext = cipher.encrypt(message, key = k1 , pad='PKCS7')
    # 4. Devolve(Y, iv, c).
    # 5. Calcula o MAC(k2, c)
    tag = hmac.new(k2, iv + ciphertext, _hash).digest()
    # 6. Envia para o Bob (Y,iv,c,salt,tag)
    return Y, iv, ciphertext, salt, tag

  def set_pkB(self, x, y):
      self.pkB = ECPoint(x, y, ec = self.ec)

  def decrypt(self, Y, iv, ciphertext, salt, tag):
    """
    """
    # O algoritmo de decifra D(sk,(Y,c,t)) atua da seguinte forma:
    #1. Deriva o ponto comum K = (x3,y3) = Y * X – o segredo S entre os dois passa a ser x3;
    try:
      K = Y.multiplyPointByScalar(self.sk)
    except AttributeError as err:
      print('Excepting and integer.')
    #2. Usa a função KDF para derivar duas chaves k1 e k2, uma para decifrar, outra para verificar o MAC;
    k1 = HKDF(salt = salt, input_key_material = format(K.x, 'x').encode(), hash=hashlib.sha256).expand(info  = b'', length = 16)
    k2 = HKDF(salt = salt, input_key_material = format(K.y, 'x').encode(), hash=hashlib.sha256).expand(info  = b'', length = 16)

    #3. Verifica o MAC e debita falha se t' !=g MAC(k2, c);
    tag1 = hmac.new(k2, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag,tag1):
      raise MACError
    #4. Decifra m a partir de c e usando k1, i.e., m = D(k1,c).
    cipher = AES_Cipher()
    plaintext = cipher.decrypt(ciphertext, key = k1, iv = iv, pad = 'PKCS7')
    #5. Devolve m.
    return plaintext

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
    return r, s

  def verify_signature(self, r, s, pk, data,  hash = hashlib.sha256):
    """
    """
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
