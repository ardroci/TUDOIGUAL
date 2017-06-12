#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import hashlib
from binascii import hexlify, unhexlify, Error, Incomplete
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter


class AES_Cipher:
    """
    Implementation of the Advanced Encryption Standard cipher in mode Cipher Block Chaining and Counter Mode. Both with PKCS7 Padding or with no padding.
    """

    def __init__(self):
        self.__dict__ = {}

    def __pad(self, plaintext):
        """
        Plaintext padding with the PKCS7 padding scheme.

        :param str plaintext:
            Plaintext to apply padding
        :return:
            Padded plaintext.
        """
        return plaintext + ((AES.block_size - len(plaintext) % AES.block_size) * chr(AES.block_size - len(plaintext) % AES.block_size)).encode()

    def __unpad(self, ciphertext):
        """
        Remove PKCS7 padding.

        :param str ciphertext:
            Ciphertext where we want to remove the padding.
        :return:
            Ciphertext without padding.
        """
        return ciphertext[0:-ciphertext[-1]]

    def encrypt(self, plaintext, **kwargs):
        """
        Encrypt given plaintext.

        :param str pad:
            Padding scheme, default is PKCS7.
        :param int mode:
            Cipher mode of operation (2 - Cipher Block Chaining, 6 - Counter Mode)
            Cipher Block Chaining is the default mode.
        :param str iv:
            Initial vector. The default value is none so it would be created a 16 bytes random initial vector for the cipher.
        :return:
            A tuple containing the iv and the ciphertext.
        """
        _pad = kwargs.get('pad', 'PKCS7')
        _mode = kwargs.get('mode', 2)
        _iv = kwargs.get('iv', None)
        _key = kwargs.get('key', None)

        if _pad == 'PKCS7':
            try:
                plaintext = self.__pad(unhexlify(plaintext))
            except (TypeError, Error, Incomplete) as err:
                plaintext = self.__pad(plaintext)

        if _iv is None:
            _IV = Random.new().read(AES.block_size).upper()
        else:
            try:
                _IV = unhexlify(_iv)
            except (TypeError, Error, Incomplete) as err:
                _IV = _iv

        if _key is None:
            _KEY = hexlify(Random.new().read(AES.block_size)).upper()
        else:
            try:
                _KEY = unhexlify(_key)
            except (TypeError, Error, Incomplete) as err:
                _KEY = _key

        if _mode == 2:
            _cipher = AES.new(_KEY, _mode, _IV)
        if _mode == 6:
            _ctr = Counter.new(
                AES.block_size * 8, initial_value=int(_IV.hex(), AES.block_size), allow_wraparound=True)
            _cipher = AES.new(_KEY, 6, counter=_ctr)

        try:
            _ciphertext = _cipher.encrypt(unhexlify(plaintext))
        except (TypeError, Error, Incomplete) as err:
            _ciphertext = _cipher.encrypt(plaintext)
        return _IV, _ciphertext

    def decrypt(self, ciphertext, **kwargs):
        """
        Decrypt given ciphertext.

        :param str pad:
            type of padding.
            default is PKCS7.
        :param int mode:
            cipher mode of operation (2 - cipher block chaining, 6 - counter mode)
            default is cipher block chainig.
        :return:
            Plaintext.
        """
        _pad = kwargs.get('pad', 'PKCS7')
        _mode = kwargs.get('mode', 2)
        _key = kwargs.get('key',  None)
        _iv = kwargs.get('iv',   None)

        try:
            _CIPHERTEXT = unhexlify(ciphertext)
        except (TypeError, Error, Incomplete) as err:
            _CIPHERTEXT = ciphertext

        try:
            _IV = unhexlify(_iv)
        except (TypeError, Error, Incomplete) as err:
            _IV = _iv

        if _key is None:
            return
        else:
            try:
                _KEY = unhexlify(_key)
            except (TypeError, Error, Incomplete) as err:
                _KEY = _key

        if _mode == 2:
            _cipher = AES.new(_KEY, _mode, _IV)
        if _mode == 6:
            _ctr = Counter.new(
                AES.block_size * 8, initial_value=int(_IV.hex(), AES.block_size), allow_wraparound=True)
            _cipher = AES.new(_KEY, 6, counter=_ctr)

        if _pad == 'PKCS7':
            return self.__unpad(_cipher.decrypt(_CIPHERTEXT))
        else:
            return _cipher.decrypt(_CIPHERTEXT)
