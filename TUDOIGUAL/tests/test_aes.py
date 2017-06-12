#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
try:
    # tudoigual installed into system's python path?
    import tudoigual
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__) + '/../../')
    #sys.path.insert(0,'../../tudoigual')
    import tudoigual

import pytest
from tudoigual.ciphers.AES import AES_Cipher
import binascii

__author__ = "rcoliveira"
__copyright__ = "rcoliveira"
__license__ = "none"

"""
Test vectors from http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
"""
cbc_test_vectors = (
    # CBC-AES128.Encrypt
    # key                                 iv
    # plaintext                           ciphertext
    ('2b7e151628aed2a6abf7158809cf4f3c', '000102030405060708090a0b0c0d0e0f',
     '6bc1bee22e409f96e93d7e117393172a', '7649abac8119b246cee98e9b12e9197d'),
    ('2b7e151628aed2a6abf7158809cf4f3c', '7649abac8119b246cee98e9b12e9197d',
     'ae2d8a571e03ac9c9eb76fac45af8e51', '5086cb9b507219ee95db113a917678b2'),
    ('2b7e151628aed2a6abf7158809cf4f3c', '5086cb9b507219ee95db113a917678b2',
     '30c81c46a35ce411e5fbc1191a0a52ef', '73bed6b8e3c1743b7116e69e22229516'),
    ('2b7e151628aed2a6abf7158809cf4f3c', '73bed6b8e3c1743b7116e69e22229516',
     'f69f2445df4f9b17ad2b417be66c3710', '3ff1caa1681fac09120eca307586e1a7'),
    # CBC-AES192.Encrypt
    # key                                                 iv
    # plaintext                           ciphertext
    ('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', '000102030405060708090a0b0c0d0e0f',
     '6bc1bee22e409f96e93d7e117393172a', '4f021db243bc633d7178183a9fa071e8'),
    ('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', '4f021db243bc633d7178183a9fa071e8',
     'ae2d8a571e03ac9c9eb76fac45af8e51', 'b4d9ada9ad7dedf4e5e738763f69145a'),
    ('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', 'b4d9ada9ad7dedf4e5e738763f69145a',
     '30c81c46a35ce411e5fbc1191a0a52ef', '571b242012fb7ae07fa9baac3df102e0'),
    ('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', '571b242012fb7ae07fa9baac3df102e0',
     'f69f2445df4f9b17ad2b417be66c3710', '08b0e27988598881d920a9e64f5615cd'),
    # CBC-AES256.Encrypt
    # key
    # iv                                  plaintext
    # ciphertext
    ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', '000102030405060708090a0b0c0d0e0f',
     '6bc1bee22e409f96e93d7e117393172a', 'f58c4c04d6e5f1ba779eabfb5f7bfbd6'),
    ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'f58c4c04d6e5f1ba779eabfb5f7bfbd6',
     'ae2d8a571e03ac9c9eb76fac45af8e51', '9cfc4e967edb808d679f777bc6702c7d'),
    ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', '9cfc4e967edb808d679f777bc6702c7d',
     '30c81c46a35ce411e5fbc1191a0a52ef', '39f23369a9d9bacfa530e26304231461'),
    ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', '39f23369a9d9bacfa530e26304231461',
     'f69f2445df4f9b17ad2b417be66c3710', 'b2eb05e2c39be9fcda6c19078c6a9d1b'),
)

ctr_test_vectors = (
    # CTR-AES128.Encrypt
    # key                                counter
    # plaintext                          ciphertext
    ('2b7e151628aed2a6abf7158809cf4f3c', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
     '6bc1bee22e409f96e93d7e117393172a', '874d6191b620e3261bef6864990db6ce'),
    ('2b7e151628aed2a6abf7158809cf4f3c', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdff00',
     'ae2d8a571e03ac9c9eb76fac45af8e51', '9806f66b7970fdff8617187bb9fffdff'),
    ('2b7e151628aed2a6abf7158809cf4f3c', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdff01',
     '30c81c46a35ce411e5fbc1191a0a52ef', '5ae4df3edbd5d35e5b4f09020db03eab'),
    ('2b7e151628aed2a6abf7158809cf4f3c', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdff02',
     'f69f2445df4f9b17ad2b417be66c3710', '1e031dda2fbe03d1792170a0f3009cee'),
    # CTR-AES192.Encrypt
    # key                                                counter
    # plaintext                          ciphertext
    ('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
     '6bc1bee22e409f96e93d7e117393172a', '1abc932417521ca24f2b0459fe7e6e0b'),
    ('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdff00',
     'ae2d8a571e03ac9c9eb76fac45af8e51', '090339ec0aa6faefd5ccc2c6f4ce8e94'),
    ('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdff01',
     '30c81c46a35ce411e5fbc1191a0a52ef', '1e36b26bd1ebc670d1bd1d665620abf7'),
    ('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdff02',
     'f69f2445df4f9b17ad2b417be66c3710', '4f78a7f6d29809585a97daec58c6b050'),
    # CTR-AES256.Encrypt
    # key
    # counter                            plaintext
    # ciphertext
    ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
     '6bc1bee22e409f96e93d7e117393172a', '601ec313775789a5b7a7f504bbf3d228'),
    ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdff00',
     'ae2d8a571e03ac9c9eb76fac45af8e51', 'f443e3ca4d62b59aca84e990cacaf5c5'),
    ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdff01',
     '30c81c46a35ce411e5fbc1191a0a52ef', '2b0930daa23de94ce87017ba2d84988d'),
    ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdff02',
     'f69f2445df4f9b17ad2b417be66c3710', 'dfc9c58db67aada613c2dd08457941a6'),
)

cbc_test_vectors_padding = (
    # key                               iv
    # plaintext                          ciphertext
    ('ac5800ac3cb59c7c14f36019e43b44fe', 'f013ce1ec901b5b60a85a986b3b72eba',
     'f6cee5ff28fd',                    'e8a846fd9718507371604504d4ca1ac7'),
    ('24c4328aeffc0ca354a3215a3da23a38', 'c43c6269bb8c1dbba3bc22b7ba7e24b1',
     '76cdfdf52a9753',                  '009e935f3fe4d57b57fc3127a8873d8c'),
    ('4035227440a779dbd1ed75c6ae78cef5', '8faff161a5ec06e051066a571d1729d9',
     'b103c928531d8875',                'b3d8df2c3147b0752a7e6bbbcc9d5758'),
    ('507008732ea559915e5e45d9710e3ed2', '342b22c1cbf1c92b8e63a38de99ffb09',
     '590b10224087872724',              'c11a034ed324aeae9cd5857ae4cd776f'),
    ('a060441b1b7cc2af405be4f6f5c58e22', '429d3240207e77e9b9dade05426fe3cb',
     'ccecfa22708b6d06439c',            'b61ff0a956b420347daa25bb76964b51'),
    ('721888e260b8925fe51183b88d65fb17', '5308c58068cbc05a5461a43bf744b61e',
     '8ff539940bae985f2f88f3',          '3ee8bdb21b00e0103ccbf9afb9b5bd9a'),
    ('80ba985c93763f99ff4be6cdee6ab977', 'ca8e99719be2e842e81bf15c606bb916',
     '4c84974b5b2109d5bc90e1f0',        '3e087f92a998ad531e0ff8e996098382'),
    ('1fe107d14dd8b152580f3dea8591fc3b', '7b6070a896d41d227cc0cebbd92d797e',
     '13eb26baf2b688574cadac6dba',      'a4bfd6586344bcdef94f09d871ca8a16'),
    ('4d3dae5d9e19950f278b0dd4314e3768', '80190b58666f15dbaf892cf0bceb2a50',
     '5fcb46a197ddf80a40f94dc21531',    '2b166eae7a2edfea7a482e5f7377069e'),
    ('0784fa652e733cb699f250b0df2c4b41', '106519760fb3ef97e1ccea073b27122d',
     '6842455a2992c2e5193056a5524075',  '56a8e0c3ee3315f913693c0ca781e917'),
    ('04952c3fcf497a4d449c41e8730c5d9a', '53549bf7d5553b727458c1abaf0ba167',
     'c9a44f6f75e98ddbca7332167f5c45e3', '7fa290322ca7a1a04b61a1147ff20fe66fde58510a1d0289d11c0ddf6f4decfd'),
    ('2ae7081caebe54909820620a44a60a0f', 'fc5e783fbe7be12f58b1f025d82ada50', '1ba93ee6f83752df47909585b3f28e56693f89e169d3093eee85175ea3a46cd3',
     '7944957a99e473e2c07eb496a83ec4e55db2fb44ebdd42bb611e0def29b23a73ac37eb0f4f5d86f090f3ddce3980425a'),
    ('898be9cc5004ed0fa6e117c9a3099d31', '9dea7621945988f96491083849b068df', '0397f4f6820b1f9386f14403be5ac16e50213bd473b4874b9bcbf5f318ee686b1d',
     'e232cd6ef50047801ee681ec30f61d53cfd6b0bca02fd03c1b234baa10ea82ac9dab8b960926433a19ce6dea08677e34'),
)

# Cipher Block Chaining Tests


def test_vectors_cbc_encrypt():
    for _key, _iv, _plaintext, _ciphertext in cbc_test_vectors:
        cipher = AES_Cipher()
        iv, ciphertext = cipher.encrypt(
            _plaintext, key=_key, iv=_iv, pad='none')
        assert binascii.hexlify(ciphertext) == _ciphertext.encode()


def test_vectors_cbc_decrypt():
    for _key, _iv, _plaintext, _ciphertext in cbc_test_vectors:
        cipher = AES_Cipher()
        plaintext = cipher.decrypt(_ciphertext, key=_key, iv=_iv, pad='none')
        assert binascii.hexlify(plaintext) == _plaintext.encode()


def test_vectors_cbc_padding():
    for _key, _iv, _plaintext, _ciphertext in cbc_test_vectors_padding:
        cipher = AES_Cipher()
        iv, ciphertext = cipher.encrypt(
            _plaintext, key=_key, iv=_iv, pad='PKCS7')
        assert binascii.hexlify(ciphertext) == _ciphertext.encode()


def test_cbc_no_padd():
    cipher = AES_Cipher()
    iv, ciphertext = cipher.encrypt(
        'Secret Message A', key='abcdefghijklmnop', iv='000102030405060708089a0b0c0d0e0f', pad='none')
    plaintext = cipher.decrypt(
        ciphertext, key='abcdefghijklmnop', iv='000102030405060708089a0b0c0d0e0f', pad='none')
    assert plaintext == 'Secret Message A'.encode()

# Counter Mode Tests


def test_vectors_aes_ctr_encrypt():
    for _key, _counter, _plaintext, _ciphertext in ctr_test_vectors:
        cipher = AES_Cipher()
        iv, ciphertext = cipher.encrypt(
            _plaintext, key=_key, iv=_counter, mode=6, pad='none')
        assert binascii.hexlify(ciphertext) == _ciphertext.encode()


def test_vectors_aes_ctr_decrypt():
    for _key, _counter, _plaintext, _ciphertext in ctr_test_vectors:
        cipher = AES_Cipher()
        plaintext = cipher.decrypt(
            _ciphertext, key=_key, iv=_counter, mode=6, pad='none')
        assert binascii.hexlify(plaintext) == _plaintext.encode()


def test_aes_ctr_no_padd():
    cipher = AES_Cipher()
    iv, ciphertext = cipher.encrypt('Secret Message A', key='abcdefghijklmnop',
                                    iv='000102030405060708090a0b0c0d0e0f', mode=6, pad='nopad')
    plaintext = cipher.decrypt(ciphertext, key='abcdefghijklmnop',
                               iv='000102030405060708090a0b0c0d0e0f', mode=6, pad='nopad')
    assert plaintext == 'Secret Message A'.encode()
