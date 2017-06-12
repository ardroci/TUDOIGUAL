#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
exceptions is responsible for exception handling etc.
"""

class MalformedPublicKey(BaseException):
    """
    The public key is malformed as it does not meet the Legendre symbol criterion. The key might have been tampered with or might have been damaged in transit.
    """

    def __str__(self):
        return "Public key malformed: fails Legendre symbol verification."

class RNGError(BaseException):
    """
    Thrown when RNG could not be obtained.
    """

    def __str__(self):
        return "RNG could not be obtained. This module currently only works with Python 3."

class MACError(BaseException):
    """
    Thrown when fails to verify Message Authentication Code.
    """

    def __str__(self):
        return "Invalid Message Authentication Code."

class InvalidHashFunction(BaseException):
    """
    Thrown when select cryptographic hash functions is not correct.
    """

    def __str__(self):
        return 'Invalid Hash function.'

class InvalidSignatureParameter(BaseException):
    """
    Thrown when signature parameters are not in the correct interval.
    """

    def __str__(self):
        return 'Invalid signature parameter.'

class InvalidSignature(BaseException):
    """
    Thrown when fails to verify Signature.
    """

    def __str__(self):
        return 'Invalid signature.'
