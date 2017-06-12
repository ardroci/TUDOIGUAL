# -*- coding: utf-8 -*-

"""
"""
# from .ec_elgamal import *
# from .ecdsa import *
# from .gen import *
# from .hkdf import *


try:
    # tudoigual installed into system's python path?
    import tudoigual
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__) + '/../../')
    #sys.path.insert(0,'../../tudoigual')
    import tudoigual

__all__ = ['ec_elgamal', 'ecdsa', 'gen', 'hkdf']

