# -*- coding: utf-8 -*-
import sys, os, pkg_resources
try:
    # tudoigual installed into system's python path?
    import tudoigual
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__) + '/../../')
    #sys.path.insert(0,'../../tudoigual')
    import tudoigual

try:
    __version__ = pkg_resources.get_distribution(__name__).version
except:
    __version__ = 'unknown'

