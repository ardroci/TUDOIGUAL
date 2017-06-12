#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import division, print_function, absolute_import

import argparse
import sys
import logging
import os
import hashlib
import subprocess
import datetime

from tudoigual import __version__

__author__ = "rcoliveira"
__copyright__ = "rcoliveira"
__license__ = "none"

_logger = logging.getLogger(__name__)


OPENSSL_CONFIG_TEMPLATE = """
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
C                      = PT
ST                     = Castelo Branco
L                      = Covilha
O                      = tudoigual
OU                     = .
CN                     = %(domain)s
emailAddress           = %(domain)s@tudoigual.com

[ v3_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]§
DNS.1 = %(domain)s
DNS.2 = *.%(domain)s
"""

_openssl = '/usr/bin/openssl'
_ca_cert = 'certs/0000_cert.pem'
_ca_key = 'certs/server.key'

# Extra X509 args. Consider using e.g. ('-passin', 'pass:blah') if your
# CA password is 'blah'. For more information, see:
#
# http://www.openssl.org/docs/apps/openssl.html#PASS_PHRASE_ARGUMENTS
X509_EXTRA_ARGS = ()

def openssl(*args):
    cmdline = [_openssl] + list(args)
    subprocess.check_call(cmdline)

def dfile(ext, domain):
    return os.path.join('domains','%s.%s'%(domain,ext))

def gen_request(domain, rootdir=os.path.abspath(os.path.dirname(__file__)), keysize = 2048):
    os.chdir(rootdir)

    if not os.path.exists('domains'):
        os.mkdir('domains')

    if not os.path.exists(dfile('key', domain)):
        openssl('genrsa', '-out', dfile('key', domain), str(keysize))

    config = open(dfile('config', domain), 'w')
    config.write(OPENSSL_CONFIG_TEMPLATE % {'domain': domain})
    config.close()

    openssl('req','-new','-key',dfile('key', domain),'-out',
            dfile('request', domain),'-config',dfile('config', domain))
    print ("Done. The private request is at %s." % (dfile('request', domain)))

def gen_cert(domain, rootdir=(os.path.abspath(os.path.dirname(__file__))),
             days=360, ca_cert=_ca_cert, ca_key=_ca_key):
    openssl('x509', '-req', '-days', str(days), '-in', dfile('request', domain),
            '-CA', ca_cert, '-CAkey', ca_key,
            '-set_serial',
            '0x%s' % hashlib.sha256(domain.encode('utf-8') + str(datetime.datetime.now()).encode('utf-8')).hexdigest(),
            '-out', dfile('cert', domain),
            '-extensions', 'v3_req', '-extfile', dfile('config', domain),
            *X509_EXTRA_ARGS)

    print ("Done. The private key is at %s, the cert is at %s, and the " \
			"CA cert is at %s." % (dfile('key', domain), dfile('cert', domain), ca_cert) )
