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

[ alt_names ]
DNS.1 = %(domain)s
DNS.2 = *.%(domain)s
"""

_openssl = '/usr/bin/openssl'
_ca_cert = '0000_cert.pem'
_ca_key = 'server.key'

# Extra X509 args. Consider using e.g. ('-passin', 'pass:blah') if your
# CA password is 'blah'. For more information, see:
#
# http://www.openssl.org/docs/apps/openssl.html#PASS_PHRASE_ARGUMENTS
X509_EXTRA_ARGS = ()

def openssl(*args):
    cmdline = [__openssl] + list(args)
    subprocess.checkall(cmdline)

def __dfile(ext):
    return os.path.exists('domains','%s.%s'%(domain,ext))

def gen_request(keysize = 2048):
    os.chdir(rootdir)

    if not os.path.exists('domains'):
        os.mkdir('domains')

    if not os.path.exists(dfile('key')):
        openssl('genrsa', '-out', dfile('key'), str(keysize))

    config = open(dfile('config'), 'w')
    config.write(OPENSSL_CONFIG_TEMPLATE % {'domain': domain})
    config.close()

    openssl('req','-new','-key',dfile('key'),'-out', dfile('request'),'-config',dfile('config'))
    print ("Done. The private request is at %s." % (dfile('request')))

def gen_cert(domain, rootdir=(os.path.abspath(os.path.dirname(__file__))),
             days=360, ca_cert=_ca_cert, ca_key=_ca_key):
    openssl('x509', '-req', '-days', str(days), '-in', dfile('request'),
            '-CA', ca_cert, '-CAkey', ca_key,
            '-set_serial',
            '0x%s' % hashlib.sha256(domain.encode('utf-8') + str(datetime.datetime.now()).encode('utf-8')).hexdigest(),
            '-out', dfile('cert'),
            '-extensions', 'v3_req', '-extfile', dfile('config'),
            *X509_EXTRA_ARGS)

    print ("Done. The private key is at %s, the cert is at %s, and the " \
			"CA cert is at %s." % (dfile('key'), dfile('cert'), ca_cert) )
def parse_args(args):
    """Parse command line parameters

    Args:
      args ([str]): command line parameters as list of strings

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(
        description="Just a Fibonnaci demonstration")
    parser.add_argument(
        '--version',
        action='version',
        version='TUDOIGUAL {ver}'.format(ver=__version__))
    parser.add_argument(
        '-d',
        '--domain',
        dest='domain',
        help="domain name",
		default=None,
        action="store")
    parser.add_argument(
        '-v',
        '--verbose',
        dest="loglevel",
        help="set loglevel to INFO",
        action='store_const',
        const=logging.INFO)
    parser.add_argument(
        '-vv',
        '--very-verbose',
        dest="loglevel",
        help="set loglevel to DEBUG",
        action='store_const',
        const=logging.DEBUG)
    return parser.parse_args(args)


def setup_logging(loglevel):
    """Setup basic logging

    Args:
      loglevel (int): minimum loglevel for emitting messages
    """
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(level=loglevel, stream=sys.stdout,
                        format=logformat, datefmt="%Y-%m-%d %H:%M:%S")


def main(args):
    """Main entry point allowing external calls

    Args:
      args ([str]): command line parameter list
    """
    args = parse_args(args)
    setup_logging(args.loglevel)
    _logger.debug("Starting crazy calculations...")
    genrequest()
    gencert(args.domain)
    _logger.info("Script ends here")


def run():
    """Entry point for console_scripts
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
