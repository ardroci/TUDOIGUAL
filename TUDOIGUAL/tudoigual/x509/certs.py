#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
"""
from __future__ import division, print_function, absolute_import

from tudoigual.x509.ca import (do_output, new_ec_key, load_password, key_to_pem, as_unicode,
                as_bytes, CertInfo, parse_dn, parse_list, load_key,create_x509_req,
                req_to_pem, load_cert,load_req, ec, EC_CURVES, same_pubkey,
                create_x509_cert, cert_to_pem, new_rsa_key, rsa, MIN_RSA_BITS, MAX_RSA_BITS)


__author__ = "rcoliveira"
__copyright__ = "rcoliveira"
__license__ = "none"


def output(data, cmd, text = '', out = ''):
    """
    Output X509 structure
    """
    if text:
        cmd = ['openssl', cmd, '-text']
        if args.out:
            cmd.extend(['-out', args.out])
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        p.communicate(data)
    elif out:
        with open(out, 'wb') as f:
            f.write(as_bytes(data))
    else:
        sys.stdout.write(as_unicode(data))
        sys.stdout.flush()

def new_Key(out, type = 'ec', password_file = ''):
    """
    Create new key.
    """
    k = None
    if type == 'ec':
        try:
            k = new_ec_key('secp256r1')
        except ValueError:
            print("Invalid curve: %s", v)
    elif type == 'rsa':
        try:
            k = new_rsa_key(2048)
        except ValueError:
            print("Invalid value for RSA bits: %s", v)
    else:
        print('Bad key type: %s', t)

    if k is None:
        print('Bad news')
    # Output with optional encryption
    psw = load_password(password_file)
    pem = key_to_pem(k, psw)
    output(data = pem, cmd = type, out = out)

def csr(key, subject, usage = '', alt_names = '', ocsp_nocheck = '', ocsp_urls = '',
    crl_urls = '', issuer_urls = '',permit_subtrees = '',exclude_subtrees = '',CA = '',path_length = 0, password_file = '', out = ''):
    """
    Load args, create CSR.
    """
    subject_info = CertInfo(
        subject=parse_dn(subject),
        usage=parse_list(usage),
        alt_names=parse_list(alt_names),
        ocsp_nocheck=ocsp_nocheck,
        ocsp_urls=parse_list(ocsp_urls),
        crl_urls=parse_list(crl_urls),
        issuer_urls=parse_list(issuer_urls),
        permit_subtrees=parse_list(permit_subtrees),
        exclude_subtrees=parse_list(exclude_subtrees),
        ca=CA,
        path_length=path_length)

    # Load private key, create req
    key = load_key(key, load_password(password_file))
    req = create_x509_req(key, subject_info)
    output(data = req_to_pem(req), cmd = 'req', out = out)

def sign_csr(csr, days = 730, ca_cert = None, ca_key = None, password_file = '', out = 'OverHere.pem'):
    """Load args, output cert.
    """
    if days is None:
        print("Need --days")
    if days <= 0:
        print("Invalid --days")

    # Load CA info
    if ca_cert is None:
        print("Need ca_cert")
    if ca_cert.endswith('.csr'):
        issuer_obj = load_req(ca_cert)
    else:
        issuer_obj = load_cert(ca_cert)
    issuer_info = CertInfo(load=issuer_obj)

    # Load certificate request
    if csr is None:
        print("Need csr")
    subject_csr = load_req(csr)
    subject_info = CertInfo(load=subject_csr)

    # Check CA params
    #if not same_pubkey(subject_csr, issuer_obj):
        #if not issuer_info.ca:
        #    print("Issuer must be CA.")
        #if 'key_cert_sign' not in issuer_info.usage:
        #    print("Issuer CA is not allowed to sign certs.")
    if subject_info.ca:
        if not same_pubkey(subject_csr, issuer_obj):
            # not selfsigning, check depth
            if issuer_info.path_length == 0:
                print("Issuer cannot sign sub-CAs")
            if issuer_info.path_length - 1 < args.path_length:
                print("--path-length not allowed by issuer")

    # Load subject's public key, check sanity
    pkey = subject_csr.public_key()
    if isinstance(pkey, ec.EllipticCurvePublicKey):
        pkeyinfo = 'ec:' + str(pkey.curve.name)
        if pkey.curve.name not in EC_CURVES:
            print("Curve not allowed: %s", pkey.curve.name)
    elif isinstance(pkey, rsa.RSAPublicKey):
        pkeyinfo = 'rsa:' + str(pkey.key_size)
        if pkey.key_size < MIN_RSA_BITS or pkey.key_size > MAX_RSA_BITS:
            print("RSA size not allowed: %s", pkey.key_size)
    else:
        print("Unsupported public key: %s", str(pkey))

    # Load CA private key
    key = load_key(ca_key, load_password(password_file))
    if not same_pubkey(key, issuer_obj):
        print("--ca-private-key does not match --ca-info data")

    # Stamp request
    cert = create_x509_cert(key, subject_csr.public_key(), subject_info, issuer_info, days = days)
    output(data = cert_to_pem(cert), cmd = 'x509', out = out)