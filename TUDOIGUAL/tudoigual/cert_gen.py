# -*- coding: latin-1 -*-
#
# Copyright (C) AB Strakt
# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.

"""
Certificate generation module.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_pem_private_key
import OpenSSL
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID


from OpenSSL import crypto

if sys.version_info[0] > 2:
    unicode = str

TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA

# -*- Elliptic Curve -*- #
def generate_ecdsa_key(key_curve, out):
    key_curve = key_curve.lower()
    if ('secp256r1' == key_curve):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    elif ('secp384r1' == key_curve):
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    elif ('secp521r1' == key_curve):
        key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    else:
        print('Unsupported key curve: ', key_curve, '\n')
        return None
#        return OpenSSL.crypto.PKey.from_cryptography_key(key)  # currently not supported
    key_pem = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
    # sys.stdout.write(as_unicode(key_pem))
    # sys.stdout.flush()
    with open(out, 'wb') as f:
        f.write(as_bytes(key_pem))
    #return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_pem)

# def do_output(data, args, cmd):
#     """
#     Output X509 structure
#     """
#     if args.text:
#         cmd = ['openssl', cmd, '-text']
#         if args.out:
#             cmd.extend(['-out', args.out])
#         p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
#         p.communicate(data)
#     elif args.out:
#         with open(args.out, 'wb') as f:
#             f.write(as_bytes(data))
#     else:
#         sys.stdout.write(as_unicode(data))
#         sys.stdout.flush()

def as_unicode(s):
  """
  Return unicode-string.
  """
  if isinstance(s, unicode):
      return s
  return s.decode('utf8')

def as_bytes(s):
  """
  Return byte-string.
  """
  if isinstance(s, unicode):
      return s.encode('utf8')
  return s



def csr(pk):
  private_key = load_pem_private_key(pk, password=None, backend=default_backend())
  builder = x509.CertificateSigningRequestBuilder()
  builder = builder.subject_name(x509.Name([
      x509.NameAttribute(NameOID.COMMON_NAME, u'PELO_MENOS_ISTO'),
  ]))
  builder = builder.add_extension(
      x509.BasicConstraints(ca=False, path_length=None), critical=True,
  )

  ext = x509.KeyUsage(digital_signature=True,
    content_commitment=False,
    key_encipherment=True,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False
    )

  # ku_args['digital_signature'] = True
  # ku_args['key_encipherment'] = True
  # ext = make_key_usage(**ku_args)
  builder = builder.add_extension(ext, critical=True)

  request = builder.sign(
      private_key, hashes.SHA256(), default_backend()
  )
  if(isinstance(request, x509.CertificateSigningRequest)):
    return request


def req_to_pem(req):
    """Serialize certificate request in PEM format.
    """
    return req.public_bytes(Encoding.PEM)







def createKeyPair(type, bits):
    """
    Create a public/private key pair.

    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey

def loadPrivateKey(sk):
  """
  Load a public/private key pair.

  Arguments:
  Returns:
  """
  with open(sk, 'rb') as fh:
      private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, fh.read())
  return private_key

def loadCertificate(cert):
  """
  Load a public/private key pair.

  Arguments:
  Returns:
  """
  with open(cert, 'rb') as fh:
      private_key = crypto.load_certificate(crypto.FILETYPE_PEM, fh.read())
  return private_key

def createCertRequest(pkey, digest="sha256", **name):
    """
    Create a certificate request.

    Arguments: pkey   - The key to associate with the request
               digest - Digestion method to use for signing, default is sha256
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    for key, value in name.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req


def createCertificate(req, issuerCertKey, serial, validityPeriod,
                      digest="sha256"):
    """
    Generate a certificate given a certificate request.

    Arguments: req        - Certificate request to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is sha256
    Returns:   The signed certificate in an X509 object
    """
    issuerCert, issuerKey = issuerCertKey
    notBefore, notAfter = validityPeriod
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert

# https://github.com/pyca/pyopenssl/issues/256
def verify(ca_cert_pem, crl_pem, cert_pem):
    store = crypto.X509Store()
    store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem))
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    ctx = crypto.X509StoreContext(store, cert)
    ctx.verify_certificate()

    # Until `X509StoreContext` accepts CRLs
    crl = crypto.load_crl(crypto.FILETYPE_PEM, crl_pem)
    revoked = crl.get_revoked() or []
    for r in revoked:
        r_serial = r.get_serial()
        c_serial = "%X" % (cert.get_serial_number(),)
        if r_serial == c_serial:
            raise Exception("Certificate revoked")


