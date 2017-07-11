#!/usr/bin/env python
"""
Utility and functions to create a signed certificate for SSL.

Requires M2Crypto.
http://www.heikkitoivonen.net/m2crypto/
"""

try :
    import M2Crypto
except ImportError, e :
    print "M2Crypto is required.  See http://chandlerproject.org/Projects/MeTooCrypto"
    raise SystemExit(1)

import optparse, random, time
from M2Crypto import ASN1, EVP, RSA, X509

def makeRSA(n=512) :
    k = EVP.PKey()
    k.assign_rsa(RSA.gen_key(n, 65537, lambda: None))
    return k

def certTime(func, s) :
    t = ASN1.ASN1_UTCTIME()
    t.set_time(s)
    func(t)

def certTimes(c, frm, to) :
    certTime(c.set_not_before, frm)
    certTime(c.set_not_after, to)
    
def certName(**kw) :
    n = X509.X509_Name()
    for k,v in kw.items() :
        setattr(n, k, v)
    return n

def makeCert(cn, ca=None, cak=None, CA=False, subjAltNames=None, bits=2048) :
    """
    Make a certificate signed by signer (or self-signed).
    If CA is true, make a key for CA use, otherwise for SSL.
    """
    k = makeRSA(bits)
    cert = X509.X509()
    chain = [cert]
    if cak is None : # self-signed
        ca,cak = cert,k
    else :
        chain.append(ca)
    cert.set_version(2);
    cert.set_serial_number(random.randint(0,0xffffffff)) # arbitrary range
    now = int(time.time())
    certTimes(cert, now - 60*60*24*365*5, now + 60*60*24*365*5)
    cert.set_subject(certName(C='US', ST='CA', O='iSEC Partners', OU='port swiggers', CN=cn))
    cert.set_pubkey(k)
    if CA :
        cert.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE'))
        cert.add_ext(X509.new_extension('subjectKeyIdentifier', cert.get_fingerprint()))
    else :
        cert.add_ext(X509.new_extension('basicConstraints', 'CA:FALSE'))
        cert.add_ext(X509.new_extension("nsComment", "SSL Server")) # XXX?
        if subjAltNames != None:
            cert.add_ext(X509.new_extension("subjectAltName", subjAltNames))
    ## XXX for CA, keyid, dirname, serial?
    #cert.add_ext(X509.new_extension('authorityKeyIdentifier', ca.get_fingerprint()))
    cert.set_issuer(ca.get_subject())
    cert.sign(cak, "sha1")
    return chain, k

pwCb = lambda *args : None

def save(fn, dat) :
    f = file(fn, 'w')
    f.write(dat)
    f.close()

def saveCerts(cs, k, name) :
    """Save a cert chain and its private key to a PEM file,
       and the first cert to a CER file."""
    namePem = name + ".pem"
    nameCer = name + ".cer"
    pems = ''.join(c.as_pem() for c in cs)
    save(namePem, pems + k.as_pem(cipher=None))
    c = cs[0]
    c.save(nameCer, X509.FORMAT_DER)
    return namePem, nameCer

def loadCert(name) :
    """Load a cert and its private key and return them both."""
    p = name + ".pem"
    c = X509.load_cert(p)
    k = EVP.PKey()
    k.assign_rsa(RSA.load_key(p, callback=pwCb))
    return c, k

def loadOrDie(name) :
    try :
        return loadCert(name)
    except Exception,e :
        fail("error loading cert %r: %s", name, e)

def saveOrDie(cs, k, name) :
    try :
        return saveCerts(cs, k, name)
    except Exception, e :
        fail("error saving cert %r: %s", name, e)

def getopts() :
    p = optparse.OptionParser(usage="usage: %prog [opts] cname")
    p.add_option("-C", dest="caName", default="ca", help="Name of CA file")
    p.add_option("-o", dest="outName", default=None, help="Name of output file")
    p.add_option("-c", dest="makeCA", action="store_true", help="Create a CA cert")
    p.add_option("-s", dest="selfSign", action="store_true", help="Create a self-signed cert")
    p.add_option("-a", dest="subjAltNames", default=None, help="List of subject alternative names e.g. DNS:example.com, IP:1.2.3.4, email:foo@bar.com")
    opt,args = p.parse_args()
    if opt.makeCA and len(args) == 0 :
        args = ["My Super CA"]
    if len(args) != 1 :
        p.error("specify a cname")
    if opt.outName is None :
        opt.outName = "ca" if opt.makeCA else "cert"
    opt.cname = args[0]
    return opt

def fail(fmt, *args) :
    print fmt % args
    raise SystemExit(1)
    
def main() :
    opt = getopts()
    if opt.selfSign or opt.makeCA :
        cacert, cakey = None, None
    else :
        cacert, cakey = loadOrDie(opt.caName)

    chain,privk = makeCert(opt.cname, CA=opt.makeCA, ca=cacert, cak=cakey, subjAltNames=opt.subjAltNames, bits=2048)

    names = saveOrDie(chain, privk, opt.outName)
    print "generated", ', '.join(names)

if __name__ == '__main__' :
    main()

