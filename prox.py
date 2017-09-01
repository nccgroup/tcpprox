#!/usr/bin/env python
"""
TCP Proxy server.  Listens on a port for connections, initiates
a connection to the real server, and copies data between the
two connections.  Optionally logs the data.

TODO:
    - non-blocking connect ?
    - possibly do non-blocking ssl handshaking?
    - cleaner shutdown?
"""

from socket import *
import errno, optparse, os, platform, socket, ssl, struct, time
from select import *

class Error(Exception) :
    pass

def fail(fmt, *args) :
    print "error:", fmt % args
    raise SystemExit(1)

def tcpListen(six, addr, port, blk, sslProto, cert=None, key=None) :
    """Return a listening server socket."""
    s = socket.socket(AF_INET6 if six else AF_INET, SOCK_STREAM)
    if six and hasattr(socket, 'IPV6_V6ONLY') :
        s.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    if sslProto is not None :
        if not os.path.exists(cert) :
            fail("cert file %s doesnt exist", cert)
        if key and not os.path.exists(key) :
            fail("cert key %s doesnt exist", key)
        s = ssl.wrap_socket(s, ssl_version=sslProto, server_side=True, certfile=cert, keyfile=key)
    s.bind((addr,port))
    s.listen(5)
    s.setblocking(blk)
    return s

def tcpConnect(six, addr, port, blk, sslProto, clientCert=None) :
    """Returned a connected client socket (blocking on connect...)"""
    s = socket.socket(AF_INET6 if six else AF_INET, SOCK_STREAM)
    s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    if sslProto is not None :
        if clientCert is None:
            certfile = None
            keyfile = None
        else:
            certfile = clientCert + '.cert'
            keyfile = clientCert + '.key'
        s = ssl.wrap_socket(s, certfile=certfile, keyfile=keyfile, cert_reqs=ssl.CERT_NONE, ssl_version=sslProto)
    s.connect((addr,port))
    s.setblocking(blk)
    return s

def safeClose(x) :
    try :
        x.close()
    except Exception, e :
        pass

def getSslVers(opt, enable) :
    if enable :
        if opt.sslV3 :
            return ssl.PROTOCOL_SSLv3
        elif opt.TLS :
            return ssl.PROTOCOL_TLSv1
        else :
            return ssl.PROTOCOL_SSLv23

class Server(object) :
    def __init__(self, opt, q) :
        self.opt = opt
        sslCert = opt.cert + ".pem"
        ver = getSslVers(opt, opt.sslIn)
        self.sock = tcpListen(opt.ip6, opt.bindAddr, opt.locPort, 0, ver, sslCert, None)
        self.q = q
    def preWait(self, rr, r, w, e) :
        r.append(self.sock)
    def postWait(self, r, w, e) :
        if self.sock in r :
            try :
                cl,addr = self.sock.accept()
            except ssl.SSLError, e :
                print "ssl error during accept", e
                return
            cl.setblocking(0)
            self.q.append(Proxy(self.opt, cl, addr))
            if self.opt.oneshot :
                safeClose(self.sock)
                return 'elvis has left the building'

class Half(object) :
    """a single connection"""
    def __init__(self, opt, sock, addr, dir) :
        self.opt = opt
        self.sock = sock
        self.addr = addr
        self.dir = dir

        self.name = "peer" if self.dir else "client"
        self.queue = []
        self.dest = None
        self.err = None
        self.ready = False

        # XXX handle ssl

    def preWait(self, rr, r, w, e) :
        if self.ready :
            rr.append(self.sock)
        r.append(self.sock)
        if self.queue :
            w.append(self.sock)
    def postWait(self, r, w, e) :
        if not self.err and self.sock in w and self.queue :
            self.writeSome()
        if not self.err and self.sock in r :
            self.ready = True
            self.copy()
        return self.err

    def error(self, msg, e) :
        print "%s on %s: %r %s" % (msg, self.name, e, e)
        self.err = "error on " + self.name
        return self.err

    def writeSome(self) :
        try :
            n = self.sock.send(self.queue[0])
        except ssl.SSLError, e :
            # XXX can we get WantRead here?
            if e.args[0] == ssl.SSL_ERROR_WANT_WRITE :
                n = 0
            else :
                return self.error("send ssl error", e)
        except Exception, e :
            return self.error("send error", e)
        if n != len(self.queue[0]) :
            self.queue[0] = self.queue[0][n:]
        else :
            del self.queue[0]

    def copy(self) :
        try :
            buf = self.sock.recv(4096)
        except ssl.SSLError, e :
            # XXX can we get WantWrite here?
            if e.args[0] == ssl.SSL_ERROR_WANT_READ :
                self.ready = False
                return
            if e.args[0] == ssl.SSL_ERROR_EOF :
                return self.error("eof", e)
            return self.error("recv ssl error", e)
        except socket.error, e : 
            if e.errno == errno.EWOULDBLOCK :
                self.ready = False
                return
            return self.error("recv socket error", e)
        except Exception, e :
            return self.error("recv error", e)
        if len(buf) == 0 :
            return self.error("eof", 0)
        for mod in self.opt.filters :
            buf = mod.filter(self.addr, self.dir, buf)
        self.dest.queue.append(buf)
        if self.opt.log :
            now = time.time()
            a = '%s:%s' % self.addr
            self.opt.log.write("%f %s %s %s\n" % (now, a, self.dir, buf.encode('hex')))
            self.opt.log.flush()
    def close(self) :
        safeClose(self.sock)

class Proxy(object) :
    """A client connection and the peer connection he proxies to"""
    def __init__(self, opt, sock, addr) :
        print "New client %s" % (addr,)
        self.opt = opt

        if opt.originalDst :
            try :
                sockaddr_in = sock.getsockopt(socket.SOL_IP, 80, 16)  # SO_ORIGINAL_DST = 80
            except socket.error :
                raise Error("SO_ORIGINAL_DST not supported on this platform")
            _, port, a, b, c, d = struct.unpack('!HHBBBB', sockaddr_in[:8])
            print('Original destination was: %d.%d.%d.%d:%d' % (a, b, c, d, port))
            self.opt.addr = '%d.%d.%d.%d' % (a, b, c, d)
            self.opt.port = port

        self.cl = Half(opt, sock, addr, 'i')
        # note: blocking connect for simplicity for now...
        ver = getSslVers(opt, opt.sslOut)
        peer = tcpConnect(opt.ip6, opt.addr, opt.port, 0, ver, opt.clientCert)
        self.peer = Half(opt, peer, addr, 'o')

        self.cl.dest = self.peer
        self.peer.dest = self.cl
        self.err = None

    def preWait(self, rr, r, w, e) :
        self.cl.preWait(rr, r,w,e)
        self.peer.preWait(rr, r,w,e)
    def postWait(self, r, w, e) :
        if not self.err :
            self.err = self.cl.postWait(r,w,e)
        if not self.err :
            self.err = self.peer.postWait(r,w,e)
        if self.err :
            self.cl.close()
            self.peer.close()
        return self.err

def serverLoop(opt) :
    qs = []
    qs.append(Server(opt, qs))
    while qs :
        # note: rr holds "read already ready"
        # meaning it wasnt fully drained last time
        rr,r,w,e = [], [], [], []
        for q in qs :
            q.preWait(rr, r, w, e)
        timeo = 10.0 if not rr else 0.0
        r,w,e = select(r, w, e, timeo)
        r = set(r).union(rr)
        for q in qs :
            if q.postWait(r, w, e) :
                qs.remove(q)
    print 'done'

def autoCert(cn, caName, name) :
    """Create a certificate signed by caName for cn into name."""
    import ca # requires M2Crypto!
    cac, cak = ca.loadOrDie(caName)
    c,k = ca.makeCert(cn, ca=cac, cak=cak)
    ca.saveOrDie(c, k, name)

def getopts() :
    p = optparse.OptionParser(usage="usage: %prog [opts] addr port")
    p.add_option('-6', dest='ip6', action='store_true', help="Use IPv6")
    p.add_option("-b", dest="bindAddr", default="0.0.0.0", help="Address to bind to")
    p.add_option("-L", dest="locPort", type="int", help="Local port to listen on")
    p.add_option("-s", dest="ssl", action="store_true", help="Use SSL for incoming and outgoing connections")
    p.add_option("--ssl-in", dest="sslIn", action="store_true", help="Use SSL for incoming connections")
    p.add_option("--ssl-out", dest="sslOut", action="store_true", help="Use SSL for outgoing connections")
    p.add_option('-3', dest='sslV3', action='store_true', help='Use SSLv3 protocol')
    p.add_option('-T', dest='TLS', action='store_true', help='Use TLSv1 protocol')
    p.add_option("-C", dest="cert", default=None, help="Cert for SSL")
    p.add_option("-A", dest="autoCname", action="store", help="CName for Auto-generated SSL cert")
    p.add_option('-1', dest='oneshot', action='store_true', help="Handle a single connection")
    p.add_option("-l", dest="logFile", help="Filename to log to")
    p.add_option("-m", dest="modules", action="append", default=[], help="filtering modules")
    p.add_option("-O", dest="originalDst", action="store_true", help="Use SO_ORIGINAL_DST for destination")
    p.add_option("-c", dest="clientCert", default=None, help="Client certificate to present to server")
    opt,args = p.parse_args()
    if opt.ssl :
        opt.sslIn = True
        opt.sslOut = True
    if opt.sslV3 and opt.TLS :
        p.error("-3 and -T cannot be used together")
    if opt.bindAddr == '0.0.0.0' and opt.ip6 :
        opt.bindAddr = '::'
    if opt.originalDst and platform.system() != "Linux" :
        p.error("SO_ORIGINAL_DST is only supported in Linux systems")
    if len(args) != 2 and not opt.originalDst :
        p.error("specify address and port or use -O")
    if opt.cert is None :
        opt.cert = "ca" if opt.autoCname else "cert"
    if opt.ssl and opt.cert is None :
        if opt.autoCname is not None :
            p.error("specify CA cert")
        else :
            p.error("specify SSL cert")
    if not opt.originalDst :
        opt.addr = args[0]
        try :
            opt.port = int(args[1])
        except ValueError :
            p.error("invalid port: " + args[1])
    if opt.locPort == None :
        if opt.originalDst :
            p.error("-O requires -L")
        else :
            opt.locPort = opt.port
    return opt

def initModule(modstr) :
    modname, modargs = modstr.split(':', 1) if ':' in modstr else (modstr,"")
    try :
        mod = __import__(modname)
    except ImportError :
        fail("could not import %r" % modname)
    mod.init(modargs)
    return mod

def main() :
    opt = getopts()
    if opt.sslIn and opt.autoCname :
        autoCert(opt.autoCname, opt.cert, "autocert")
        opt.cert = "autocert"
    opt.log = file(opt.logFile, 'w') if opt.logFile else None
    opt.filters = map(initModule, opt.modules)
    serverLoop(opt)

if __name__ == '__main__' :
    main()

