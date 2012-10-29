#!/usr/bin/env python
"""
Dumps the output from a proxy log.

Todo:
    - timed replay?
"""

import optparse, sys, time

def tfmt(t) :
    return time.strftime('%Y-%M-%d_%H:%M:%S', time.localtime(t))

reset = "\x1b[m"
red = "\x1b[31m"
green = "\x1b[32m"

def hex(off, dat) :
    def datAt(n) :
        if n >= 0 and n < len(dat) :
            return dat[n]
    def hexIt(ch) :
        if ch is None :
            return '  '
        return '%02x' % ord(ch)
    def ascIt(ch) :
        if ch is None :
            return ' '
        if ch >= ' ' and ch <= '~' :
            return ch
        return '.'

    quant = 16 # power of 2
    d = off & (quant - 1)
    off,n = off-d, 0-d
    ls = []
    while n < len(dat) :
        hex1 = ' '.join(hexIt(datAt(n+m)) for m in xrange(0, 8))
        hex2 = ' '.join(hexIt(datAt(n+m)) for m in xrange(8, 16))
        asc = ''.join(ascIt(datAt(n+m)) for m in xrange(0, 16))
        l = '%08x: %-23s : %-23s | %s' % (off, hex1, hex2, asc)
        sys.stdout.write(l)
        sys.stdout.write('\n')
        off,n = off+quant, n+quant

def parsedLines(fn) :
    for l in file(fn, 'r') :
        ts,addr,dir,dat = l.strip().split(' ')
        ts = float(ts)
        yield ts,addr,dir,dat

def cat(opt, fn, seen) :
    offs = dict()
    for ts,addr,dir,dat in parsedLines(fn) :
        if opt.addr is not None and addr != opt.addr :
            continue
        if opt.list :
            if addr not in seen :
                sys.stdout.write("%s %s\n" % (tfmt(ts), addr))
                seen.add(addr)
            continue
        dat = dat.decode('hex')
        if dir == 'o' and opt.output or dir == 'i' and opt.input :
            if opt.timestamp :
                sys.stdout.write("\n%s %s %s: " % (tfmt(ts), addr, dir))
                if opt.hex :
                    sys.stdout.write('\n')
            if opt.color :
                sys.stdout.write(green if dir == 'o' else red)
            if opt.hex : 
                k = addr,dir
                off = offs.get(k, 0)
                offs[k] = off + len(dat)
                hex(off, dat)
            else :
                sys.stdout.write(dat)
            if opt.color :
                sys.stdout.write(reset)
            sys.stdout.flush()

def getopts() :
    p = optparse.OptionParser(usage="usage: %prog [opts] files...")
    p.add_option("-i", dest="input", action="store_true", help="show data from client")
    p.add_option("-o", dest="output", action="store_true", help="show data to client")
    p.add_option("-t", dest="timestamp", action="store_true", help="show timestamp and other metadata")
    p.add_option("-x", dest="hex", action="store_true", help="show data in hex")
    p.add_option('-a', dest="addr", help="only show data from addr")
    p.add_option('-c', dest='color', action="store_true", help="use colors")
    p.add_option('-l', dest='list', action='store_true', help='list sessions')
    opt,args = p.parse_args()
    opt.files = args

    if not opt.input and not opt.output :
        opt.input = True
        opt.output = True
    return opt

def main() :
    opt = getopts()
    seen = set()
    for fn in opt.files :
        cat(opt, fn, seen)

if __name__ == '__main__' :
    main()

