#!/usr/bin/env python
"""
A small example filter module.
This module will change all outgoing data to uppercase.
"""

def init(argstr) :
    print "modFiltCase initialized with %r" % argstr

def filter(addr, dir, buf) :
    if dir == 'o' :
        buf = buf.upper()
    return buf

