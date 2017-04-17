#!/usr/bin/env python
''' 
HOTP as RFC-4226
https://tools.ietf.org/html/rfc4226
'''
import time
import hmac
import struct
import hashlib
import base64
import sys


def DT(String):
    ''' Dynamic Truncation
    '''
    offset = int(String[-1:], 16)
    print "offset", offset
    P = int(String[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
    print "truncate", str(P)
    return str(P)


def HOTP(K, C):
    ''' Generating an HOTP Value
    '''
    print "K", str(K).encode('hex')
    print "C", hex(C)
    C = struct.pack(b'>Q', C)
    hs = hmac.new(K, C, hashlib.sha1).hexdigest()
    print "hmac", hs
    Sbits = DT(hs)
    return Sbits[-6:]


def TOTP(K):
    ''' TOTP 30s window
    '''
    C = int(time.time()/30)
    return HOTP(K, C)


K = base64.b32decode(sys.argv[1])
print TOTP(K)
