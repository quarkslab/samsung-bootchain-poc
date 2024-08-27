#!/usr/bin/env python

'''
@Author  :   Damien Cauquil
'''

import sys
import lief
import re
from struct import unpack,pack

def parse_versions_sect(content):
    """
    Parse 64-bit versions section
    """
    symbols_crc = {}
    nb_symbols = int(len(content)/64)
    for i in range(nb_symbols):
        crc = unpack('<Q', bytes(content[i*64:i*64+8]))[0]
        symbol = ''
        for j in range(64 - 8):
            if content[i*64+8+j]!=0:
                symbol += chr(content[i*64+8+j])
        symbols_crc[symbol] = (crc, i*64)
    return symbols_crc


def parse_modsymvers(modsymvers):
    """
    Read and parse modsymvers file
    """
    symbols_crc = {}
    content =open(modsymvers,'rb').read()
    lines = [l[:-1] for l in content.split(b'\n')]
    for line in lines:
        if re.match(b'^(0x[a-f0-9]+)\t([^\s]+)', line): 
            crc,symbol = line.split(b'\t')[:2]
            symbols_crc[symbol.decode('latin-1')] = int(crc.decode('latin-1'),16)
    return symbols_crc

# First, parse module.symvers
print('[i] Parse symbols version info from %s' % sys.argv[1])
symbols = parse_modsymvers(sys.argv[1])
for sym in symbols.keys():
    print(' :: %s (0x%08x)' % (sym, symbols[sym]))

# Then load .ko, read __versions section
ko = lief.parse(sys.argv[2])
versions = ko.get_section('__versions')
if versions is not None:
    print('[i] versions section found, parsing')
    # parse versions section
    modvers = parse_versions_sect(versions.content)
    for sym in modvers.keys():
        print(' :: %s (0x%08x)' % (sym, modvers[sym][0]))

# Ensure .ko symbols are defined in module.symvers
print('[i] Checking all required symbols are defined ...')
for sym in modvers.keys():
    if sym not in symbols:
        print('/!\\ Symbol "%s" not found :/' % sym)
    else:
        offset = modvers[sym][1]
        versions.content = memoryview(bytearray(versions.content[:offset]) + pack('<Q', symbols[sym]) + bytearray(versions.content[offset+8:]))
        print('- symbol "%s" successfully patched' % sym)

# Show relocations
ko.write(sys.argv[2]+'.fixed')

