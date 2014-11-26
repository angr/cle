#!/usr/bin/env python

import cle
import os

def find_binaries(path):
    binaries = []

    for p,d,f in os.walk(path):
        for e in f:
            binaries.append(os.path.join(p,e))

    return binaries


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        print("Missing parameter: path")

    binaries = find_binaries(path)

    rtypes = []
    for b in binaries:
        try:
            e = cle.Elf(b)
        except:
            print "%s failed, it's probably not a binary file" % b
            continue
        rel = e._raw_reloc
        for r in rel:
            rtypes.append(r[2])
        rtypes = list(set(rtypes))
        rtypes.sort()
    print "Found relocation types %s" % repr(rtypes)
