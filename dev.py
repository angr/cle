#!/usr/bin/env python3

import os
import sys

# TODO we will want to look at lib name if they auto load and not add to corpus
# OR we will want to generate separate corpora
import cle

path = sys.argv[1]
if not os.path.exists(path):
    sys.exit("%s does not exist" % path)
quiet = False
if "--quiet" in sys.argv:
    quiet = True
ld = cle.Loader(path, load_debug_info=True, auto_load_libs=False)
if not quiet:
    print(ld.corpus.to_json())
