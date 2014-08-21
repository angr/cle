#!/usr/bin/env python
try:
    from python_lib import standard_logging, angr_debug
except ImportError:
    pass

import angr
import logging

logging.basicConfig(level=logging.DEBUG)


def print_obj_addresses(p_cle):
    for i in p_cle.ld.shared_objects:
        print "base addr of %s is 0x%x" % (i.binary, i.rebase_addr)
        print "max addr of %s is 0x%x" % (i.binary, i.get_max_addr())

    max_ld = p_cle.ld.max_addr()
    print "Cle.Ld's max addr is 0x%x" % max_ld


def compare_mem(m1, m2):
    # Compares memory m1 to m2
    unknown = []  # What addresses are unknown to m2

    # What's in m1 that is not in m2 ?
    print "addr \tm1 \tm2"
    for k1, v1 in m1.iteritems():
        try:
            v2 = m2[k1]
            if (v1 != v2):
                print "%x:\t%s\t%s" % (k1, repr(v2),repr(v1))
        except KeyError:
            unknown.append(hex(k1))
    print "Missing addresses:"
    print unknown


def compare_entry(p1,p2):
    print "entry @ 0x%x" % p1.entry
    print "entry @ 0x%x" % p2.entry


def run(p1):
    print "Simrun info:\n---"
    run1 = p1.sim_run(p1.exit_to(p1.entry))
    print "simrun default exit: %s" % hex(run1.default_exit.concretize())
    print "simrun conditional exits %s" % repr(run1.conditional_exits)
    print "simrun #exits %s" % repr(len(run1.exits()))
    print "simrun addr 0x%x" % run1.addr
    print "simrun id %s" % repr(run1.id_str)
    print "irsb #instructions %d" % run1.irsb.instructions()
    print "irsb size %d" % run1.irsb.size()
    print "---"

def browse(p):
    run = p.sim_run(p.initial_exit())
    for exit in run.exits():
        print "exit concretized to: %x" % exit.concretize()

def cfg(p):
    cfg = p.construct_cfg()
    graph = cfg.get_graph()
    print "CFG nodes:\n---"
    print graph.nodes()
    print"---"
    return cfg

def setup_ida(filename):
    p_ida = None
    p_ida = angr.Project(filename, default_analysis_mode='symbolic',
                         use_sim_procedures=True, load_libs=True, arch="AMD64")
    return p_ida

def setup_cle(filename):
    p_cle = angr.Project(filename, default_analysis_mode='symbolic',
                         use_sim_procedures=True, load_libs = False, force_ida = True)
    return p_cle

def test(p):
    run(p)
    cfg(p)
    browse(p)

if __name__ == '__main__':
    #path="/home/christophe/binary_project/angr/angr/tests/fauxware/fauxware-x86"
     # path ="/home/christophe/binary_project/angr/angr/tests/fauxware/fauxware-mips"
    #path ="/home/christophe/binary_project/angr/angr/tests/fauxware/fauxware-ppc32"
    #path="/home/christophe/binary_project/angr/angr/tests/fauxware/fauxware-amd64"

    #path = "/home/christophe/binary_project/loader/cle/ccle/ppc/clextract"
    #path = "/home/christophe/binary_project/loader/cle/ccle/i386/clextract"
    #path = "/home/christophe/binary_project/loader/cle/ccle/x86_64/clextract"
    #path = "/home/christophe/binary_project/loader/cle/ccle/mips/clextract"
    #path = "/home/christophe/binary_project/loader/cle/ccle/arm/clextract"
    path = "/home/christophe/binary_project/angr/angr/tests/fauxware/fauxware-amd64"

    p = setup_cle(path)
    test(p)
    #cle = setup_cle(path)
    #test(cle)


