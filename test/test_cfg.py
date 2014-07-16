import angr_ida
import angr
from python_lib import standard_logging, angr_debug

import logging

logging.basicConfig(level=logging.DEBUG)
#filename = "/home/christophe/binary_project/angr/angr/tests/never/never"
#filename = "/home/christophe/binary_project/loader/cle/test/test_reloc"
#filename ="/home/christophe/binary_project/angr/angr/tests/fauxware/fauxware-amd64"


def print_obj_addresses(p_cle):
    for i in p_cle.ld.shared_objects:
        print "base addr of %s is %x" % (i.binary, i.rebase_addr)
        print "max addr of %s is %x" % (i.binary, i.get_max_addr())

    max_ld = p_cle.ld.max_addr()
    print "Cle.Ld's max addr is %x" % max_ld


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
    print "entry @ %x" % p1.entry
    print "entry @ %x" % p2.entry


def run(p1):
    print "Simrun info:\n---"
    run1 = p1.sim_run(p1.exit_to(p1.entry))
    print "simrun default exit: %s" % hex(run1.default_exit.concretize())
    print "simrun conditional exits %s" % repr(run1.conditional_exits)
    print "simrun #exits %s" % repr(len(run1.exits()))
    print "simrun addr %x" % run1.addr
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




if __name__ == '__main__':
    filename = "/tmp/fauxware-amd64"
    p_ida = angr_ida.Project(filename, default_analysis_mode='symbolic',
                    use_sim_procedures=True)
    p_cle = angr.Project(filename, default_analysis_mode='symbolic',
                    use_sim_procedures=True)


    #print "--> Cle's memory compared to IDA's"
    #compare_mem(p_ida.mem, p_cle.mem)
    run(p_ida)
    run(p_cle)
    c1 = cfg(p_ida)
    c2 = cfg(p_cle)
    browse(p_cle)
    browse(p_ida)

    print_obj_addresses(p_cle)
