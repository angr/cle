import angr
import avatar2 as avatar2
import claripy

from angr_targets import AvatarGDBConcreteTarget

MALWARE_PATH = '/home/degrigis/Projects/angr-dev/binaries/tests/i386/not_packed_elf32'

GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999


MALWARE_OEP = 0x804874F
MALWARE_DECISION_ADDRESS = 0x8048879

DROP_STAGE2_V1 = 0x8048901
DROP_STAGE2_V2 = 0x8048936

VENV_DETECTED = 0x8048948
FAKE_CC = 0x8048962


MALWARE_EXECUTION_END = 0x8048992

avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP ,GDB_SERVER_PORT)
p = angr.Project(MALWARE_PATH , concrete_target=avatar_gdb)


def execute_concretly(state,address,concretize):
 simgr = p.factory.simgr(state)
 simgr.use_technique(angr.exploration_techniques.Symbion(find=address, concretize = concretize))
 exploration = simgr.run()
 return exploration.stashes['found'][0]


entry_state = p.factory.entry_state()



import ipdb
ipdb.set_trace()


new_concrete_state = execute_concretly(entry_state,[MALWARE_DECISION_ADDRESS],[])

import ipdb
ipdb.set_trace()

arg0 = claripy.BVS('arg0',8*32)
symbolic_buffer_address = new_concrete_state.regs.ebp-0xa0
new_concrete_state.memory.store(symbolic_buffer_address,arg0)

# symbolic exploration
simgr = p.factory.simgr(new_concrete_state)
print "[2]Symbolically executing malware to find dropping of second stage [ address:  " + hex(DROP_STAGE2_V1) + " ]"
exploration = simgr.explore(find=[DROP_STAGE2_V1], avoid=[DROP_STAGE2_V2,VENV_DETECTED, FAKE_CC ])
new_symbolic_state = exploration.stashes['found'][0]


malware_configuration = hex(new_symbolic_state.se.eval(arg0,cast_to=int))
#print(malware_configuration)

print "[3]Executing malware concretely with solution found until the end " + hex(MALWARE_EXECUTION_END)
execute_concretly(new_symbolic_state,[MALWARE_EXECUTION_END, FAKE_CC],[(symbolic_buffer_address,arg0)])


print "[4]Malware execution ends, the configuration to reach your BB is: " + malware_configuration

#assert(malware_configuration == hex(0xa000000f9ffffff000000000000000000000000000000000000000000000000))

avatar_gdb.exit()