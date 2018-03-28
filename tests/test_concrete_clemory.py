import nose.tools
import cle
import os
from angr_targets import AvatarGDBConcreteTarget
from avatar2 import *
import subprocess

binary = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries','tests','x86_64','fauxware'))



def setup_func():
    print("Calling setupfunction")
    subprocess.Popen("gdbserver 127.0.0.1:1234 %s" % (binary), shell=True)


@nose.tools.with_setup(setup_func)
def test_concrete_clemory_read_bytes():
    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, "Go away!")
    cle_msg = clemory.read_bytes(0, 8)

    concrete_target = AvatarGDBConcreteTarget(archs.x86.X86_64, "127.0.0.1", 1234)
    concrete_clemory = cle.Clemory(None,root=True)
    concrete_clemory.set_concrete_target(concrete_target)
    cle_msg_concrete = concrete_clemory.read_bytes(0x40090C, 8)

    nose.tools.assert_true(cle_msg == cle_msg_concrete and type(cle_msg) == type(cle_msg_concrete) and type(cle_msg[0] == cle_msg_concrete[0]) )
    concrete_target.exit()

@nose.tools.with_setup(setup_func)
def test_concrete_clemory_get_byte():
    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, "Go away!")
    cle_byte = clemory.get_byte(0)

    concrete_target = AvatarGDBConcreteTarget(archs.x86.X86_64, "127.0.0.1", 1234)
    concrete_clemory = cle.Clemory(None, root=True)
    concrete_clemory.set_concrete_target(concrete_target)
    cle_byte_concrete = concrete_clemory.get_byte(0x40090C)

    nose.tools.assert_true(cle_byte == cle_byte_concrete and type(cle_byte_concrete) == type(cle_byte_concrete))
    concrete_target.exit()

@nose.tools.with_setup(setup_func)
def test_concrete_clemory_read():
    print("read ")
    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, "Go away!")
    cle_read = clemory.read(8)

    concrete_target = AvatarGDBConcreteTarget(archs.x86.X86_64, "127.0.0.1", 1234)
    concrete_clemory = cle.Clemory(None, root=True)
    concrete_clemory.set_concrete_target(concrete_target)

    concrete_clemory.seek(0x40090C)
    cle_read_concrete = concrete_clemory.read(8)
    nose.tools.assert_true(cle_read == cle_read_concrete and type(cle_read) == type(cle_read_concrete) and type(cle_read[0] == cle_read_concrete[0]))
    concrete_target.exit()




