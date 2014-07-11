Clé is part of Angr. It loads binaries and their associated libraries, resolves
imports and provides an abstraction of process memory to Angr.


# Dependencies

You will need binutils-multiarch-dev and gcc for mips, arm, ppc, x86 and
x86_64. On Debian, this is provided by emdebian.


# Manual install

To install Clé manually, you need to compile and install the code in the
subdirectories bfd, cle and ld_audit. The best way to do it is in a python
virtual
environment, e.g.:

    workon angr

And then:
    make 
    make install
in each directory.


# Auto install

Just git clone git@git.seclab.cs.ucsb.edu:angr/angr_setup.git and run the
install script.


