Relocations
-----------

CLE's loader implements program relocation data on a plugin basis.
If you would like to add more relocation implementations, do so by subclassing the ``Relocation`` class and overriding any relevant methods or properties.
Put your subclasses in a module in the ``relocations`` subpackage of the appropraite backend package.
The name of the subclass will be used to determine when to use it!
Look at the existing versions for details.

.. automodule:: cle.backends.relocation
.. automodule:: cle.backends.elf.relocation
.. automodule:: cle.backends.elf.relocation.elfreloc
.. automodule:: cle.backends.elf.relocation.mips64
.. automodule:: cle.backends.elf.relocation.generic
.. automodule:: cle.backends.elf.relocation.ppc
.. automodule:: cle.backends.elf.relocation.armhf
.. automodule:: cle.backends.elf.relocation.pcc64
.. automodule:: cle.backends.elf.relocation.i386
.. automodule:: cle.backends.elf.relocation.amd64
.. automodule:: cle.backends.elf.relocation.mips
.. automodule:: cle.backends.elf.relocation.arm
.. automodule:: cle.backends.elf.relocation.arm_cortex_m
.. automodule:: cle.backends.elf.relocation.arm64
.. automodule:: cle.backends.elf.relocation.s390x
.. automodule:: cle.backends.pe.relocation
.. automodule:: cle.backends.pe.relocation.pereloc
.. automodule:: cle.backends.pe.relocation.generic
.. automodule:: cle.backends.pe.relocation.i386
.. automodule:: cle.backends.pe.relocation.amd64
.. automodule:: cle.backends.pe.relocation.mips
.. automodule:: cle.backends.pe.relocation.arm
.. automodule:: cle.backends.pe.relocation.riscv
