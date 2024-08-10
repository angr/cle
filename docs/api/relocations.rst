Relocations
-----------

CLE's loader implements program relocations.
If you would like to add support for more relocations, you can do so by subclassing the ``Relocation`` class and overriding any relevant methods or properties.
Then, add or uncomment the appropriate line in the relocations_table dict at the bottom of the file.
Look at the existing versions for details.

.. automodule:: cle.backends.relocation
.. automodule:: cle.backends.elf.relocation
.. automodule:: cle.backends.elf.relocation.elfreloc
.. automodule:: cle.backends.elf.relocation.generic
.. automodule:: cle.backends.elf.relocation.ppc
.. automodule:: cle.backends.elf.relocation.ppc64
.. automodule:: cle.backends.elf.relocation.i386
.. automodule:: cle.backends.elf.relocation.amd64
.. automodule:: cle.backends.elf.relocation.mips
.. automodule:: cle.backends.elf.relocation.arm
.. automodule:: cle.backends.elf.relocation.arm64
.. automodule:: cle.backends.elf.relocation.s390x
.. automodule:: cle.backends.pe.relocation
.. automodule:: cle.backends.pe.relocation.pereloc
.. automodule:: cle.backends.pe.relocation.generic
.. automodule:: cle.backends.pe.relocation.mips
.. automodule:: cle.backends.pe.relocation.arm
.. automodule:: cle.backends.pe.relocation.riscv
