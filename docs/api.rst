:mod:`cle` --- Binary Loader
============================

.. automodule:: cle
   :members:


Loading Interface
-----------------

.. automodule:: cle.loader
   :members:


Backends
--------

.. automodule:: cle.backends
   :members:
.. automodule:: cle.backends.backend
   :members:
.. automodule:: cle.backends.symbol
   :members:
.. automodule:: cle.backends.regions
   :members:
.. automodule:: cle.backends.region
   :members:
.. automodule:: cle.backends.elf
   :members:
.. automodule:: cle.backends.elf.elf
   :members:
.. automodule:: cle.backends.elf.elfcore
   :members:
.. automodule:: cle.backends.elf.lsda
   :members:
.. automodule:: cle.backends.elf.metaelf
   :members:
.. automodule:: cle.backends.elf.symbol
   :members:
.. automodule:: cle.backends.elf.symbol_type
   :members:
.. automodule:: cle.backends.elf.regions
   :members:
.. automodule:: cle.backends.elf.hashtable
   :members:
.. automodule:: cle.backends.elf.variable
   :members:
.. automodule:: cle.backends.elf.subprogram
   :members:
.. automodule:: cle.backends.elf.variable_type
   :members:
.. automodule:: cle.backends.elf.compilation_unit
   :members:
.. automodule:: cle.backends.named_region
   :members:
.. automodule:: cle.backends.pe
   :members:
.. automodule:: cle.backends.pe.pe
   :members:
.. automodule:: cle.backends.pe.symbol
   :members:
.. automodule:: cle.backends.pe.regions
   :members:
.. automodule:: cle.backends.macho
   :members:
.. automodule:: cle.backends.macho.macho
   :members:
.. automodule:: cle.backends.macho.symbol
   :members:
.. automodule:: cle.backends.macho.section
   :members:
.. automodule:: cle.backends.macho.segment
   :members:
.. automodule:: cle.backends.macho.binding
   :members:
.. automodule:: cle.backends.macho.macho_load_commands
   :members:
.. automodule:: cle.backends.macho.structs
   :members:
.. automodule:: cle.backends.minidump
   :members:
.. automodule:: cle.backends.cgc
   :members:
.. automodule:: cle.backends.cgc.cgc
   :members:
.. automodule:: cle.backends.cgc.backedcgc
   :members:
.. automodule:: cle.backends.blob
   :members:
.. automodule:: cle.backends.ihex
   :members:
.. automodule:: cle.backends.binja
   :members:
.. automodule:: cle.backends.externs
   :members:
.. automodule:: cle.backends.externs.simdata
   :members:
.. automodule:: cle.backends.externs.simdata.simdata
   :members:
.. automodule:: cle.backends.externs.simdata.common
   :members:
.. automodule:: cle.backends.java.android_lifecycle
   :members:
.. automodule:: cle.backends.java.apk
   :members:
.. automodule:: cle.backends.java.jar
   :members:
.. automodule:: cle.backends.java
   :members:
.. automodule:: cle.backends.java.soot
   :members:
.. automodule:: cle.backends.xbe
   :members:
.. automodule:: cle.backends.static_archive
   :members:
.. automodule:: cle.backends.uefi_firmware
   :members:
.. automodule:: cle.backends.te
   :members:


Relocations
-----------

CLE's loader implements program relocation data on a plugin basis.
If you would like to add more relocation implementations, do so by subclassing the ``Relocation`` class and overriding any relevant methods or properties.
Put your subclasses in a module in the ``relocations`` subpackage of the appropraite backend package.
The name of the subclass will be used to determine when to use it!
Look at the existing versions for details.

.. automodule:: cle.backends.relocation
   :members:
.. automodule:: cle.backends.elf.relocation
   :members:
.. automodule:: cle.backends.elf.relocation.elfreloc
   :members:
.. automodule:: cle.backends.elf.relocation.mips64
   :members:
.. automodule:: cle.backends.elf.relocation.generic
   :members:
.. automodule:: cle.backends.elf.relocation.armel
   :members:
.. automodule:: cle.backends.elf.relocation.ppc
   :members:
.. automodule:: cle.backends.elf.relocation.armhf
   :members:
.. automodule:: cle.backends.elf.relocation.pcc64
   :members:
.. automodule:: cle.backends.elf.relocation.i386
   :members:
.. automodule:: cle.backends.elf.relocation.amd64
   :members:
.. automodule:: cle.backends.elf.relocation.mips
   :members:
.. automodule:: cle.backends.elf.relocation.arm
   :members:
.. automodule:: cle.backends.elf.relocation.arm_cortex_m
   :members:
.. automodule:: cle.backends.elf.relocation.arm64
   :members:
.. automodule:: cle.backends.elf.relocation.s390x
   :members:
.. automodule:: cle.backends.pe.relocation
   :members:
.. automodule:: cle.backends.pe.relocation.pereloc
   :members:
.. automodule:: cle.backends.pe.relocation.generic
   :members:
.. automodule:: cle.backends.pe.relocation.i386
   :members:
.. automodule:: cle.backends.pe.relocation.amd64
   :members:
.. automodule:: cle.backends.pe.relocation.mips
   :members:
.. automodule:: cle.backends.pe.relocation.arm
   :members:
.. automodule:: cle.backends.pe.relocation.riscv
   :members:


Thread-local storage
--------------------

.. automodule:: cle.backends.tls
   :members:
.. automodule:: cle.backends.tls.tls_object
   :members:
.. automodule:: cle.backends.tls.elf_tls
   :members:
.. automodule:: cle.backends.tls.pe_tls
   :members:
.. automodule:: cle.backends.tls.elfcore_tls
   :members:
.. automodule:: cle.backends.tls.minidump_tls
   :members:


Misc. Utilities
---------------

.. automodule:: cle.gdb
   :members:
.. automodule:: cle.memory
   :members:
.. automodule:: cle.patched_stream
   :members:
.. automodule:: cle.address_translator
   :members:
.. automodule:: cle.utils
   :members:


Errors
------

.. automodule:: cle.errors
   :members:
