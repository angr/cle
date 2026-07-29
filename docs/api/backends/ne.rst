Windows NE
==========

.. autoclass:: cle.backends.NE
   :members: segment_to_rva, rva_to_segment, segment_to_selector

NE segment numbers are encoded in deterministic 64 KiB analysis slots. The
high part of an address is therefore a module-qualified analysis token, not a
Windows runtime selector. Native addresses can be converted explicitly with
:meth:`~cle.backends.NE.segment_to_rva` and
:meth:`~cle.backends.NE.rva_to_segment`.

Internal and imported fixups use those analysis selectors. Imports resolve to
exports from a matching loaded NE module, or to module-qualified extern symbols
when the runtime module is unavailable. Iterated segments are expanded before
their fixup chains are interpreted. Windows floating-point-emulator OS fixups
remain recorded as metadata because they do not relocate an address.

.. automodule:: cle.backends.ne
   :members: NEEntryPoint, NEFixupRecord, NEHeader, NEImportedModule, NEImportedProcedure, NEInternalRelocation, NEName, NERelocation, NESegment, NESymbol
