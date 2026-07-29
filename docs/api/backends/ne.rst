Windows NE
==========

.. autoclass:: cle.backends.NE
   :members: segment_to_rva, rva_to_segment

NE segment numbers are encoded in deterministic 64 KiB analysis slots. The
high part of an address is therefore a segment-table index, not a Windows
runtime selector. Native addresses can be converted explicitly with
:meth:`~cle.backends.NE.segment_to_rva` and
:meth:`~cle.backends.NE.rva_to_segment`.

.. automodule:: cle.backends.ne
   :members: NEEntryPoint, NEFixupRecord, NEHeader, NEImportedModule, NEImportedProcedure, NEName, NERelocation, NESegment, NESymbol
