DOS MZ
======

.. autoclass:: cle.backends.MZ
   :members: initial_stack, initial_cs_value, initial_ss_value

MZ load modules use a canonical 20-bit linear analysis space. Their linked
base is zero, so default loading preserves the relative segment words stored
in the image. A paragraph-aligned ``base_addr`` together with
``force_rebase=True`` models a concrete DOS load segment and applies every
header relocation to the corresponding word.

The single load-module segment includes the minimum allocation requested by
the header in its memory size. Only bytes declared by the executable are
backed; the Program Segment Prefix, uninitialized allocation, trailing
overlays, and other DOS runtime state are not synthesized.

.. automodule:: cle.backends.mz
   :members: MZHeader, MZRelocation
