from __future__ import print_function
import os
import sys
import platform
import logging
from collections import OrderedDict

import archinfo

from .address_translator import AT
from .utils import ALIGN_UP, key_bisect_insort_left, key_bisect_floor_key

try:
    import claripy
except ImportError:
    claripy = None

__all__ = ('Loader',)

l = logging.getLogger("cle.loader")


class Loader:
    """
    The loader loads all the objects and exports an abstraction of the memory of the process. What you see here is an
    address space with loaded and rebased binaries.

    :param main_binary:         The path to the main binary you're loading, or a file-like object with the binary
                                in it.

    The following parameters are optional.

    :param auto_load_libs:      Whether to automatically load shared libraries that loaded objects depend on.
    :param concrete_target:     Whether to instantiate a concrete target for a concrete execution of the process.
                                if this is the case we will need to instantiate a SimConcreteEngine that wraps the
                                ConcreteTarget provided by the user.
    :param force_load_libs:     A list of libraries to load regardless of if they're required by a loaded object.
    :param skip_libs:           A list of libraries to never load, even if they're required by a loaded object.
    :param main_opts:           A dictionary of options to be used loading the main binary.
    :param lib_opts:            A dictionary mapping library names to the dictionaries of options to be used when
                                loading them.
    :param ld_path:      A list of paths in which we can search for shared libraries.
    :param use_system_libs:     Whether or not to search the system load path for requested libraries. Default True.
    :param ignore_import_version_numbers:
                                Whether libraries with different version numbers in the filename will be considered
                                equivalent, for example libc.so.6 and libc.so.0
    :param case_insensitive:    If this is set to True, filesystem loads will be done case-insensitively regardless of
                                the case-sensitivity of the underlying filesystem.
    :param rebase_granularity:  The alignment to use for rebasing shared objects
    :param except_missing_libs: Throw an exception when a shared library can't be found.
    :param aslr:                Load libraries in symbolic address space. Do not use this option.
    :param page_size:           The granularity with which data is mapped into memory. Set to 1 if you are working
                                in a non-paged environment.

    :ivar memory:               The loaded, rebased, and relocated memory of the program.
    :vartype memory:            cle.memory.Clemory
    :ivar main_object:          The object representing the main binary (i.e., the executable).
    :ivar shared_objects:       A dictionary mapping loaded library names to the objects representing them.
    :ivar all_objects:          A list containing representations of all the different objects loaded.
    :ivar requested_names:      A set containing the names of all the different shared libraries that were marked as a
                                dependency by somebody.
    :ivar initial_load_objects: A list of all the objects that were loaded as a result of the initial load request.

    When reference is made to a dictionary of options, it requires a dictionary with zero or more of the following keys:

    - backend :             "elf", "pe", "mach-o", "blob" : which loader backend to use
    - arch :                The archinfo.Arch object to use for the binary
    - base_addr :           The address to rebase the object at
    - entry_point :         The entry point to use for the object

    More keys are defined on a per-backend basis.
    """

    def __init__(self, main_binary, auto_load_libs=True, concrete_target = None,
                 force_load_libs=(), skip_libs=(),
                 main_opts=None, lib_opts=None, ld_path=(), use_system_libs=True,
                 ignore_import_version_numbers=True, case_insensitive=False, rebase_granularity=0x1000000,
                 except_missing_libs=False, aslr=False, perform_relocations=True,
                 page_size=0x1, extern_size=0x8000):
        if hasattr(main_binary, 'seek') and hasattr(main_binary, 'read'):
            self._main_binary_path = None
            self._main_binary_stream = main_binary
        else:
            self._main_binary_path = os.path.realpath(str(main_binary))
            self._main_binary_stream = None

        # auto_load_libs doesn't make any sense if we have a concrete target.
        if concrete_target:
            auto_load_libs = False

        self._auto_load_libs = auto_load_libs
        self._satisfied_deps = dict((x, False) for x in skip_libs)
        self._main_opts = {} if main_opts is None else main_opts
        self._lib_opts = {} if lib_opts is None else lib_opts
        self._custom_ld_path = [ld_path] if type(ld_path) is str else ld_path
        self._use_system_libs = use_system_libs
        self._ignore_import_version_numbers = ignore_import_version_numbers
        self._case_insensitive = case_insensitive
        self._rebase_granularity = rebase_granularity
        self._except_missing_libs = except_missing_libs
        self._extern_size = extern_size
        self._relocated_objects = set()
        self._perform_relocations = perform_relocations

        # case insensitivity setup
        if sys.platform == 'win32': # TODO: a real check for case insensitive filesystems
            if self._main_binary_path: self._main_binary_path = self._main_binary_path.lower()
            force_load_libs = [x.lower() if type(x) is str else x for x in force_load_libs]
            for x in list(self._satisfied_deps): self._satisfied_deps[x.lower()] = self._satisfied_deps[x]
            for x in list(self._lib_opts): self._lib_opts[x.lower()] = self._lib_opts[x]
            self._custom_ld_path = [x.lower() for x in self._custom_ld_path]

        self.aslr = aslr
        self.page_size = page_size
        self.memory = None # type: Clemory

        self.main_object = None # type: Backend
        self._tls_object = None # type: TLSObject
        self._kernel_object = None # type: KernelObject
        self._extern_object = None # type: ExternObject
        self.shared_objects = OrderedDict()
        self.all_objects = []  # this list should always be sorted by min_addr
        self.requested_names = set()

        self.initial_load_objects = self._internal_load(main_binary, *force_load_libs)

        # cache
        self._last_object = None

        if self._extern_object and self._extern_object._warned_data_import:
            l.warning('For more information about "Symbol was allocated without a known size", see https://docs.angr.io/extending-angr/environment#simdata')

    # Basic functions and properties

    def close(self):
        """
        Release any resources held by this loader.
        """
        for obj in self.all_objects:
            obj.close()

    def __repr__(self):
        if self._main_binary_stream is None:
            return '<Loaded %s, maps [%#x:%#x]>' % (os.path.basename(self._main_binary_path), self.min_addr, self.max_addr)
        else:
            return '<Loaded from stream, maps [%#x:%#x]>' % (self.min_addr, self.max_addr)

    @property
    def max_addr(self):
        """
        The maximum address loaded as part of any loaded object (i.e., the whole address space).
        """
        return self.all_objects[-1].max_addr

    @property
    def min_addr(self):
        """
        The minimum address loaded as part of any loaded object (i.e., the whole address space).
        """
        return self.all_objects[0].min_addr

    @property
    def initializers(self):
        """
        Return a list of all the initializers that should be run before execution reaches the entry point, in the order
        they should be run.
        """
        return sum((x.initializers for x in self.all_objects), [])

    @property
    def finalizers(self):
        """
        Return a list of all the finalizers that should be run before the program exits.
        I'm not sure what order they should be run in.
        """
        return sum((x.finalizers for x in self.all_objects), [])

    @property
    def linux_loader_object(self):
        """
        If the linux dynamic loader is present in memory, return it
        """
        for obj in self.all_objects:
            if obj.provides is None:
                continue
            if self._is_linux_loader_name(obj.provides) is True:
                return obj
        return None

    @property
    def extern_object(self):
        """
        Return the extern object used to provide addresses to unresolved symbols and angr internals.

        Accessing this property will load this object into memory if it was not previously present.
        """
        if self._extern_object is None:
            if self.main_object.arch.bits < 32 and self._extern_size == 0x8000:
                l.warning("Your extern object is probably too big for your memory space.  Making it 0x200")
                self._extern_size = 0x200
            self._extern_object = ExternObject(self, map_size=self._extern_size)
            self._map_object(self._extern_object)
        return self._extern_object

    @property
    def kernel_object(self):
        """
        Return the object used to provide addresses to syscalls.

        Accessing this property will load this object into memory if it was not previously present.
        """
        if self._kernel_object is None:
            self._kernel_object = KernelObject(self)
            self._map_object(self._kernel_object)
        return self._kernel_object

    @property
    def tls_object(self):
        """
        Return the object used to provide addresses for thread-local storage.

        Accessing this property will load this object into memory if it was not previously present.
        """
        if self._tls_object is None:
            if isinstance(self.main_object, MetaELF):
                self._tls_object = ELFTLSObject(self)
                self._map_object(self._tls_object)
            elif isinstance(self.main_object, PE):
                self._tls_object = PETLSObject(self)
                self._map_object(self._tls_object)
        return self._tls_object

    @property
    def all_elf_objects(self):
        """
        Return a list of every object that was loaded from an ELF file.
        """
        return [o for o in self.all_objects if isinstance(o, MetaELF)]

    @property
    def all_pe_objects(self):
        """
        Return a list of every object that was loaded from an ELF file.
        """
        return [o for o in self.all_objects if isinstance(o, PE)]

    @property
    def missing_dependencies(self):
        """
        Return a set of every name that was requested as a shared object dependency but could not be loaded
        """
        return self.requested_names - set(self._satisfied_deps)

    def describe_addr(self, addr):
        """
        Returns a textual description of what's in memory at the provided address
        """
        o = self.find_object_containing(addr)

        if o is None:
            return 'not part of a loaded object'

        options = []

        rva = AT.from_va(addr, o).to_rva()

        idx = o.symbols.bisect_key_right(rva) - 1
        while idx >= 0:
            sym = o.symbols[idx]
            if not sym.name or sym.is_import:
                idx -= 1
                continue
            options.append((sym.relative_addr, '%s+' % sym.name))
            break

        if isinstance(o, ELF):
            try:
                plt_addr, plt_name = max((a, n) for n, a in o._plt.items() if a <= rva)
            except ValueError:
                pass
            else:
                options.append((plt_addr, 'PLT.%s+' % plt_name))

        options.append((0, 'offset '))

        if o.provides:
            objname = o.provides
        elif o.binary:
            objname = os.path.basename(o.binary)
        elif self.main_object is o:
            objname = 'main binary'
        else:
            objname = 'object loaded from stream'

        best_offset, best_prefix = max(options, key=lambda v: v[0])
        return '%s%#x in %s (%#x)' % (best_prefix, rva - best_offset, objname, AT.from_va(addr, o).to_lva())

    # Search functions

    def find_object(self, spec, extra_objects=()):
        """
        If the given library specification has been loaded, return its object, otherwise return None.
        """
        if self._case_insensitive:
            spec = spec.lower()
        extra_idents = {}
        for obj in extra_objects:
            for ident in self._possible_idents(obj):
                extra_idents[ident] = obj

        for ident in self._possible_idents(spec):
            if ident in self._satisfied_deps:
                return self._satisfied_deps[ident]
            if ident in extra_idents:
                return extra_idents[ident]

        return None

    def find_object_containing(self, addr, membership_check=True):
        """
        Return the object that contains the given address, or None if the address is unmapped.

        :param int addr:    The address that should be contained in the object.
        :param bool membership_check:   Whether a membership check should be performed or not (True by default). This
                                        option can be set to False if you are certain that the target object does not
                                        have "holes".
        :return:            The object or None.
        """

        def _check_object_memory(obj_):
            if isinstance(obj_.memory, Clemory):
                if AT.from_va(addr, obj_).to_rva() in obj_.memory:
                    self._last_object = obj_
                    return obj_
                return None
            elif type(obj_.memory) is str:
                self._last_object = obj_
                return obj_
            else:
                raise CLEError('Unsupported memory type %s' % type(obj_.memory))

        # check the cache first
        if self._last_object is not None and \
                self._last_object.min_addr <= addr < self._last_object.max_addr:
            if not membership_check: return self._last_object
            o = _check_object_memory(self._last_object)
            if o: return o

        if addr >= self.max_addr or addr < self.min_addr:
            return None

        obj = key_bisect_floor_key(self.all_objects, addr, keyfunc=lambda obj: obj.min_addr)
        if obj is None:
            return None
        if not obj.min_addr <= addr < obj.max_addr:
            return None
        if not membership_check:
            return obj
        return _check_object_memory(obj)

    def find_segment_containing(self, addr, skip_pseudo_objects=True):
        """
        Find the section object that the address belongs to.

        :param int addr: The address to test
        :param bool skip_pseudo_objects: Skip objects that CLE adds during loading.
        :return: The section that the address belongs to, or None if the address does not belong to any section, or if
                section information is not available.
        :rtype: cle.Segment
        """

        obj = self.find_object_containing(addr, membership_check=False)

        if obj is None:
            return None

        if skip_pseudo_objects and isinstance(obj, (ExternObject, KernelObject, TLSObject)):
            # the address is from a section allocated by angr.
            return None

        return obj.find_segment_containing(addr)

    def find_section_containing(self, addr, skip_pseudo_objects=True):
        """
        Find the section object that the address belongs to.

        :param int addr: The address to test.
        :param bool skip_pseudo_objects: Skip objects that CLE adds during loading.
        :return: The section that the address belongs to, or None if the address does not belong to any section, or if
                section information is not available.
        :rtype: cle.Section
        """

        obj = self.find_object_containing(addr, membership_check=False)

        if obj is None:
            return None

        if skip_pseudo_objects and isinstance(obj, (ExternObject, KernelObject, TLSObject)):
            # the address is from a special CLE section
            return None

        return obj.find_section_containing(addr)

    def find_section_next_to(self, addr, skip_pseudo_objects=True):
        """
        Find the next section after the given address.

        :param int addr: The address to test.
        :param bool skip_pseudo_objects: Skip objects that CLE adds during loading.
        :return: The next section that goes after the given address, or None if there is no section after the address,
                 or if section information is not available.
        :rtype: cle.Section
        """

        obj = self.find_object_containing(addr, membership_check=False)

        if obj is None:
            return None

        if skip_pseudo_objects and isinstance(obj, (ExternObject, KernelObject, TLSObject)):
            # the address is from a special CLE section
            return None

        return obj.sections.find_region_next_to(addr)

    def find_symbol(self, thing, fuzzy=False):
        """
        Search for the symbol with the given name or address.

        :param thing:       Either the name or address of a symbol to look up
        :param fuzzy:       Set to True to return the first symbol before or at the given address

        :returns:           A :class:`cle.backends.Symbol` object if found, None otherwise.
        """
        if type(thing) is archinfo.arch_soot.SootAddressDescriptor:
            # Soot address
            return thing.method.fullname
        elif type(thing) is int:
            # address
            if fuzzy:
                so = self.find_object_containing(thing)
                if so is None:
                    return None
                objs = [so]
            else:
                objs = self.all_objects

            for so in objs:
                idx = so.symbols.bisect_key_right(AT.from_mva(thing, so).to_rva()) - 1
                while idx >= 0 and (fuzzy or so.symbols[idx].rebased_addr == thing):
                    if so.symbols[idx].is_import:
                        idx -= 1
                        continue
                    return so.symbols[idx]
        else:
            # name
            for so in self.all_objects:
                if so is self._extern_object:
                    continue
                sym = so.get_symbol(thing)
                if sym is None:
                    continue

                if sym.is_import:
                    if sym.resolvedby is not None:
                        if sym.resolvedby.is_forward and sym.resolvedby.resolvedby is not None:
                            return sym.resolvedby.resolvedby
                        return sym.resolvedby
                else:
                    if sym.is_forward and sym.resolvedby is not None:
                        return sym.resolvedby
                    return sym

            if self._extern_object is not None:
                sym = self.extern_object.get_symbol(thing)
                if sym is not None:
                    return sym

        return None

    @property
    def symbols(self):
        peeks = []
        for so in self.all_objects:
            if so.symbols:
                i = iter(so.symbols)
                n = next(i)
                peeks.append((n, i))
        while peeks:
            element = min(peeks, key=lambda x: x[0].rebased_addr) # if we don't do this it might crash on comparing iterators
            n, i = element
            idx = peeks.index(element)
            yield n
            try:
                peeks[idx] = next(i), i
            except StopIteration:
                peeks.pop(idx)

    def find_all_symbols(self, name, exclude_imports=True, exclude_externs=False, exclude_forwards=True):
        """
        Iterate over all symbols present in the set of loaded binaries that have the given name

        :param name:                The name to search for
        :param exclude_imports:     Whether to exclude import symbols. Default True.
        :param exclude_externs:     Whether to exclude symbols in the extern object. Default False.
        :param exclude_forwards:    Whether to exclude forward symbols. Default True.
        """
        for so in self.all_objects:
            sym = so.get_symbol(name)
            if sym is None:
                continue
            if sym.is_import and exclude_imports:
                continue
            if sym.owner is self._extern_object and exclude_externs:
                continue
            if sym.is_forward and exclude_forwards:
                continue

            yield sym

    def find_plt_stub_name(self, addr):
        """
        Return the name of the PLT stub starting at ``addr``.
        """
        so = self.find_object_containing(addr)
        if so is not None and isinstance(so, MetaELF):
            return so.reverse_plt.get(addr, None)
        return None

    def find_relevant_relocations(self, name):
        """
        Iterate through all the relocations referring to the symbol with the given ``name``
        """
        for so in self.all_objects:
            for reloc in so.relocs:
                if reloc.symbol is not None:
                    if reloc.symbol.name == name:
                        yield reloc

    # Complicated stuff

    def perform_irelative_relocs(self, resolver_func):
        """
        Use this method to satisfy ``IRelative`` relocations in the binary that require execution of loaded code.

        Note that this does NOT handle ``IFunc`` symbols, which must be handled separately. (this could be changed, but
        at the moment it's desirable to support lazy IFunc resolution, since emulation is usually slow)

        :param resolver_func:   A callback function that takes an address, runs the code at that address, and returns
                                the return value from the emulated function.
        """
        for obj in self.all_objects:
            for resolver, dest in obj.irelatives:
                val = resolver_func(resolver)
                if val is not None:
                    obj.memory.pack_word(dest, val)

    def dynamic_load(self, spec):
        """
        Load a file into the address space. Note that the sematics of ``auto_load_libs`` and ``except_missing_libs``
        apply at all times.

        :param spec:    The path to the file to load. May be an absolute path, a relative path, or a name to search in
                        the load path.

        :return:        A list of all the objects successfully loaded, which may be empty if this object was previously
                        loaded. If the object specified in ``spec`` failed to load for any reason, including the file
                        not being found, return None.
        """
        try:
            return self._internal_load(spec)
        except CLEFileNotFoundError as e:
            l.warning("Dynamic load failed: %r", e)
            return None

    def add_object(self, obj):
        """
        If you've constructed your own Backend-subclass object and want to add it directly to the loader, use this.
        """
        self._register_object(obj)
        self._map_object(obj)
        if isinstance(obj, (MetaELF, PE)) and obj.tls_used:
            self.tls_object.register_object(obj)
        self._relocate_object(obj)

    def get_loader_symbolic_constraints(self):
        """
        Do not use this method.
        """
        if not self.aslr:
            return []
        if not claripy:
            l.error("Please install claripy to get symbolic constraints")
            return []
        outputlist = []
        for obj in self.all_objects:
            #TODO Fix Symbolic for tls whatever
            if obj.aslr and isinstance(obj.mapped_base_symbolic, claripy.ast.BV):
                outputlist.append(obj.mapped_base_symbolic == obj.mapped_base)
        return outputlist


    # Private stuff

    @staticmethod
    def _is_linux_loader_name(name):
        """
        ld can have different names such as ld-2.19.so or ld-linux-x86-64.so.2 depending on symlinks and whatnot.
        This determines if `name` is a suitable candidate for ld.
        """
        return 'ld.so' in name or 'ld64.so' in name or 'ld-linux' in name

    def _internal_load(self, *args):
        """
        Pass this any number of files or libraries to load. If it can't load any of them for any reason, it will
        except out. Note that the sematics of ``auto_load_libs`` and ``except_missing_libs`` apply at all times.

        It will return a list of all the objects successfully loaded, which may be smaller than the list you provided
        if any of them were previously loaded.
        """
        objects = []
        dependencies = []
        cached_failures = set() # this assumes that the load path is global and immutable by the time we enter this func

        for main_spec in args:
            if self.find_object(main_spec, extra_objects=objects) is not None:
                l.info("Skipping load request %s - already loaded", main_spec)
                continue
            main_obj = self._load_object_isolated(main_spec)
            objects.append(main_obj)
            dependencies.extend(main_obj.deps)

            if self.main_object is None:
                self.main_object = main_obj
                self.memory = Clemory(self.main_object.arch, root=True)

        while self._auto_load_libs and dependencies:
            dep_spec = dependencies.pop(0)
            if dep_spec in cached_failures:
                l.debug("Skipping implicit dependency %s - cached failure", dep_spec)
                continue
            if self.find_object(dep_spec, extra_objects=objects) is not None:
                l.debug("Skipping implicit dependency %s - already loaded", dep_spec)
                continue

            try:
                l.info("Loading %s...", dep_spec)
                dep_obj = self._load_object_isolated(dep_spec)  # loading dependencies
            except CLEFileNotFoundError:
                l.info("... not found")
                cached_failures.add(dep_spec)
                if self._except_missing_libs:
                    raise
                else:
                    continue

            objects.append(dep_obj)
            dependencies.extend(dep_obj.deps)

        for obj in objects:
            self._register_object(obj)
        for obj in objects:
            self._map_object(obj)
        for obj in objects:
            if isinstance(obj, (MetaELF, PE)) and obj.tls_used:
                self.tls_object.register_object(obj)
        if self._perform_relocations:
            for obj in objects:
                self._relocate_object(obj)

        for obj in objects:
            if isinstance(obj, (MetaELF, PE)) and obj.tls_used:
                self.tls_object.map_object(obj)
        if self._extern_object and self._extern_object.tls_used:
            # this entire scheme will break when we do dynamic loading. you have been warned, me.
            self.tls_object.map_object(self._extern_object)

        return objects

    def _register_object(self, obj):
        """
        Insert this object's clerical information into the loader
        """
        self.requested_names.update(obj.deps)
        for ident in self._possible_idents(obj):
            self._satisfied_deps[ident] = obj

        if obj.provides is not None:
            self.shared_objects[obj.provides] = obj

    def _load_object_isolated(self, spec):
        """
        Given a partial specification of a dependency, this will return the loaded object as a backend instance.
        It will not touch any loader-global data.
        """
        # STEP 1: identify file
        if isinstance(spec, Backend):
            return spec
        elif hasattr(spec, 'read') and hasattr(spec, 'seek'):
            full_spec = spec
        elif type(spec) in (bytes, str):
            full_spec = self._search_load_path(spec) # this is allowed to cheat and do partial static loading
            l.debug("... using full path %s", full_spec)
        else:
            raise CLEError("Bad library specification: %s" % spec)

        # STEP 2: collect options
        if self.main_object is None:
            options = self._main_opts
        else:
            for ident in self._possible_idents(full_spec): # also allowed to cheat
                if ident in self._lib_opts:
                    options = self._lib_opts[ident]
                    break
            else:
                options = {}

        # STEP 3: identify backend
        backend_spec = options.pop('backend', None)
        backend_cls = self._backend_resolver(backend_spec)
        if backend_cls is None:
            backend_cls = self._static_backend(full_spec)
        if backend_cls is None:
            raise CLECompatibilityError("Unable to find a loader backend for %s.  Perhaps try the 'blob' loader?" % spec)

        # STEP 4: LOAD!
        l.debug("... loading with %s", backend_cls)

        return backend_cls(full_spec, is_main_bin=self.main_object is None, loader=self, **options)

    def _map_object(self, obj):
        """
        This will integrate the object into the global address space, but will not perform relocations.
        """
        obj_size = obj.max_addr - obj.min_addr

        if obj.pic:
            if obj._custom_base_addr is not None and self._is_range_free(obj._custom_base_addr, obj_size):
                base_addr = obj._custom_base_addr
            elif obj.linked_base and self._is_range_free(obj.linked_base, obj_size):
                base_addr = obj.linked_base
            elif not obj.is_main_bin:
                base_addr = self._find_safe_rebase_addr(obj_size)
            else:
                l.warning("The main binary is a position-independent executable. "
                          "It is being loaded with a base address of 0x400000.")
                base_addr = 0x400000

            obj.mapped_base = base_addr
            obj.rebase()
        else:
            if obj._custom_base_addr is not None and not isinstance(obj, Blob):
                l.warning("%s: base_addr was specified but the object is not PIC. "
                    "specify force_rebase=True to override",
                            os.path.basename(obj.binary) if obj.binary is not None else obj.binary_stream)
            base_addr = obj.linked_base
            if not self._is_range_free(obj.linked_base, obj_size):
                raise CLEError("Position-DEPENDENT object %s cannot be loaded at %#x"% (obj.binary, base_addr))

        assert obj.min_addr < obj.max_addr
        assert obj.mapped_base >= 0

        if obj.has_memory:
            l.info("Mapping %s at %#x", obj.binary, base_addr)
            self.memory.add_backer(base_addr, obj.memory)
            key_bisect_insort_left(self.all_objects, obj, keyfunc=lambda o: o.min_addr)
        obj._is_mapped = True

    def _relocate_object(self, obj):
        """
        Perform the relocations for ``obj``, making sure its dependencies are relocated first
        """
        if id(obj) in self._relocated_objects:
            return
        self._relocated_objects.add(id(obj))

        dep_objs = [self.shared_objects[dep_name] for dep_name in obj.deps if dep_name in self.shared_objects]
        for dep_obj in dep_objs:
            self._relocate_object(dep_obj)

        l.info("Relocating %s", obj.binary)
        for reloc in obj.relocs:
            if not reloc.resolved:
                reloc.relocate(([self.main_object] if self.main_object is not obj else []) + dep_objs + [obj])

    # Address space management

    def _find_safe_rebase_addr(self, size):
        """
        Return a "safe" virtual address to map an object of size ``size``, i.e. one that won't
        overlap with anything already loaded.
        """
        # this assumes that self.main_object exists, which should... definitely be safe
        if self.main_object.arch.bits < 32:
            # HACK: On small arches, we should be more aggressive in packing stuff in.
            gap_start = 0
        else:
            gap_start = ALIGN_UP(self.main_object.max_addr, self._rebase_granularity)
        for o in self.all_objects:
            if gap_start + size <= o.min_addr:
                break
            else:
                gap_start = ALIGN_UP(o.max_addr, self._rebase_granularity)

        if gap_start + size >= 2**self.main_object.arch.bits:
            raise CLEOperationError("Ran out of room in address space")

        return gap_start

    def _is_range_free(self, va, size):
        # self.main_object should not be None here
        if va < 0 or va + size >= 2**self.main_object.arch.bits:
            return False

        for o in self.all_objects:
            if o.min_addr <= va < o.max_addr or va <= o.min_addr < va + size:
                return False

        return True

    # Functions of the form "use some heuristic to tell me about this spec"

    def _search_load_path(self, spec):
        """
        This will return the most likely full path that could satisfy the given partial specification.

        It will prefer files of a known filetype over files of an unknown filetype.
        """
        # this could be converted to being an iterator pretty easily
        for path in self._possible_paths(spec):
            if self.main_object is not None:
                backend_cls = self._static_backend(path)
                if backend_cls is None:
                    continue
                if not backend_cls.check_compatibility(path, self.main_object):
                    continue

            return path

        raise CLEFileNotFoundError("Could not find file %s" % spec)

    def _possible_paths(self, spec):
        """
        This iterates through each possible path that could possibly be used to satisfy the specification.

        The only check performed is whether the file exists or not.
        """
        dirs = []
        dirs.extend(self._custom_ld_path)                   # if we say dirs = blah, we modify the original

        if self.main_object is not None:
            if self.main_object.binary is not None:
                dirs.append(os.path.dirname(self.main_object.binary))
            if self._use_system_libs:
                # Ideally this should be taken into account for each shared
                # object, not just the main object.
                dirs.extend(self.main_object.extra_load_path)
                if sys.platform.startswith('linux'):
                    dirs.extend(self.main_object.arch.library_search_path())
                elif sys.platform == 'win32':
                    native_dirs = os.environ['PATH'].split(';')

                    # simulate the wow64 filesystem redirect, working around the fact that WE may be impacted by it as
                    # a 32-bit python process.......
                    python_is_32bit = platform.architecture()[0] == '32bit'
                    guest_is_32bit = self.main_object.arch.bits == 32

                    if python_is_32bit != guest_is_32bit:
                        redirect_dir = os.path.join(os.environ['SystemRoot'], 'system32').lower()
                        target_dir = os.path.join(os.environ['SystemRoot'], 'SysWOW64' if guest_is_32bit else 'sysnative')
                        i = 0
                        while i < len(native_dirs):
                            if native_dirs[i].lower().startswith(redirect_dir):
                                # replace the access to System32 with SysWOW64 or sysnative
                                native_dirs[i] = target_dir + native_dirs[i][len(target_dir):]
                            i += 1

                    dirs.extend(native_dirs)

        dirs.append('.')


        if self._case_insensitive:
            spec = spec.lower()

        for libdir in dirs:
            if self._case_insensitive:
                insensitive_path = self._path_insensitive(os.path.join(libdir, spec))
                if insensitive_path is not None:
                    yield os.path.realpath(insensitive_path)
            else:
                fullpath = os.path.realpath(os.path.join(libdir, spec))
                if os.path.exists(fullpath):
                    yield fullpath

            if self._ignore_import_version_numbers:
                try:
                    for libname in os.listdir(libdir):
                        ilibname = libname.lower() if self._case_insensitive else libname
                        if ilibname.strip('.0123456789') == spec.strip('.0123456789'):
                            yield os.path.realpath(os.path.join(libdir, libname))
                except (IOError, OSError): pass

    @classmethod
    def _path_insensitive(cls, path):
        """
        Get a case-insensitive path for use on a case sensitive system, or return None if it doesn't exist.

        From https://stackoverflow.com/a/8462613
        """
        if path == '' or os.path.exists(path):
            return path
        base = os.path.basename(path)  # may be a directory or a file
        dirname = os.path.dirname(path)
        suffix = ''
        if not base:  # dir ends with a slash?
            if len(dirname) < len(path):
                suffix = path[:len(path) - len(dirname)]
            base = os.path.basename(dirname)
            dirname = os.path.dirname(dirname)
        if not os.path.exists(dirname):
            dirname = cls._path_insensitive(dirname)
            if not dirname:
                return None
        # at this point, the directory exists but not the file
        try:  # we are expecting dirname to be a directory, but it could be a file
            files = os.listdir(dirname)
        except OSError:
            return None
        baselow = base.lower()
        try:
            basefinal = next(fl for fl in files if fl.lower() == baselow)
        except StopIteration:
            return None
        if basefinal:
            return os.path.join(dirname, basefinal) + suffix
        else:
            return None

    def _possible_idents(self, spec, lowercase=False):
        """
        This iterates over all the possible identifiers that could be used to describe the given specification.
        """
        if isinstance(spec, Backend):
            if spec.provides is not None:
                yield spec.provides
                if self._ignore_import_version_numbers:
                    yield spec.provides.rstrip('.0123456789')
            if spec.binary:
                yield spec.binary
                yield os.path.basename(spec.binary)
                yield os.path.basename(spec.binary).split('.')[0]
                if self._ignore_import_version_numbers:
                    yield os.path.basename(spec.binary).rstrip('.0123456789')
        elif hasattr(spec, 'read') and hasattr(spec, 'seek'):
            backend_cls = self._static_backend(spec)
            if backend_cls is not None:
                soname = backend_cls.extract_soname(spec)
                if soname is not None:
                    yield soname
                    if self._ignore_import_version_numbers:
                        yield soname.rstrip('.0123456789')
        elif type(spec) in (bytes, str):
            yield spec
            yield os.path.basename(spec)
            yield os.path.basename(spec).split('.')[0]
            if self._ignore_import_version_numbers:
                yield os.path.basename(spec).rstrip('.0123456789')

            if os.path.exists(spec):
                backend_cls = self._static_backend(spec)
                if backend_cls is not None:
                    soname = backend_cls.extract_soname(spec)
                    if soname is not None:
                        yield soname
                        if self._ignore_import_version_numbers:
                            yield soname.rstrip('.0123456789')

        if not lowercase and (sys.platform == 'win32' or self._case_insensitive):
            for name in self._possible_idents(spec, lowercase=True):
                yield name.lower()

    def _static_backend(self, spec):
        """
        Returns the correct loader for the file at `spec`.
        Returns None if it's a blob or some unknown type.
        TODO: Implement some binwalk-like thing to carve up blobs automatically
        """

        try:
            return self._backend_resolver(self._lib_opts[spec]['backend'])
        except KeyError:
            pass

        with stream_or_path(spec) as stream:
            for rear in ALL_BACKENDS.values():
                if rear.is_default and rear.is_compatible(stream):
                    return rear

        return None

    @staticmethod
    def _backend_resolver(backend, default=None):
        if isinstance(backend, type) and issubclass(backend, Backend):
            return backend
        elif backend in ALL_BACKENDS:
            return ALL_BACKENDS[backend]
        elif backend is None:
            return default
        else:
            raise CLEError('Invalid backend: %s' % backend)


from .errors import CLEError, CLEFileNotFoundError, CLECompatibilityError, CLEOperationError
from .memory import Clemory
from .backends import MetaELF, ELF, PE, Blob, ALL_BACKENDS, Backend
from .backends.tls import PETLSObject, ELFTLSObject, TLSObject
from .backends.externs import ExternObject, KernelObject
from .utils import stream_or_path
