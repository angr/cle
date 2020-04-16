import os
import sys
import platform
import logging
from collections import OrderedDict

import archinfo
from archinfo.arch_soot import ArchSoot

from .address_translator import AT
from .utils import ALIGN_UP, key_bisect_floor_key, key_bisect_insort_right

try:
    import claripy
except ImportError:
    claripy = None

__all__ = ('Loader',)

l = logging.getLogger(name=__name__)


class Loader:
    """
    The loader loads all the objects and exports an abstraction of the memory of the process. What you see here is an
    address space with loaded and rebased binaries.

    :param main_binary:         The path to the main binary you're loading, or a file-like object with the binary
                                in it.

    The following parameters are optional.

    :param auto_load_libs:      Whether to automatically load shared libraries that loaded objects depend on.
    :param load_debug_info:     Whether to automatically parse DWARF data and search for debug symbol files.
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
    :param preload_libs:        Similar to `force_load_libs` but will provide for symbol resolution, with precedence
                                over any dependencies.
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
                 ignore_import_version_numbers=True, case_insensitive=False, rebase_granularity=0x100000,
                 except_missing_libs=False, aslr=False, perform_relocations=True, load_debug_info=False,
                 page_size=0x1, preload_libs=(), arch=None):
        if hasattr(main_binary, 'seek') and hasattr(main_binary, 'read'):
            self._main_binary_path = None
            self._main_binary_stream = main_binary
        else:
            self._main_binary_path = os.path.realpath(str(main_binary))
            self._main_binary_stream = None

        # whether we are presently in the middle of a load cycle
        self._juggling = False

        # auto_load_libs doesn't make any sense if we have a concrete target.
        if concrete_target:
            auto_load_libs = False

        self._auto_load_libs = auto_load_libs
        self._load_debug_info = load_debug_info
        self._satisfied_deps = dict((x, False) for x in skip_libs)
        self._main_opts = {} if main_opts is None else main_opts
        self._lib_opts = {} if lib_opts is None else lib_opts
        self._custom_ld_path = [ld_path] if type(ld_path) is str else ld_path
        force_load_libs = [force_load_libs] if type(force_load_libs) is str else force_load_libs
        preload_libs = [preload_libs] if type(preload_libs) is str else preload_libs
        self._use_system_libs = use_system_libs
        self._ignore_import_version_numbers = ignore_import_version_numbers
        self._case_insensitive = case_insensitive
        self._rebase_granularity = rebase_granularity
        self._except_missing_libs = except_missing_libs
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
        self.tls = None # type: ThreadManager
        self._kernel_object = None # type: KernelObject
        self._extern_object = None # type: ExternObject
        self.shared_objects = OrderedDict()
        self.all_objects = []  # this list should always be sorted by min_addr
        self.requested_names = set()
        if arch is not None:
            self._main_opts.update({'arch': arch})
        self.preload_libs = []
        self.initial_load_objects = self._internal_load(main_binary, *preload_libs, *force_load_libs, preloading=(main_binary, *preload_libs))

        # cache
        self._last_object = None

        if self._extern_object and self._extern_object._warned_data_import:
            l.warning('For more information about "Symbol was allocated without a known size", see https://docs.angr.io/extending-angr/environment#simdata')

    # Basic functions and properties

    def close(self):
        l.warning("You don't need to close the loader anymore :)")

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

        proposed model for how multiple extern objects should work:

            1) extern objects are a linked list. the one in loader._extern_object is the head of the list
            2) each round of explicit loads generates a new extern object if it has unresolved dependencies. this object
               has exactly the size necessary to hold all its exports.
            3) All requests for size are passed down the chain until they reach an object which has the space to service it
               or an object which has not yet been mapped. If all objects have been mapped and are full, a new extern object
               is mapped with a fixed size.
        """
        if self._extern_object is None:
            if self.main_object.arch.bits < 32:
                extern_size = 0x200
            elif self.main_object.arch.bits == 32:
                extern_size = 0x8000
            else:
                extern_size = 0x80000
            self._extern_object = ExternObject(self, map_size=extern_size)
            self._internal_load(self._extern_object)
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
        return self.requested_names - set(k for k,v in self._satisfied_deps.items() if v is not False)

    @property
    def auto_load_libs(self):
        return self._auto_load_libs

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
        if isinstance(spec, Backend):
            for obj in self.all_objects:
                if obj is spec:
                    return obj
            return None

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
                self._last_object.min_addr <= addr <= self._last_object.max_addr:
            if not membership_check: return self._last_object
            if not self._last_object.has_memory: return self._last_object
            o = _check_object_memory(self._last_object)
            if o: return o

        if addr > self.max_addr or addr < self.min_addr:
            return None

        obj = key_bisect_floor_key(self.all_objects, addr, keyfunc=lambda obj: obj.min_addr)
        if obj is None:
            return None
        if not obj.min_addr <= addr <= obj.max_addr:
            return None
        if not membership_check:
            self._last_object = obj
            return obj
        if not obj.has_memory:
            self._last_object = obj
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

    def _internal_load(self, *args, preloading=()):
        """
        Pass this any number of files or libraries to load. If it can't load any of them for any reason, it will
        except out. Note that the semantics of ``auto_load_libs`` and ``except_missing_libs`` apply at all times.

        It will return a list of all the objects successfully loaded, which may be smaller than the list you provided
        if any of them were previously loaded.

        The ``main_binary`` has to come first, followed by any additional libraries to load this round. To create the
        effect of "preloading", i.e. ensuring symbols are resolved to preloaded libraries ahead of any others, pass
        ``preloading`` as a list of identifiers which should be considered preloaded. Note that the identifiers will
        be compared using object identity.
        """
        # ideal loading pipeline:
        # - load everything, independently and recursively until dependencies are satisfied
        # - resolve symbol-based dependencies
        # - layout address space, including (as a prerequisite) coming up with the layout for tls and externs
        # - map everything into memory
        # - perform relocations

        # STEP 1
        # Load everything. for each binary, load it in isolation so we end up with a Backend instance.
        # If auto_load_libs is on, do this iteratively until all dependencies is satisfied
        objects = []
        preload_objects = []
        dependencies = []
        cached_failures = set() # this assumes that the load path is global and immutable by the time we enter this func

        for main_spec in args:
            is_preloading = any(spec is main_spec for spec in preloading)
            if self.find_object(main_spec, extra_objects=objects) is not None:
                l.info("Skipping load request %s - already loaded", main_spec)
                continue
            obj = self._load_object_isolated(main_spec)
            objects.append(obj)
            objects.extend(obj.child_objects)
            dependencies.extend(obj.deps)

            if self.main_object is None:
                # this is technically the first place we can start to initialize things based on platform
                self.main_object = obj
                self.memory = Clemory(obj.arch, root=True)

                chk_obj = self.main_object if isinstance(self.main_object, ELFCore) or not self.main_object.child_objects else self.main_object.child_objects[0]
                if isinstance(chk_obj, ELFCore):
                    self.tls = ELFCoreThreadManager(self, obj.arch)
                elif isinstance(obj, Minidump):
                    self.tls = MinidumpThreadManager(self, obj.arch)
                elif isinstance(chk_obj, MetaELF):
                    self.tls = ELFThreadManager(self, obj.arch)
                elif isinstance(chk_obj, PE):
                    self.tls = PEThreadManager(self, obj.arch)
                else:
                    self.tls = ThreadManager(self, obj.arch)

            elif is_preloading:
                self.preload_libs.append(obj)
                preload_objects.append(obj)


        while self._auto_load_libs and dependencies:
            spec = dependencies.pop(0)
            if spec in cached_failures:
                l.debug("Skipping implicit dependency %s - cached failure", spec)
                continue
            if self.find_object(spec, extra_objects=objects) is not None:
                l.debug("Skipping implicit dependency %s - already loaded", spec)
                continue

            try:
                l.info("Loading %s...", spec)
                obj = self._load_object_isolated(spec)  # loading dependencies
            except CLEFileNotFoundError:
                l.info("... not found")
                cached_failures.add(spec)
                if self._except_missing_libs:
                    raise
                continue

            objects.append(obj)
            objects.extend(obj.child_objects)
            dependencies.extend(obj.deps)

            if type(self.tls) is ThreadManager:   # ... java
                if isinstance(obj, MetaELF):
                    self.tls = ELFThreadManager(self, obj.arch)
                elif isinstance(obj, PE):
                    self.tls = PEThreadManager(self, obj.arch)

        # STEP 1.5
        # produce dependency-ordered list of objects and soname map

        ordered_objects = []
        soname_mapping = OrderedDict((obj.provides, obj) for obj in objects if obj.provides)
        seen = set()
        def visit(obj):
            if id(obj) in seen:
                return
            seen.add(id(obj))

            dep_objs = [soname_mapping[dep_name] for dep_name in obj.deps if dep_name in soname_mapping]
            for dep_obj in dep_objs:
                visit(dep_obj)

            ordered_objects.append(obj)

        for obj in preload_objects + objects:
            visit(obj)

        # STEP 2
        # Resolve symbol dependencies. Create an unmapped extern object, which may not be used
        # after this step, everything should have the appropriate references to each other and the extern
        # object should have all the space it needs allocated

        extern_obj = ExternObject(self)

        # tls registration
        for obj in objects:
            self.tls.register_object(obj)

        # link everything
        if self._perform_relocations:
            for obj in ordered_objects:
                l.info("Linking %s", obj.binary)
                sibling_objs = list(obj.parent_object.child_objects) if obj.parent_object is not None else []
                dep_objs = [soname_mapping[dep_name] for dep_name in obj.deps if dep_name in soname_mapping]
                main_objs = [self.main_object] if self.main_object is not obj else []
                for reloc in obj.relocs:
                    reloc.resolve_symbol(main_objs + preload_objects + sibling_objs + dep_objs + [obj], extern_object=extern_obj)

        # if the extern object was used, add it to the list of objects we're mapping
        # also add it to the linked list of extern objects
        if extern_obj.map_size:
            # resolve the extern relocs this way because they may produce more relocations as we go
            i = 0
            while i < len(extern_obj.relocs):
                extern_obj.relocs[i].resolve_symbol(objects, extern_object=extern_obj)
                i += 1

            objects.append(extern_obj)
            ordered_objects.insert(0, extern_obj)
            extern_obj._next_object = self._extern_object
            self._extern_object = extern_obj

            extern_obj._finalize_tls()
            self.tls.register_object(extern_obj)

        # STEP 3
        # Map everything to memory
        for obj in objects:
            self._map_object(obj)

        # STEP 4
        # Perform relocations
        if self._perform_relocations:
            for obj in ordered_objects:
                obj.relocate()

        # Step 5
        # Insert each object into the appropriate mappings for lookup by name
        for obj in objects:
            self.requested_names.update(obj.deps)
            for ident in self._possible_idents(obj):
                self._satisfied_deps[ident] = obj

            if obj.provides is not None:
                self.shared_objects[obj.provides] = obj

        return objects

    def _load_object_isolated(self, spec):
        """
        Given a partial specification of a dependency, this will return the loaded object as a backend instance.
        It will not touch any loader-global data.
        """
        # STEP 1: identify file
        if isinstance(spec, Backend):
            return spec
        elif hasattr(spec, 'read') and hasattr(spec, 'seek'):
            binary_stream = spec
            binary = None
            close = False
        elif type(spec) in (bytes, str):
            binary = self._search_load_path(spec) # this is allowed to cheat and do partial static loading
            l.debug("... using full path %s", binary)
            binary_stream = open(binary, 'rb')
            close = True
        else:
            raise CLEError("Bad library specification: %s" % spec)

        try:
            # STEP 2: collect options
            if self.main_object is None:
                options = dict(self._main_opts)
            else:
                for ident in self._possible_idents(binary_stream if binary is None else binary): # also allowed to cheat
                    if ident in self._lib_opts:
                        options = dict(self._lib_opts[ident])
                        break
                else:
                    options = {}

            # STEP 3: identify backend
            backend_spec = options.pop('backend', None)
            backend_cls = self._backend_resolver(backend_spec)
            if backend_cls is None:
                backend_cls = self._static_backend(binary_stream if binary is None else binary)
            if backend_cls is None:
                raise CLECompatibilityError("Unable to find a loader backend for %s.  Perhaps try the 'blob' loader?" % spec)

            # STEP 4: LOAD!
            l.debug("... loading with %s", backend_cls)

            result = backend_cls(binary, binary_stream, is_main_bin=self.main_object is None, loader=self, **options)
            result.close()
            return result
        finally:
            if close:
                binary_stream.close()

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

            obj.rebase(base_addr)
        else:
            if obj._custom_base_addr is not None and not isinstance(obj, Blob):
                l.warning("%s: base_addr was specified but the object is not PIC. "
                          "specify force_rebase=True to override", obj.binary_basename)
            base_addr = obj.linked_base
            if not self._is_range_free(obj.linked_base, obj_size):
                raise CLEError("Position-DEPENDENT object %s cannot be loaded at %#x"% (obj.binary, base_addr))

        assert obj.mapped_base >= 0

        if obj.has_memory:
            assert obj.min_addr < obj.max_addr
            l.info("Mapping %s at %#x", obj.binary, base_addr)
            self.memory.add_backer(base_addr, obj.memory)
        obj._is_mapped = True
        key_bisect_insort_right(self.all_objects, obj, keyfunc=lambda o: o.min_addr)

    # Address space management

    def _find_safe_rebase_addr(self, size):
        """
        Return a "safe" virtual address to map an object of size ``size``, i.e. one that won't
        overlap with anything already loaded.
        """
        # this assumes that self.main_object exists, which should... definitely be safe
        if self.main_object.arch.bits < 32 or self.main_object.max_addr >= 2**(self.main_object.arch.bits-1):
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
                # If arch of main object is Soot ...
                if isinstance(self.main_object.arch, ArchSoot):
                    # ... skip compatibility check, since it always evaluates to false
                    # with native libraries (which are the only valid dependencies)
                    return path
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
            # add path of main binary
            if self.main_object.binary is not None:
                dirs.append(os.path.dirname(self.main_object.binary))
            # if arch of main_object is Soot ...
            is_arch_soot = isinstance(self.main_object.arch, ArchSoot)
            if is_arch_soot:
                # ... extend with load path of native libraries
                dirs.extend(self.main_object.extra_load_path)
                if self._use_system_libs:
                    l.debug("Path to system libraries (usually added as dependencies of JNI libs) needs "
                            "to be specified manually, by using the custom_ld_path option.")
            # add path of system libraries
            if self._use_system_libs and not is_arch_soot:
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
            backend_cls = self._static_backend(spec, ignore_hints=True)
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
                backend_cls = self._static_backend(spec, ignore_hints=True)
                if backend_cls is not None:
                    soname = backend_cls.extract_soname(spec)
                    if soname is not None:
                        yield soname
                        if self._ignore_import_version_numbers:
                            yield soname.rstrip('.0123456789')

        if not lowercase and (sys.platform == 'win32' or self._case_insensitive):
            for name in self._possible_idents(spec, lowercase=True):
                yield name.lower()

    def _static_backend(self, spec, ignore_hints=False):
        """
        Returns the correct loader for the file at `spec`.
        Returns None if it's a blob or some unknown type.
        TODO: Implement some binwalk-like thing to carve up blobs automatically
        """

        if not ignore_hints:
            for ident in self._possible_idents(spec):
                try:
                    return self._backend_resolver(self._lib_opts[ident]['backend'])
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
from .backends import MetaELF, ELF, PE, ELFCore, Minidump, Blob, ALL_BACKENDS, Backend
from .backends.tls import ThreadManager, ELFThreadManager, PEThreadManager, ELFCoreThreadManager, MinidumpThreadManager, TLSObject
from .backends.externs import ExternObject, KernelObject
from .utils import stream_or_path
