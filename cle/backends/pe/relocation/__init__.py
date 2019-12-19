import os
import logging
import importlib
import archinfo
from collections import defaultdict
from ...relocation import Relocation

ALL_RELOCATIONS = defaultdict(dict)
complaint_log = set()

path = os.path.dirname(os.path.abspath(__file__))
l = logging.getLogger(name=__name__)

def load_relocations():
    for filename in os.listdir(path):
        if not filename.endswith('.py'):
            continue
        if filename == '__init__.py':
            continue

        l.debug('Importing PE relocation module: %s', filename[:-3])
        module = importlib.import_module('.%s' % filename[:-3], 'cle.backends.pe.relocation')

        try:
            arch_name = module.arch
        except AttributeError:
            continue

        for item_name in dir(module):
            if item_name not in archinfo.defines:
                continue
            item = getattr(module, item_name)
            if not isinstance(item, type) or not issubclass(item, Relocation):
                continue

            ALL_RELOCATIONS[arch_name][archinfo.defines[item_name]] = item


def get_relocation(arch, r_type):
    if r_type == 0:
        return None
    try:
        return ALL_RELOCATIONS[arch][r_type]
    except KeyError:
        if (arch, r_type) not in complaint_log:
            complaint_log.add((arch, r_type))
            l.warning("Unknown reloc %d on %s", r_type, arch)
        return None

load_relocations()
