__author__ = "Vanessa Sochat"
__copyright__ = "Copyright The ORAS Authors."
__license__ = "Apache-2.0"

from functools import partial, update_wrapper

import json
import hashlib

class cache_type:
    """
    Ensure the parsed type is cached (added to the lookup)
    """

    def __init__(self, func):
        update_wrapper(self, func)
        self.func = func

    def __get__(self, obj, objtype):
        return partial(self.__call__, obj)

    def hash(self, typ):
        """
        Generate a unique hash depending on the type
        """    
        dumped = json.dumps(typ, sort_keys=True)
        return hashlib.md5(dumped.encode("utf-8")).hexdigest()

    def __call__(self, cls, *args, **kwargs):

        die = args[0]
        # Note that here we are returning the unique id of the type
        if die.offset in cls._types:
            return {"type": cls._types[die.offset]}
        if die.offset in cls._types_seen:
            return {"type": "Recursive"}

        # Keep track of seen by offset
        cls._types_seen.add(die.offset)
        typ = self.func(cls, *args, **kwargs)
        if not typ:
            typ = {"type": "unknown"}

        # Hash id is based on hash of type content
        uid = self.hash(typ) 
      
        # Top level types holds the uid -> type
        cls.types[uid] = typ
        
        # _types holds lookup of die offset to uid
        cls._types[die.offset] = uid
        return {"type": uid}
