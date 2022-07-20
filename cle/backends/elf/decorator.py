__author__ = "Vanessa Sochat"
__copyright__ = "Copyright The ORAS Authors."
__license__ = "Apache-2.0"

from functools import partial, update_wrapper

import json

class cache_type:
    """
    Ensure the parsed type is cached (added to the lookup)
    """

    def __init__(self, func):
        update_wrapper(self, func)
        self.func = func

    def __get__(self, obj, objtype):
        return partial(self.__call__, obj)

    def __call__(self, cls, *args, **kwargs):

        die = args[0]
        # Note that here we are returning the unique id of the type
        if die.offset in cls._types:
            return {"type": cls._types[die.offset]}
        if die.offset in cls._types_seen:
            return {"type": "Recursive"}

        # Do we want to return the type instead of lookup to it?
        return_type = False
        if "return_type" in kwargs:
            return_type = kwargs.get('return_type')
            del kwargs["return_type"]
        
        # Keep track of seen by offset
        cls._types_seen.add(die.offset)
        typ = self.func(cls, *args, **kwargs)
        if not typ:
            typ = {"type": "unknown"}

        # Hash id is based on hash of type content
        uid = cls.hash(typ) 
      
        # Top level types holds the uid -> type
        cls.types[uid] = typ
        
        # _types holds lookup of die offset to uid
        cls._types[die.offset] = uid

        if return_type:
            return typ
        return {"type": uid}
