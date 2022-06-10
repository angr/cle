__author__ = "Vanessa Sochat"
__copyright__ = "Copyright The ORAS Authors."
__license__ = "Apache-2.0"

from functools import partial, update_wrapper


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
        if die in cls.types:
            return cls.types[die]
        if die.offset in cls.types_seen:
            return {"type": "Recursive"}

        # Keep track of seen by offset
        cls.types_seen.add(die.offset)
        typ = self.func(cls, *args, **kwargs)
        cls.types[die] = typ
        return typ
