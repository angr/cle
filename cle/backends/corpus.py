import logging
import json

l = logging.getLogger(name=__name__)


class Corpus:
    """
    A Corpus is a set of DWARF DIEs (functions and other tags) parsed into json.
    """

    def __init__(self, library, *args, **kwargs):
        self.library = library
        self.variables = []
        self.functions = []
        self.callsites = []

    def to_dict(self):
        """
        Return the corpus as a dictionary (we can decide on a standard structure)
        """
        locations = []
        locations.append({"variables": self.variables})
        for func in self.functions:
            locations.append({"function": func})
        for site in self.callsites:
            locations.append({"callsite": site})
        return {"library": self.library, "locations": locations}

    def to_json(self):
        """
        Dump the corpus to json
        """
        return json.dumps(self.to_dict(), indent=4)
