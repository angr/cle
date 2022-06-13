import logging
import json

l = logging.getLogger(name=__name__)


class Corpus:
    """
    A Corpus is a set of DWARF DIEs (functions and other tags) parsed into json.
    """

    def __init__(self, library, *args, **kwargs):
        self.library = library
        self.functions = []
        self.callsites = []

        # Lookup of variables by name, and types by some other identifier
        self.variables = {}
        self.types = {}

    def to_dict(self):
        """
        Return the corpus as a dictionary (we can decide on a standard structure)
        """
        locations = []

        if self.variables:
            variables = list(self.variables.values())
            locations.append({"variables": variables})
        for func in self.functions:
            locations.append({"function": func})
        for site in self.callsites:
            locations.append({"callsite": site})
        corpus = {"library": self.library, "locations": locations}

        # If the parser chooses to replicate dwarf, so be it
        if self.types:
            corpus["types"] = self.types
        return corpus

    def to_json(self):
        """
        Dump the corpus to json
        """
        return json.dumps(self.to_dict(), indent=4)
