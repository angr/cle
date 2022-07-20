#!/usr/bin/python


import cle
from deepdiff import DeepDiff
import pytest
import json
import shutil
import sys
import os
import io
from collections import OrderedDict

here = os.path.abspath(os.path.dirname(__file__))

args = [x for x in sys.argv if not x.startswith("-")]
if len(args) > 2:
    examples_dir = os.path.abspath(args[-1])
else:
    examples_dir = os.path.join(here, "examples")

sys.path.insert(0, here)

# Load all examples
tests = []

skips = ["Makefile", "build.sh", "dwarfdump.sh"]

# Add remainder
for name in os.listdir(examples_dir):
    if name in skips:
        continue
    if (
        not name.startswith("_")
        and not name.startswith(".")
        and not name.endswith(".md")
    ):
        tests.append((name, "lib.so"))


def write_json(data, filename):
    with open(filename, "w") as fd:
        fd.write(json.dumps(data, indent=4))


def read_json(filename):
    with open(filename, "r") as fd:
        content = json.loads(fd.read())
    return content


def check_facts(expected, facts):
    expected = read_json(expected)
    # This will vary based on the host
    libA = expected["library"]
    libB = facts["library"]
    del expected["library"]
    del facts["library"]
    res = DeepDiff(expected, facts)
    if res:
        print(res)
    assert not res

    # Not sure that we need to restore this, but I felt the desire to :)
    expected["library"] = libA
    facts["library"] = libA


def run(name, lib):
    """
    Run an example
    """
    path = os.path.join(examples_dir, name, lib)
    if not os.path.exists(path):
        path = os.path.join(examples_dir, name, "example")
    if not os.path.exists(path):
        sys.exit("%s does not exist" % path)
    ld = cle.Loader(path, load_debug_info=True, auto_load_libs=False)
    return ld.corpus


@pytest.mark.parametrize("name,lib", tests)
def test_examples(tmp_path, name, lib):
    corpus = run(name, lib)

    # First look for truth facts (will not be deleted)
    truth = os.path.join(examples_dir, name, "facts.truth.json")

    # These are temporary / WIP and can be changed
    facts = os.path.join(examples_dir, name, "facts.json")

    if not os.path.exists(truth):
        truth = facts

    # Always write facts (not truth)
    write_json(OrderedDict(corpus.to_dict()), facts)

    # Check facts (nodes and relations)
    if os.path.exists(truth):
        check_facts(truth, corpus.to_dict())
