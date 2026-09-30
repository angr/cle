from __future__ import annotations

import os

import cle

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_clemory_views_refuse_iteration():
    loader = cle.Loader(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
    memory = loader.memory
    start = memory.min_addr

    for view in (
        cle.ClemoryView(memory, start, start + 0x100),
        cle.ClemoryTranslator(memory, lambda addr: addr + start),
        cle.ClemoryReadOnlyView(loader.main_object.arch, memory),
    ):
        try:
            iter(view)
        except NotImplementedError:
            continue
        raise AssertionError(f"{type(view).__name__} still falls back to the sequence protocol")

    assert len(list(memory)) == sum(len(backer) for _, backer in memory.backers())


if __name__ == "__main__":
    test_clemory_views_refuse_iteration()
