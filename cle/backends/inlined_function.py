from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(eq=False)
class InlinedFunction:
    """
    A representation of a piece of a function which is inlined from another function.
    """

    dwoffset: int
    name: str | None = None
    ranges: list[tuple[int, int]] = field(default_factory=list)
    extern: bool = False
    entry: int | None = None
    nargs: int | None = None

    @property
    def low_pc(self):
        return min(x for x, _ in self.ranges)

    @property
    def high_pc(self):
        return max(x for _, x in self.ranges)

    def rebase(self, delta: int):
        self.ranges = [(lo + delta, hi + delta) for lo, hi in self.ranges]
