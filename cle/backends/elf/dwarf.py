
class FDE:
    """
    Frame description entry
    """

    __slots__ = ('length', 'pc_begin', 'pc_range',)

    def __init__(self, length, pc_begin, pc_range):
        self.length = length
        self.pc_begin = pc_begin
        self.pc_range = pc_range
