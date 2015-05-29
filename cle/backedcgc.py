from .absobj import Segment
from .cgc import CGC

class FakeSegment(Segment):
    def __init__(self, start, size):
        super(FakeSegment, self).__init__(0, start, 0, size)
        self.is_readable = True
        self.is_writable = True
        self.is_executable = False

class BackedCGC(CGC):
    def __init__(self, path, memory_backer=None, register_backer=None, writes_backer=None, *args, **kwargs):
        """
        This is a backend for CGC executables that allows user provide a memory backer and a register backer as the
        initial state of the running binary.

        :param path: File path to CGC executable
        :param memory_backer: A dict of memory content, with beginning address of each segment as key and actual memory
                            content as data
        :param register_backer: A dict of all register contents. EIP will be used as the entry point of this executable
        """
        super(BackedCGC, self).__init__(path, *args, **kwargs)

        self.memory_backer = memory_backer
        self.register_backer = register_backer
        self.writes_backer = writes_backer

        exec_seg_addr = None
        for seg in self.segments:
            if seg.is_executable:
                exec_seg_addr = seg.vaddr
                break
        else:
            raise ValueError("Couldn't find executable segment?")

        for start, _ in self.memory._backers:
            if start != exec_seg_addr:
                self.memory.remove_backer(start)

        for start, data in sorted(self.memory_backer.items()):
            existing_seg = self.find_segment_containing(start)
            if existing_seg is None:    # this is the text or data segment
                new_seg = FakeSegment(start, len(data))
                self.segments.append(new_seg)

            if start == exec_seg_addr:
                continue

            if start in self.memory:
                raise ValueError("IF THIS GETS THROWN I'M GONNA JUMP OUT THE WINDOW")

            self.memory.add_backer(start, data)

        if self.register_backer is not None and 'eip' in self.register_backer:
            self._entry = self.register_backer['eip']

    def initial_register_values(self):
        return self.register_backer.iteritems()
