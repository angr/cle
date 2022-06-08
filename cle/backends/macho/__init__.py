from .macho import MachO

# Some type aliases
FilePointer = int    # Offset into a raw binary file
FileOffset = int     # Offset to another FilePointer
MemoryPointer = int  # Offset into the mapped memory space
