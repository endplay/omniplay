class Byte(object):
    def __init__(self, group_id, pid, syscall, offset, meta={}, value=0):
        '''
        A byte is uniquely identified by a
        replay group, pid, syscall, and an offset in the syscall
        '''
        self.group_id = group_id
        self.pid = pid
        self.syscall = syscall
        self.offset = offset
        # meta information describing the byte that's not used for comparison
        self.meta = meta
        self.value = value

    def __eq__(self, other):
        return (self.group_id, self.pid, self.syscall, self.offset) == \
                (other.group_id, other.pid, other.syscall, other.offset)

    def __hash__(self):
        return hash((self.group_id, self.pid, self.syscall, self.offset))

    def __str__(self):
        s = ''.join(["(", str(self.group_id), ",", str(self.pid),
                        ",", str(self.syscall),
                        ",", str(self.offset), ")"])
        if self.meta:
            s += str(self.meta)
        return s

    def is_next(self, other):
        '''
        Returns True if other is the next sequential byte
        '''
        if self.group_id != other.group_id or self.pid != other.pid:
            return False
        if self.syscall == other.syscall:
            return self.offset + 1 == other.offset
        elif self.syscall + 1 == other.syscall:
            return other.offset == 0
        return False
