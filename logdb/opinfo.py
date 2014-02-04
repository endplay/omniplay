class OpInfo(object):
    def __init__(self, group_id, pid, syscall, offset, size=1):
        self.group_id = group_id
        self.pid = pid
        self.syscall = syscall
        self.offset = offset
        self.size = size

    def __hash__(self):
        s = ''.join([str(self.group_id), str(self.pid), str(self.syscall), str(self.offset)])
        return s.__hash__()

    def __eq__(self, other):
        return self.group_id == other.group_id and \
                self.pid == other.pid and \
                self.syscall == other.syscall and \
                self.offset == other.offset

class WriteInfo(OpInfo):
    def __init__(self, group_id, pid, syscall, offset, size=1):
        OpInfo.__init__(self, group_id, pid, syscall, offset, size)

    def __str__(self):
        return "WriteInfo: group %d, pid %d, syscall %d, offset %d, size %d" % \
                (self.group_id, self.pid, self.syscall, self.offset, self.size)

class ReadInfo(OpInfo):
    def __init__(self, group_id, pid, syscall, offset, size=1):
        OpInfo.__init__(self, group_id, pid, syscall, offset, size)

    def __str__(self):
        return "ReadInfo: group %d, pid %d, syscall %d, offset %d, size %d" % \
                (self.group_id, self.pid, self.syscall, self.offset, self.size)
