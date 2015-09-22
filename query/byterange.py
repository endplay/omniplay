import collections

# our modules
import byte
import operator

class ByteRange(object):
    def __init__(self, group_id, pid, syscall, offset, size, meta={}):
        self.group_id = group_id
        self.pid = pid
        self.syscall = syscall
        self.offset = offset
        self.size = size
        # meta information not used for comparison
        self.meta = meta

    def contains(self, byte):
        if self.group_id != byte.group_id or \
                self.pid != byte.pid or \
                self.syscall != byte.syscall:
            return False
        if byte.offset >= self.offset and \
                byte.offset < self.offset + self.size:
            return True

    def get_bytes(self):
        '''
        Returns a list of bytes that this range makes up
        '''
        b = []
        for i in range(self.offset, self.offset + self.size):
            tb = byte.Byte(self.group_id, self.pid, self.syscall, i)
            b.append(tb)
        return b

    def get_meta_attr(self, attr):
        '''
        Returns an attribute in the byterange.
        Returns None if it does not have the attribute
        '''
        if attr in self.meta:
            return self.meta[attr]
        return None

    def __str__(self):
        return str((self.group_id, self.pid, self.syscall,
            self.offset, self.size))

    def __eq__(self, other):
        return (self.group_id, self.pid, self.syscall,
                self.offset, self.size) == \
                    (other.group_id, other.pid, other.syscall,
                    other.offset, other.size)

    def __hash__(self):
        return hash((self.group_id,
            self.pid,
            self.syscall,
            self.offset,
            self.size))

def ranges_contain(byteranges, byte_value):
    for byterange in byteranges:
        if byterange.contains(byte_value):
            return True
    return False

def range_contains_range(range1, range2):
    '''
    Returns True if range2 is equal to or a subset of range1
    '''
    if (range1.group_id != range2.group_id) or \
            (range1.pid != range2.pid) or \
            (range1.syscall != range2.syscall):
        return False
    return range2.offset >= range1.offset and \
            ((range2.offset + range2.size) <= (range1.offset + range1.size))

def ranges_contains_ranges(range_group1, range_group2):
    '''
    Returns True if every range in range_group2 is a subset of a
    range in range_group1
    '''
    for range2 in range_group2:
        found = False
        for range1 in range_group1:
            if range_contains_range(range1, range2):
                found = True
                break
        if not found:
            return False
    return True

def create_byteranges_from_bytes(list_bytes, copy_meta=False):
    '''
    Given a list of bytes, make them into ranges
    '''
    list_bytes = sorted(list_bytes, key=operator.attrgetter('group_id',
                                                                'pid',
                                                                'syscall',
                                                                'offset'))
    byteranges = []
    curr_byte_range = None
    prev_byte = None
    for b in list_bytes:
        if not prev_byte:
            if copy_meta:
                meta = b.meta
            else:
                meta = {}
            curr_byte_range = ByteRange(b.group_id,
                                            b.pid,
                                            b.syscall,
                                            b.offset, 1,
                                            meta=meta)
            prev_byte = b
        else:
            if prev_byte.is_next(b):
                curr_byte_range.size += 1
            else:
                byteranges.append(curr_byte_range)
                if copy_meta:
                    meta = b.meta
                else:
                    meta = {}
                curr_byte_range = ByteRange(
                    b.group_id,
                    b.pid,
                    b.syscall,
                    b.offset, 1,
                    meta=meta)
            prev_byte = b
    # get the last byte range
    byteranges.append(curr_byte_range)
    return byteranges

def group_byteranges_by_group_id(list_byteranges):
    '''
    Given a list of byteranges, return a list of list of byteranges
    grouped by group_id
    '''
    grouping = collections.defaultdict(list)
    for br in list_byteranges:
        grouping[br.group_id].append(br)
    return grouping.values()
