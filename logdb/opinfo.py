import copy
import collections
from operator import attrgetter

class OpInfo(object):
    def __init__(self, group_id, pid, syscall, offset, size=1, channel=""):
        self.group_id = group_id
        self.pid = pid
        self.syscall = syscall
        self.offset = offset
        self.size = size
        self.channel = channel

    def __hash__(self):
        s = ''.join([str(self.group_id), str(self.pid), str(self.syscall), str(self.offset), str(self.channel)])
        return s.__hash__()

    def __eq__(self, other):
        return self.group_id == other.group_id and \
                self.pid == other.pid and \
                self.syscall == other.syscall and \
                self.offset == other.offset and \
                self.channel == other.channel

class WriteInfo(OpInfo):
    def __init__(self, group_id, pid, syscall, offset, size=1, channel=""):
        OpInfo.__init__(self, group_id, pid, syscall, offset, size, channel)

    def __str__(self):
        return "WriteInfo: group %d, pid %d, syscall %d, offset %d, size %d" % \
                (self.group_id, self.pid, self.syscall, self.offset, self.size)

class ReadInfo(OpInfo):
    def __init__(self, group_id, pid, syscall, offset, size=1, channel=""):
        OpInfo.__init__(self, group_id, pid, syscall, offset, size, channel)

    def __str__(self):
        return "ReadInfo: group %d, pid %d, syscall %d, offset %d, size %d" % \
                (self.group_id, self.pid, self.syscall, self.offset, self.size)

class ExecInfo(OpInfo):
    def __init__(self, group_id, pid, syscall, offset, size=1, channel=""):
        OpInfo.__init__(self, group_id, pid, syscall, offset, size, channel)

    def __str__(self):
        return "ExecInfo: group %d, pid %d, syscall %d, offset %d, size %d" % \
                (self.group_id, self.pid, self.syscall, self.offset, self.size)

def group_infos(infos):
    '''
    Given a list of infos, returns a list of new infos grouped together by offset range
    '''
    groups = []

    # sort by group, pid, syscall, offset
    sorted_infos = sorted(infos, key=attrgetter('group_id', 'pid', 'syscall', 'offset'))

    # group all infos with the same group_id, pid, syscall
    map_groups = collections.defaultdict(list)
    for info in sorted_infos:
        t = (info.group_id, info.pid, info.syscall)
        print("sorted info: %s" % str(info))
        map_groups[t].append(info)

    collasped_groups = collections.defaultdict(list)
    for ((group_id, pid, syscall), infos) in map_groups.iteritems():
        # go through infos and collaspe offsets
        prev_info = None
        for info in infos:
            if prev_info is None:
                prev_info = info
                collasped_groups[(group_id, pid, syscall)].append(prev_info)
            else:
                if (prev_info.offset + prev_info.size) == info.offset:
                    prev_info.size += 1
                else:
                    prev_info = info
                    collasped_groups[(group_id, pid, syscall)].append(prev_info)

    for (_, infos) in collasped_groups.iteritems():
        for info in infos:
            groups.append(info)
    return groups

def remove_dups(infos):
    '''
    Remove duplicate infos.
    NOTE: equality does not account for the size of the info
    '''
    return list(set(infos))

def subset(small_info, big_info):
    if not (small_info.group_id == big_info.group_id and 
            small_info.pid == big_info.pid and
            small_info.syscall == big_info.syscall):
        return False

    return small_info.offset >= big_info.offset and \
            (small_info.offset + small_info.size) < (big_info.offset + big_info.size)

def compare_lists(list1, list2):
    '''
    Checks to see if both lists of opinfos are equal
    '''
    list1 = sorted(list1, key=attrgetter('group_id', 'pid', 'syscall', 'offset'))
    list2 = sorted(list2, key=attrgetter('group_id', 'pid', 'syscall', 'offset'))

    if len(list1) != len(list2):
        return False

    for (el1, el2) in zip(list1, list2):
        if el1.__class__ != el2.__class__:
            return False
        if el1 != el2:
            return False

    return True

def sort_list(l):
    return sorted(l, key=attrgetter('group_id', 'pid', 'syscall', 'offset'))

