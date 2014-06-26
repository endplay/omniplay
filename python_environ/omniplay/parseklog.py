"""
Module for advanced klog parsing and modification
"""
import parseklograw
import omniplay

class ParseklogEntry(object):
    """
    An entry in the klog
    """
    @staticmethod
    def create_new(log, index, raw, chunk):
        """
        UNIMPLEMENTED
        """
        return log + index + raw + chunk

    def __init__(self, log, raw, chunk):
        self.raw = raw
        self.log = log
        self.chunk = chunk

    def __str__(self):
        return str(self.raw)

    @property
    def flags(self):
        """
        Gets the psr flags of the entry
        """
        return self.raw.flags

    @flags.setter
    def flags(self, value):
        """
        Updates the psr flags of the entry
        Also notifies the chunk its dirty
        """
        self.chunk.dirty = True
        self.raw.flags = value

    @property
    def sysnum(self):
        return self.raw.sysnum

    @sysnum.setter
    def sysnum(self, value):
        self.chunk.dirty = True
        self.raw.sysnum = value


class Parseklog(object):
    class _Chunk(object):
        def __init__(self, raw_log, log):
            self.size = raw_log.cur_chunk_size()
            self.dirty = False
            self.entries = []

            for _ in xrange(0, self.size):
                raw = raw_log.get_next_psr()
                if raw is None:
                    raise EOFError("No records left")

                entry = ParseklogEntry(log, raw, self)

                self.entries.append(entry)

        def mark_dirty(self):
            self.dirty = True

        def is_dirty(self):
            return self.dirty

    def __init__(self, omniplay_env, log_name):
        self.log_name = log_name

        if omniplay_env is not None:
            self.omniplay = omniplay_env
        else:
            self.omniplay = omniplay.OmniplayEnvironment()

        self.raw = parseklograw.ParseklogRaw(log_name)

        self.chunk_offs = 0
        self.chunks = []
        self.cur_chunk = None
        self.chunk_itr = None
        self.entry_itr = None

        # Scan whole log for all chunks
        try:
            self.raw.read_next_chunk()
            chunk = Parseklog._Chunk(self.raw, self)
            self.chunks.append(chunk)
        except EOFError:
            pass

    def __iter__(self):
        self.chunk_itr = self.chunks.__iter__()
        self.cur_chunk = self.chunk_itr.next()
        self.entry_itr = self.cur_chunk.entries.__iter__()
        return self

    def next(self):
        if self.chunk_offs == self.cur_chunk.size:
            self.chunk_offs = 0
            self.cur_chunk = self.chunk_itr.next()
            self.entry_itr = self.cur_chunk.entries.__iter__()

        self.chunk_offs += 1
        return self.entry_itr.next()

    def get(self, idx):
        # FIXME: return entry @ idx
        return self

    def insert(self, entry, idx):
        # FIXME: create new entry at idx
        return self

    def write(self, fd):
        return fd
        
