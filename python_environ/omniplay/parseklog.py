"""
Module for advanced klog parsing and modification
"""
import parseklograw
import omniplay

class ParseklogEntry(object):
    """
    An entry in the klog
    """

    def __init__(self, log, raw, chunk):
        self.raw = raw
        self.log = log
        self.chunk = chunk

    def __str__(self):
        return str(self.raw)

    #@property
    #def flags(self):
    #    """
    #    Gets the psr flags of the entry
    #    """
    #    return self.raw.flags

    #@flags.setter
    #def flags(self, value):
    #    """
    #    Updates the psr flags of the entry
    #    Also notifies the chunk its dirty
    #    """
    #    self.chunk.dirty = True
    #    self.raw.flags = value

    @property
    def sysnum(self):
        """
        The system call number of the log entry
        """
        return self.raw.sysnum

    @sysnum.setter
    def sysnum(self, value):
        """
        Setter for the system call number of hte log entry
        """
        self.chunk.dirty = True
        self.raw.sysnum = value

    #@property
    #def index(self):
    #    """
    #    The index (system call within the klog) of the entry
    #    """
    #    return self.raw.index

    #@index.setter
    #def index(self, value):
    #    """
    #    The setter for the index (system call within the klog) of the entry
    #    """
    #    self.chunk.dirty = True
    #    self.raw.index = value

    @property
    def retparams(self):
        """
        The return parameters (if any) of the system call
        """
        return self.raw.retparams

    @retparams.setter
    def retparams(self, value):
        """
        The setter for the return parameters (if any) of the system call
        """
        self.chunk.dirty = True
        self.raw.retparams = value

        if self.raw.retparams is None:
            self.raw.flags &= ~parseklograw.SR_HAS_RETPARAMS
        else:
            self.raw.flags |= ~parseklograw.SR_HAS_RETPARAMS

    @property
    def start_clock(self):
        """
        The logical start clock of the entry
        """
        return self.raw.start_clock

    @start_clock.setter
    def start_clock(self, value):
        """
        The setter for the start clock of the entry
        """
        #self.chunk.dirty = True
        #self.raw.start_clock = value
        raise SyntaxError

    @property
    def stop_clock(self):
        """
        The logical stop clock of the entry
        """
        return self.raw.stop_clock

    @stop_clock.setter
    def stop_clock(self, value):
        """
        The setter for the logical stop clock of the entry
        """
        #self.chunk.dirty = True
        #self.raw.stop_clock = value
        raise SyntaxError

    @property
    def retval(self):
        """
        The return value of the system call
        """
        return self.raw.retval

    @retval.setter
    def retval(self, value):
        """
        The setter for the return value of the system call
        """
        self.chunk.dirty = True
        self.raw.retval = value

        if self.raw.retval != 0:
            self.raw.flags |= parseklograw.SR_HAS_NONZERO_RETVAL
        else:
            self.raw.flags &= ~parseklograw.SR_HAS_NONZERO_RETVAL

    @property
    def signal(self):
        """
        The signal (if any) delivered at this system call
        """
        return self.raw.signal

    @signal.setter
    def signal(self, value):
        """
        The setter for the signal (if any) delivered at this system call
        NOTE: Not allowed to change signals!
        """
        raise SyntaxError


class Parseklog(object):
    """
    Class representing a kernel log.  The kernel log is a list of
    non-deterministic system calls run by an execution.  The Parseklog
    object may be iterated to get all of the log entries (system calls) within
    it.
    """
    class _Chunk(object):
        """
        INTERNAL CLASS

        A chunk of entries in the klog (klogs are organized into groups of system calls,
        with a header, each group is refered to as a chunk)
        """
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

        def create_and_insert(self, log, index):
            """
            Used to create a new empty parseklogentry assosciated with an index in a chunk
            """
            entry = ParseklogEntry(log, None, self)
            entry.raw = parseklograw.ParseklogEntryRaw(log.raw)

            entry.raw.index = index

            # Now I need to insert it into chunk, and inc the indicies of all entries after it in the chunk
            self.entries.insert(index, entry)
            for ent in self.entries[index+1:]:
                ent.raw.index += 1

            return entry

        def raw_entries(self):
            """
            Just returns a list of all of the raw entries in entries
            """
            return [e.raw for e in self.entries]

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
        """
        Gets the next ParseklogEntry from the klog

        @return The next ParseklogEntry in this Parseklog
        """
        if self.chunk_offs == self.cur_chunk.size:
            self.chunk_offs = 0
            self.cur_chunk = self.chunk_itr.next()
            self.entry_itr = self.cur_chunk.entries.__iter__()

        self.chunk_offs += 1
        return self.entry_itr.next()

    def get(self, idx):
        """
        Gets the specified parseklog entry from the klog

        @param idx 
        @return the ParseklogEntry at idx
        """
        # Iterate through the chunks until you get past the number we're looking for
        cur_chunk = None
        chunk_idx = 0
        for chunk in self.chunks:
            chunk_idx += chunk.size
            cur_chunk = chunk
            if chunk_idx > idx:
                break

        if cur_chunk is None:
            return None
        if chunk_idx <= idx:
            return None

        chunk_idx -= cur_chunk.size

        # Now, get the element from the chunk
        return cur_chunk.entries[idx - chunk_idx]

    def insert(self, idx):
        """
        Inserts a given entry into the Parseklog at index idx

        @note The on-disk klog will not be modified, only the in-memory
            version, and any version written to disk by it
            (using the write() call) will be modified
        @idx The index to insert thte entry at
        @return The newly created entry
        """
        # Find the chunk of idx
        chunk = self.get(idx).chunk

        # Make a new entry at idx
        entry = chunk.create_and_insert(self, idx)

        # Now increment all of the indexes in future chunks
        cnk_idx = self.chunks.index(chunk) + 1
        for cnk in self.chunks[cnk_idx:]:
            for ent in cnk.entries:
                ent.index += 1

        return entry

    def write(self, fil):
        """
        Writes out the (potentially modified) log to fd

        @param fd A file descriptor to the location to write this Parseklog to
        """

        for cnk in self.chunks:
            fileno = int(fil.fileno())
            raw_entries = cnk.raw_entries()
            self.raw.do_write(raw_entries, fileno)

