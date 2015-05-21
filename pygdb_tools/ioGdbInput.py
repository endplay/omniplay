import gdb
import sys
import os
import omniplay.gdbscripts
import ctypes

counter = 1
def exitHandler(event):
    pid = event.inferior.pid
    print "Goodbye! Pid %d exited" % pid

def grabParameterRegs():
    eax = gdb.parse_and_eval("$eax")
    ebx = gdb.parse_and_eval("$ebx")
    ecx = gdb.parse_and_eval("$ecx")
    edx = gdb.parse_and_eval("$edx")
    esi = gdb.parse_and_eval("$esi")
    edi = gdb.parse_and_eval("$edi")
    ebp = gdb.parse_and_eval("$ebp")
    return eax, ebx, ecx, edx, esi, edi, ebp

def getIovecPtr():
    iovecType = gdb.lookup_type("struct iovec").pointer()
    return iovecType

def getRecordPid(pid):
    if not pid in getRecordPid.pids:
        global utils
        newpid = utils.get_current_record_pid(pid)
        getRecordPid.pids[pid] = newpid
    return getRecordPid.pids[pid]
getRecordPid.pids = {}

def getPC():
    pc = gdb.parse_and_eval("$pc")
    pcint = pc.cast(gdbTypes.inttype)
    uint = ctypes.c_uint(int(pcint))
    return uint.value

class PreLoadHandler:
    def __init__(self):
        self.syscallReturn = False
        self.sawVsyscall = False
        self.needsLoad = False
        self.currentSyscall = -1
        self.basePC = getPC()
        print "PC is", self.basePC
        print "\t", format(self.basePC, '#x')

        #This maps address offsets to the correct system calls when in ld!
        self.offsetMap = {
            84164 : 45,
            91795 : 192,
            91617 : 33,
            91300 : 5,
            91117 : 195,
            91428 : 3,
            91181 : 197,
            91357 : 6,
            -1011 : 243,
            91924 : 125
        }

    def switchOver(self):
        return self.needsLoad

    def handleCatchpoint(self, pid):
        regs = grabParameterRegs()

        if self.syscallReturn:
            self.syscallReturn = False
            syscallExit(self.currentSyscall, regs, pid)
            return

        self.syscallReturn = True

        #If the breakpoint handled it, don't do anything
        if self.sawVsyscall:
            self.sawVsyscall = False
        else:
            pc = getPC()
            offset = pc - self.basePC

            if offset in self.offsetMap:
                syscall = self.offsetMap[offset]
            else:
                syscall = -1

            self.currentSyscall = syscall
            syscallEnter(syscall, regs, pid)

            if syscall == -1:
                print "\tPC:", format(pc, '#x')
                print "\tOffset:", offset

    def handleBreakpoint(self, pid, breakpoint):
        if breakpoint.location == "__libc_start_main":
            print "---- Detected libc available ----"
            self.needsLoad = True
            return

        self.sawVsyscall = True

        regs = grabParameterRegs()
        syscall = int(regs[0])
        self.currentSyscall = syscall
        syscallEnter(syscall, regs, pid)
        return

    def handle(self, event):
        pid = gdb.selected_inferior().pid

        isBreakpoint = isinstance(event, gdb.BreakpointEvent)

        if isBreakpoint:
            breakpoint = event.breakpoints[0]
            self.handleBreakpoint(pid, breakpoint)
        else:
            self.handleCatchpoint(pid)

    def onActualStop(self):
        if self.switchOver():
            print "---- Reading libc symbols ----"
            gdb.execute("sharedlibrary libc.so")
            gdb.execute("delete")

            global handler
            handler = PostLoadHandler()

            gdb.execute("continue")
            return

        gdb.execute("continue")
        return False

class PostLoadHandler:
    def __init__(self):
        self.count = 0
        self.beginOfCall = True
        self.currentSyscall = -1
        self.cstr = gdb.lookup_type("char").pointer()
        self.voidptr = gdb.lookup_type("void").pointer()
        self.recordPid = None

        gdb.Breakpoint("__kernel_vsyscall")

    def handle(self, event):
        regs = grabParameterRegs()
        pid = gdb.selected_inferior().pid

        if self.beginOfCall:
            syscall = int(regs[0])
            self.currentSyscall = syscall

            syscallEnter(syscall, regs, pid)
        else:
            syscallExit(self.currentSyscall, regs, pid)
            self.currentSyscall = -1

        self.beginOfCall = not self.beginOfCall

    def onActualStop(self):
        if not self.beginOfCall:
            gdb.execute("finish")
        else:
            gdb.execute("continue")

        return False

def syscallEnter(syscall, regs, pid):
    global counter
    recordpid = getRecordPid(pid)

    if syscall == -1:
        outstr = "%i Pid %i (record pid %i), could not determine syscall number"
        print outstr % ( counter, pid, recordpid )
        counter += 1
        return
    else:
        outstr = "%i Pid %i (record pid %i), Syscall Number %i"
        print outstr % ( counter, pid, recordpid, syscall )

        notrecorded = [ 243, 233 ]
        if syscall in notrecorded:
            return

        printArgs(syscall, regs)
        printSyscallEnterData(syscall, regs, recordpid)

def syscallExit(syscall, regs, pid):
    if syscall == -1:
        return

    notrecorded = [ 243, 244 ]
    if syscall in notrecorded:
        return

    recordpid = getRecordPid(pid)
    printSyscallExitData(syscall, regs, recordpid)
    printReturnValue(syscall, regs)

    global counter
    counter += 1

def printArgs(sysnum, regs):
    watchedCalls = [ 3, 4, 90, 145, 146, 180, 181, 192, 333, 334 ]

    if not sysnum in watchedCalls:
        return

    outputs = {
        3   :   "read ( fd = %i, buf = %s, count = %i )",
        4   :   "write ( fd = %i, buf = %s, count = %i )",
        90  :   "mmap ( addr = %s, length = %i, prot = %i, flags = %i, fd = %i, offset = %i )",
        145 :   "readv ( fd = %i, iovec = %s, iovcnt = %i )",
        146 :   "writev ( fd = %i, iovec = %s, iovcnt = %i )",
        180 :   "pread ( fd = %i, buf = %s, count = %i, offset = %i )",
        181 :   "pwrite ( fd = %i, buf = %s, count = %i, offset = %i )",
        192 :   "mmap2 ( addr = %s, length = %i, prot = %i, flags = %i, fd = %i, offset = %i )",
        333 :   "preadv ( fd = %i, iovec = %s, iovcnt = %i, offset = %i )",
        334 :   "pwritev ( fd = %i, iovec = %s, iovcnt = %i, offset = %i )"
    }

    #calls that look like "fd, address, count"
    if sysnum == 3 or sysnum == 4 or sysnum == 145 or sysnum == 146:
        buf = regs[2].cast(gdbTypes.voidptr)
        formats = ( int(regs[1]), str(buf), int(regs[3]) )
    #the mmaps
    elif sysnum == 90 or sysnum == 192:
        addr = regs[1].cast(gdbTypes.voidptr)
        offset = regs[6].cast(gdbTypes.inttype)
        formats = ( str(addr), int(regs[2]), int(regs[3]), int(regs[4]), int(regs[5]), int(offset) )
    else:
        buf = regs[2].cast(gdbTypes.voidptr)
        formats = ( int(regs[1]), str(buf), int(regs[3]), int(regs[4]) )

    outstr = outputs[sysnum] % formats
    print "\t" + outstr

def printSyscallEnterData(syscall, regs, pid):
    watchedCalls = [ 4, 146, 181, 334 ]

    if syscall not in watchedCalls:
        return

    printer = Printer()

    try:
        if syscall == 4 or syscall == 181:
            buf = regs[2].cast(gdbTypes.cstr)
            count = int(regs[3])
            printer.printWrite(pid, buf, count)
        else:
            iovec = regs[2].cast(getIovecPtr())
            count = int(regs[3])
            printer.printWriteIovec(pid, iovec, count)
    except gdb.MemoryError:
        print "\t<invalid memory address>"

def printSyscallExitData(syscall, regs, pid):
    watchedCalls = [ 3, 90, 145, 180, 192, 333 ]

    if syscall not in watchedCalls:
        return

    printer = Printer()
    retval = int(regs[0])

    if retval == -1:
        return

    try:
        if syscall == 3 or syscall == 180:
            buf = regs[2].cast(gdbTypes.cstr)
            printer.printRead(pid, buf, retval)
        elif syscall == 90 or syscall == 192:
            fd = int(regs[5])
            if fd == -1:
                return

            buf = regs[0].cast(gdbTypes.cstr)
            length = int(regs[2])
            printer.printRead(pid, buf, length)
        else:
            iovec = regs[2].cast(getIovecPtr())
            count = int(regs[3])
            printer.printReadIovec(pid, iovec, count, retval)
    except gdb.MemoryError:
        print "\t<invalid memory address>"

def printReturnValue(syscall, regs):
    watchedCalls = [ 3, 4, 90, 145, 146, 180, 181, 192, 333, 334 ]

    if syscall not in watchedCalls:
        return

    returnVal = regs[0]

    #mmap returns a pointer
    if syscall == 90 or syscall == 192:
        intval = returnVal.cast(gdbTypes.inttype)
        if intval == -1:
            val = -1
        else:
            val = returnVal.cast(gdbTypes.voidptr)
        print "\tReturned: %s" % str(val)
    else:
        print "\tReturned: %i" % int(returnVal)

class Printer():
    def init(self, group):
        Printer.group = group
        Printer.root = "/tmp/io_%i" % group
        Printer.reads = '/'.join([Printer.root, "reads"])
        Printer.writes = '/'.join([Printer.root, "writes"])

    def setup_files(self):
        if not os.path.isdir(Printer.root):
            os.mkdir(Printer.root)
        if not os.path.isdir(Printer.reads):
            os.mkdir(Printer.reads)
        if not os.path.isdir(Printer.writes):
            os.mkdir(Printer.writes)

    def printRead(self, pid, buf, length):
        self._doRead(pid, Printer._printMemRaw, buf, length)

    def printWrite(self, pid, buf, length):
        self._doWrite(pid, Printer._printMemRaw, buf, length)

    def printReadIovec(self, pid, iovec, count, length):
        self._doRead(pid, Printer._printIovecRaw, iovec, count, length)

    def printWriteIovec(self, pid, iovec, count):
        self._doWrite(pid, Printer._printIovecRaw, iovec, count, None)

    def _doRead(self, pid, func, *args):
        outfile = self._getFile(True, pid)
        func(self, outfile, *args, newLine=False)
        print "\tCreated out file", outfile.name
        outfile.close()

    def _doWrite(self, pid, func, *args):
        outfile = self._getFile(False, pid)

        print "\tData ***"
        func(self, sys.stdout, *args, newLine=True)
        print "\t***"

        func(self, outfile, *args, newLine=False)
        print "\tCreated out file", outfile.name
        outfile.close()

    def _getFile(self, isRead, pid):
        folder = Printer.reads if isRead else Printer.writes
        global counter
        filename = "%s/%i_%i_%i" % ( folder, Printer.group, pid, counter )
        outfile = open(filename, 'w')
        return outfile

    def _printMemRaw(self, ostream, buf, length, newLine=True):
        try:
            sval = buf.string('ascii', 'ignore', length)
        except UnicodeError:
            sval = "<***contained unprintable characters***>"

        if newLine:
            print >>ostream, sval
        else:
            print >>ostream, sval,

    def _printIovecRaw(self, ostream, iovecArr, count, length, newLine=False):
        vecarr = [ iovecArr[i]  for i in xrange(count) ]

        if length == None:
            length = sum([ int(vec['iov_len'])  for vec in vecarr ])

        for vec in vecarr:
            buf = vec['iov_base'].cast(gdbTypes.cstr)
            vlength = int(vec['iov_len'])
            if vlength > length:
                vlength = length
            length -= vlength

            self._printMemRaw(ostream, buf, vlength, newLine=False)

        if newLine:
            print >>ostream, ''

#This is pretty hacky but oh well
class gdbTypes:
    cstr = gdb.lookup_type("char").pointer()
    voidptr = gdb.lookup_type("void").pointer()
    inttype = gdb.lookup_type("int")

handler = None
utils = None

def stopHandler(event):
    global handler
    handler.handle(event)

def main():
    global utils
    utils = omniplay.gdbscripts.ScriptUtilities()
    group = utils.get_replay_group()

    printer = Printer()
    printer.init(group)
    printer.setup_files()

    print "Replay Group is", group

    global handler
    handler = PreLoadHandler()

    gdb.events.exited.connect(exitHandler)
    gdb.events.stop.connect(stopHandler)

    #This line is a performance booster potentially -> makes it so it doesn't
    #   remove and reinsert breakpoints everytime it stops
    #gdb.execute("set breakpoint always-inserted on")


    #Temp
    gdb.execute("catch syscall")
    gdb.execute("break __kernel_vsyscall")
    gdb.execute("break __libc_start_main")

    while True:
        try:
            if handler.onActualStop():
                break
        except gdb.error:
            break

    return

main()
