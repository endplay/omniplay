import gdb
import pydoc
import sys

#class SyscallBreakpoint(gdb.Breakpoint):
#	def __init__(self, syscall, spec=None):
#		if spec == None:
#			spec = syscall
#		self.syscall = syscall
#		
#		#Call the base constructor
#		super(SyscallBreakpoint, self).__init__(spec)
#
#	def stop(self):
#		print "py: Hit syscall", self.syscall
#		return False

def exitHandler(event):
	pid = event.inferior.pid
	print "py: Goodbye! Pid %d exited" % pid

def grabParameterRegs():
	eax = gdb.parse_and_eval("$eax")
	ebx = gdb.parse_and_eval("$ebx")
	ecx = gdb.parse_and_eval("$ecx")
	edx = gdb.parse_and_eval("$edx")
	esi = gdb.parse_and_eval("$esi")
	edi = gdb.parse_and_eval("$edi")
	ebp = gdb.parse_and_eval("$ebp")
	return eax, ebx, ecx, edx, esi, edi, ebp

def printRegs(regs):
	first = True
	for val in regs:
		if first:
			first = False
		else:
			print ", ",
		print val,

	print ''

class PreLoadHandler:
	def __init__(self):
		self.syscallReturn = False
		self.sawVsyscall = False
		self.needsLoad = False

	def switchOver(self):
		return self.needsLoad

	def handleCatchpoint(self, pid):
		regs = grabParameterRegs()

		if self.syscallReturn:
			self.syscallReturn = False

			returnVal = regs[0]
			print "\tReturned:", returnVal
			return

		self.syscallReturn = True

		#If the breakpoint has it, don't spew stuff
		if self.sawVsyscall:
			self.sawVsyscall = False
		else:
			print "Pid", pid, "Syscall Number", regs[0], "(could not determine)"

	def handleBreakpoint(self, pid, breakpoint):
		if breakpoint.location == "__libc_start_main":
			print "---- Detected libc available ----"
			self.needsLoad = True
			return

		self.sawVsyscall = True

		regs = grabParameterRegs()
		print "Pid", pid, "Syscall Number", regs[0]

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
		self.specialReturn = -1
		self.cstr = gdb.lookup_type("char").pointer()
		self.voidptr = gdb.lookup_type("void").pointer()

		gdb.Breakpoint("__kernel_vsyscall")

	def determinePrintArgs(self, regs):
		watchedCalls = [ 3, 4, 90, 145, 146, 180, 181, 192, 333, 334 ]

		sysnum = regs[0]		

		if not sysnum in watchedCalls:
			return

		if sysnum == 3 or sysnum == 4: #read or write
			name = "read" if sysnum == 3 else "write"
			out = "\t%s ( fd = %s, buf = %s, count = %s )"
			bufptr = regs[2].cast(self.cstr)
			print out % ( name, str(regs[1]), str(bufptr), str(regs[3]) )

			if sysnum == 4: #write only
				print "\tFull data ***:"
				self.printMem(bufptr, int(regs[3]))
				print "\t***"
			else:
				self.specialReturn = sysnum
		elif sysnum == 90 or sysnum == 192: #mmap
			out = "\tmmap ( addr = %s, length = %i, prot = %i, flags = %i, fd = %i, offset = %i )"
			addr = regs[1].cast(self.voidptr)
			inttype = gdb.lookup_type("int")
			offset = int(regs[6].cast(inttype))
			print out % ( addr, int(regs[2]), int(regs[3]), int(regs[4]), int(regs[5]), offset )
				
			
	def determinePrintReturn(self, regs):
		if self.specialReturn == -1:
			print "\tReturned", regs[0]
			return	

		if self.specialReturn == 3:
			bufptr = regs[2].cast(self.cstr)
			print "\tFull data ***:"
			self.printMem(bufptr, int(regs[3]))
			print "\t***"

			print "\tReturned", regs[0]

		self.specialReturn = -1

	def printMem(self, buf, length):
		sval = buf.string('utf-8', 'backslashreplace', length)
		print sval


	def handle(self, event):
		regs = grabParameterRegs()
		pid = gdb.selected_inferior().pid

		if self.beginOfCall:
			print "Pid", pid, "Syscall Number", regs[0]
			self.determinePrintArgs(regs)
		else:
			self.determinePrintReturn(regs)
		self.beginOfCall = not self.beginOfCall		

	def onActualStop(self):
		if not self.beginOfCall:
			gdb.execute("finish")
		else:
			gdb.execute("continue")


		return False

handler = None

def stopHandler(event):
	global handler
	handler.handle(event)	

def main():
	#pydoc.writedoc("gdb.events")
	#return

	#redirect all print output!
	outfile = open("io_out2.txt", 'w')
	sys.stdout = outfile

	global handler
	handler = PreLoadHandler()

	#First things: need to load the eglibc, which for some reason
	#	gdb does not do by default
	#gdb.execute("break main")
	#gdb.execute("continue")
	#gdb.execute("sharedlibrary") #load it up!
	#gdb.execute("delete 1")

	gdb.events.exited.connect(exitHandler)
	gdb.events.stop.connect(stopHandler)

	#Running with -batch takes care of this!
	#gdb.execute("set pagination off")
	#gdb.execute("set confirm off")

	#This line is a performance booster potentially -> makes it so it doesn't
	#	remove and reinsert breakpoints everytime it stops
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

	SyscallBreakpoint("fork")
	SyscallBreakpoint("sleep")
	SyscallBreakpoint("write")
	SyscallBreakpoint("read")

	gdb.execute("continue")
	gdb.execute("quit")

main()
