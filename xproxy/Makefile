CXX      = g++
CXXFLAGS = -g -O2 -DLZO2 -DHAVE_CONFIG_H
LDFLAGS  = 
LIBS     =  -llzo2  -lpthread
EXEEXT   = 
MINGW32  = false

srcdir      = .
prefix      = /usr/local
exec_prefix = ${prefix}
bindir      = ${exec_prefix}/bin
man1dir     = ${prefix}/man/man1


INSTALL         = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA    = ${INSTALL} -m 644

.SUFFIXES:	.C

# We may have separate source and binary trees -- make sure we can find
# dxpcconf.h
CPPFLAGS = -I.

.C.o:
	$(CXX) $(CPPFLAGS) -c $(CXXFLAGS) $<

TARGET=	xproxy$(EXEEXT)

# The mingw build results in two targets, the console mode and windows mode
# app.
ifeq ($(MINGW32),true)
SECONDTARGET = dxpc-win32$(EXEEXT)
else
SECONDTARGET =
endif

all: $(TARGET) $(SECONDTARGET)

pure: pure_$(TARGET)
quantify: quant_$(TARGET)

SRCS=	util.H main.C util.C constants.C Stats.C \
	Multiplexer.C ClientMultiplexer.C ServerMultiplexer.C \
	ClientChannel.C ServerChannel.C ReadBuffer.C \
	ProxyReadBuffer.C ClientReadBuffer.C ServerReadBuffer.C \
	EncodeBuffer.C DecodeBuffer.C WriteBuffer.C \
	IntCache.C CharCache.C PixelCache.C HuffmanCoder.C \
	ClientCache.C ServerCache.C \
	TextCompressor.C LastPixels.C SequenceNumQueue.C \
	BlockCache.C BlockCacheSet.C Compresser.C Decompresser.C ResourceID.C EventQueue.C

OBJS=	$(SRCS:.C=.o)

$(TARGET):	$(OBJS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

ifeq ($(MINGW32),true)
$(SECONDTARGET): $(OBJS)
	$(CXX) -mwindows $(CPPFLAGS) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)
endif

pure_$(TARGET):	$(OBJS)
	purify $(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

quant_$(TARGET):	$(OBJS) $(OBJS)
	quantify $(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

depends:
	makedepend -f Makefile $(SRCS)

install: install.bin install.man

install.bin:	$(TARGET)
	$(srcdir)/mkinstalldirs $(bindir)
	$(INSTALL) $(TARGET) $(bindir)/$(TARGET)

install.man:
	$(srcdir)/mkinstalldirs $(man1dir)
	$(INSTALL_DATA) $(TARGET).man $(man1dir)/$(TARGET).1

clean:
	-rm -f *~ *.o $(TARGET) pure_* quant_* *.bak core gmon.out

distclean: clean
	-rm -f config.status config.log config.cache Makefile tags dxpcconf.h
	-rm -rf autom4te.cache

# gnu indent v2.2.9 has a nasty bug whereby a const method ends up with a
# "const const" modifier.
indent:
	indent -bad -bap -bl -bli0 -cdw -i4 -npcs -npsl -nut -ppi1 *.C *.H
	for f in *.C *.H; do sed "s/const const/const/" $$f >$$f.fixed.$$$$ && cp $$f.fixed.$$$$ $$f; done
	rm -f *.fixed.$$$$

