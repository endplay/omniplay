CFLAGS := -Wall -Werror -g 
LDFLAGS := -Wall -Werror -g 

KERN_CONFIG := replay_headers/include/linux/replay_configs.h

all: libutil.a parseklog parseulog parsemlog launcher resume parseckpt getstats filemap # parseelog

parseklog: parseklog.c $(KERN_COFNIG)
	gcc parseklog.c -o parseklog -Wall -Werror -g

parseulog: parseulog.c
	gcc parseulog.c -o parseulog -Wall -Werror -g

parsemlog: parsemlog.c
	gcc parsemlog.c -o parsemlog -Wall -Werror -g

parseelog: parseelog.c
	gcc parseelog.c -o parseelog -Wall -Werror -g

parseckpt: parseckpt.c
	gcc parseckpt.c -o parseckpt -Wall -Werror -g

launcher: launcher.c libutil.a
	gcc launcher.c -o launcher libutil.a -Wall -Werror --static -g -I../../eglibc-2.15/prefix/include -L../../eglibc-2.15/prefix/lib

resume: resume.o libutil.a
	gcc resume.c -o resume libutil.a -Wall -Werror --static -g

getstats: getstats.c libutil.a
	gcc getstats.c -o getstats libutil.a -Wall -Werror --static -g

filemap: filemap.c libutil.a
	gcc filemap.c -o filemap libutil.a -Wall -Werror --static -g

libutil.a: util.o
	ar rv libutil.a util.o
	ranlib libutil.a

clean:
	rm *.a *.o
