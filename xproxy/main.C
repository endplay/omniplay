#include "dxpcconf.h"

#include <sys/time.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
# include <sys/wait.h>
# include <sys/socket.h>
# include <sys/resource.h>
# include <sys/utsname.h>
# include <netdb.h>
# include <netinet/in.h>
# include <pwd.h>
# include <arpa/inet.h>
# include <netinet/tcp.h>
# include <sys/un.h>

#include "X-headers.H"

#ifdef _AIX
# include <strings.h>
#endif /* _AIX */

#include "constants.H"
#include "util.H"
#include "ClientMultiplexer.H"
#include "ServerMultiplexer.H"
#include "ServerChannel.H"
#include "ClientChannel.H"

#include "Compresser.H"
#include <pthread.h>
#include <stdio.h>

#ifdef _AIX
# include <sys/select.h>
#endif /* _AIX */

#if defined(hpux) && !defined(RLIM_INFINITY)
/* HP-UX hides this define */
# define    RLIM_INFINITY   0x7fffffff
#endif

using namespace std;

// Variable to tell output routines whether they should be quiet or not
// Added for -f option
// This variable is used by other files
int silent = 0;
// Now statistics can go to a file
char logfilename[1024] = { 0 };
OSTREAM *logofs;

// Controls miniLZO PutImage compression: used by other files.
int compressImages = 0;

// whether we are in file replay mode or not
int file_replay = 0;
unsigned int convert_log = 0;

// Info about sockets used by the client proxy (global so that
// the cleanup signal handler can access it)
static char udomSocketPathname[100];
static int useUnixDomainSocket = 1;
sockaddr_in serverAddr;

// Maximum number of open file descriptors for this process
static unsigned int maxNumFDs = 0;
int thread_debug = 0;

struct thread_struct {
	int addrFamily;
	sockaddr * addr;
	unsigned int length;
	unsigned int statLevel;
	int connectFD;
};

static void Cleanup();
static void HandleSignal(int);

void *serverThread(void *args) {
	EncodeBuffer encodeBuffer;
	struct thread_struct *params = (struct thread_struct*) args;
	cout << "Get a new connection."<<endl;
	// Connect to the real X server
	int xServerFD = socket(params->addrFamily, SOCK_STREAM, PF_UNSPEC);
	int xAppFD = params->connectFD;
	int convertFD = 0;

#ifdef FILE_REPLAY
	if (file_replay) {
		// replaying from file
		xAppFD = fileno(fopen("request.log.debug", "r+"));
	}
#endif

	if (xServerFD == -1) {
		CERR << "socket() failed, errno=" << errno << ENDL;
		return 0;
	}

	SETNODELAY(xServerFD);

	if (connect(xServerFD, params->addr, params->length) == -1) {
		CERR << "connect() to X server failed, errno=" << errno << " (" <<
		strerror(errno) << ")" << ENDL;
		SOCKCLOSE(xServerFD);
		return 0;
	}

	//get first message from our record/replay system
	int replay_mode;
	char replyFileName[256];
	char requestFileName[256];
	char eventFileName [256];
	char replyFileNameDebug [256];
	char errorFileName [256];
	char convertFileName [256];

#ifndef FILE_REPLAY
	char tmp_buffer [256];
	unsigned int pid;
	int connTimes;
	int rc = read(xAppFD, tmp_buffer, 1);
	if (rc != 1) {
		cout << "Init message can't be received(mode), quit this thread, rc = "
				<<rc<<endl;
		close(xAppFD);
		close(xServerFD);
		return NULL;
	}
	convert_log = 0;
	if (tmp_buffer[0] == '0')
		replay_mode = 0;
	else if (tmp_buffer[0] == '1')
		replay_mode = 1;
	else if (tmp_buffer[0] == '2') {
		replay_mode = 0;
		convert_log = 1;
		cout <<"converting log mode..."<<endl;
	}
	rc = read(xAppFD, tmp_buffer, 81);
	if (rc != 81) {
		cout
				<< "Init message can't be received(logdir), quit this thread, rc = "
				<<rc<<endl;
		close(xAppFD);
		close(xServerFD);
		return NULL;
	}
	rc = read(xAppFD, (char*)&pid, sizeof(unsigned int));
	if (rc != sizeof(unsigned int)) {
		cout << "Init message can't be received, quit this thread.(pid), rc = "
				<<rc<<endl;
		close(xAppFD);
		close(xServerFD);
		return NULL;
	}
	rc = read(xAppFD, (char*)&connTimes, sizeof(int));
	if (rc != sizeof(int)) {
		cout
				<< "Init message can't be received, quit this thread.(connTimes), rc = "
				<<rc<<endl;
		close(xAppFD);
		close(xServerFD);
		return NULL;
	}
	cout <<"Get the first message for initialization. "
			<<(replay_mode ? "replaying" : "recording")<<", logdir:"
			<<tmp_buffer<<", pid:"<<pid<<", connection times:"<<connTimes<<endl;
	//mkdir(tmp_buffer+14, 0777);
	sprintf(replyFileName, "/replay_logdb/%s/reply.log.id.%u.%d", tmp_buffer + 13, pid,
			connTimes);
	sprintf(requestFileName, "/replay_logdb/%s/request.log.id.debug.%u.%d", tmp_buffer + 13,
			pid, connTimes);
	sprintf(eventFileName, "/replay_logdb/%s/event.log.id.%u.%d", tmp_buffer + 13, pid,
			connTimes);
	sprintf(errorFileName, "/replay_logdb/%s/error.log.id.%u.%d", tmp_buffer + 13, pid,
			connTimes);
	sprintf(replyFileNameDebug, "/replay_logdb/%s/reply.log.id.debug.%u.%d",
			tmp_buffer + 13, pid, connTimes);
	if (convert_log) {
		sprintf(convertFileName, "/replay_logdb/%s/klog.id.%u.x.%d", tmp_buffer + 13, pid,
				connTimes);
		printf("reading from convert file:%s\n", convertFileName);
	}
#else 
	sprintf(replyFileNameDebug, "reply.log.debug");
	sprintf(requestFileName, "request.log.debug");
	sprintf(eventFileName, "event.log");
	sprintf (replyFileName, "reply.log");
	sprintf(errorFileName, "error.log");

#endif
	cout << "reply log:"<<replyFileName<<", reply log:"<<requestFileName
			<<", reply log:"<<eventFileName<<endl;
	//init server channel and client channel
	ResourceID *idMap = new ResourceID();
	unsigned int outputLength = 0;

	ServerChannel serverChannel(xServerFD, params->statLevel, idMap,
			&outputLength, replyFileNameDebug, file_replay);
	if (convert_log) {
		convertFD = serverChannel.setConvertMode(convertFileName);
		cout << "convert fd is "<<convertFD<<endl;
#ifndef CONVERT
		cerr <<"Converting mode: but CONVERT is not on"<<endl;
#endif
	}
	std::cout << "connected to x server."<<std::endl;

	//create channel to client application
	ClientChannel clientChannel(params->connectFD, params->statLevel, idMap,
			&outputLength, requestFileName, file_replay);

#ifdef FILE_REPLAY
	if (file_replay)
	clientChannel.setupFileReplay(xAppFD);
	replay_mode = file_replay;
#endif

	fd_set rfds;
	FD_ZERO (&rfds);

	int maxfd = (xServerFD > xAppFD ? xServerFD : xAppFD);
	if (convert_log) {
		maxfd = (xAppFD > convertFD ? xAppFD : convertFD);
	}
	SequenceNumQueue sequence;
	EventQueue eventQueue(eventFileName, replyFileName, errorFileName,
			replay_mode);
	/*	char buffer[1024];
	 int length;*/
#ifdef CONVERT
	int tried_times = 0;
	int client_close = 0;
#endif
	while (1) {
#ifndef CONVERT
		FD_SET (xServerFD, &rfds);
		FD_SET (xAppFD, &rfds);
		int result = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if (result == -1) {
			cout <<"select in thread fails."<<endl;
			Cleanup();
		} else {
			encodeBuffer.reset();
			if (FD_ISSET (xServerFD, &rfds)) {
				if (thread_debug)
				cout <<"reply and event messages from x server"<<endl;

				if (!serverChannel.doRead(encodeBuffer, sequence, eventQueue,
								xAppFD, xServerFD, replay_mode)) {
					cout <<"x server connection closed."<<endl;
					SOCKCLOSE (xAppFD);
					SOCKCLOSE (xServerFD);
					break;
				}

				if (thread_debug)
				cout <<"reply and event message written to x apps." <<endl;
			} else if (FD_ISSET (xAppFD, &rfds)) {
#ifndef FILE_REPLAY
				if (thread_debug)
				cout <<"request message from x apps"<<endl;
#endif
				if (!clientChannel.doRead(encodeBuffer, sequence, eventQueue,
								xAppFD, xServerFD, replay_mode)) {
					cout << "client application quits."<<endl;
					SOCKCLOSE (xAppFD);
					SOCKCLOSE (xServerFD);
					break;
				}
#ifndef FILE_REPLAY
				if (thread_debug)
				cout << "request message written to x server"<<endl;
#endif
			}
		}
#else
		struct timeval time;
		time.tv_sec = 0;
		time.tv_usec = 0;
		FD_SET (xAppFD, &rfds);
		select(maxfd + 1, &rfds, NULL, NULL, &time);
		int clientRetval = 0;

		encodeBuffer.reset();
		if (clientChannel.hasBufferredMessage()) {
			cout <<"still has bufferred message"<<endl;
		}
		if (FD_ISSET (xAppFD, &rfds) || clientChannel.hasBufferredMessage ()) {
			if (thread_debug)
				cout <<"request message from x apps"<<endl;
			if (!(clientRetval = clientChannel.doRead(encodeBuffer, sequence,
					eventQueue, xAppFD, xServerFD, replay_mode))) {
				/*serverChannel.setConvertPos(clientChannel.getConvertPos());
				 cerr << "client application quits. writing out the remaining reply messages, retval:"<<serverChannel.doRead(encodeBuffer, sequence, eventQueue,
				 xAppFD, xServerFD, replay_mode)<<endl;
				 SOCKCLOSE (xAppFD);
				 SOCKCLOSE (xServerFD);
				 break;*/
				cerr <<"client application quits."<<endl;
				client_close = 1;
			}
			if (thread_debug)
				cout << "request message written to x server"<<endl;

			int convertPos = clientChannel.getConvertPos();
			if (thread_debug)
				cout <<"convertPos:"<<convertPos<<endl;
			serverChannel.setConvertPos(convertPos);
			int retval;
			retval = serverChannel.doRead(encodeBuffer, sequence, eventQueue,
					xAppFD, xServerFD, replay_mode);
			if (tried_times> 50) {
				cerr <<"tried to many times for sending messages"<<endl;
				convertPos += clientChannel.getReadBufferLength();
				serverChannel.setConvertPos(convertPos);
				retval = serverChannel.doRead(encodeBuffer, sequence,
						eventQueue, xAppFD, xServerFD, replay_mode);
				cerr <<"tried again, retval:"<<retval<<endl;
				if (client_close) {
					SOCKCLOSE (xAppFD);
					SOCKCLOSE (xServerFD);
					break;
				}
			}
			if (retval == 0) {
				cout <<"x server connection closed."<<endl;
				SOCKCLOSE (xAppFD);
				SOCKCLOSE (xServerFD);
				break;
			} else if (retval == -1) {
				cout
						<<"at the end of file, continue consuming bufferred messages."
						<<endl;
			} else if (retval == 1) {
				tried_times = 0;
			} else {
				if (clientRetval != 2) {
					cout <<"++tried times"<<endl;
					++tried_times;
				}
			}

		} /*else if (FD_ISSET (convertFD, &rfds) || endOfFile) {
		 //if (sequence.getLength()) {
		 //cout <<"here"<<endl;
		 int retval;
		 if ((retval = serverChannel.doRead(encodeBuffer, sequence,
		 eventQueue, xAppFD, xServerFD, replay_mode)) <= 0) {
		 if (retval == 0) {
		 cout <<"x server connection closed."<<endl;
		 SOCKCLOSE (xAppFD);
		 SOCKCLOSE (xServerFD);
		 break;
		 } else if (retval == -1) {
		 cout
		 <<"at the end of file, continue consuming bufferred messages."
		 <<endl;
		 endOfFile = 1;
		 }
		 }

		 //}
		 }*/
#endif
	}
	return NULL;
}

int main(int argc, char **argv) {
	udomSocketPathname[0] = 0;

	unsigned int displayNum = DEFAULT_DISPLAY_NUM;
	unsigned int statisticsLevel = 0;
	int useTCPSocket = 0;
	const char *displaySrc = 0;

	int xServerAddrFamily= AF_INET;
	sockaddr *xServerAddr= NULL;
	unsigned int xServerAddrLength = 0;

	pthread_t threadID;

	for (int argi = 1; argi < argc; argi++) {
		char *nextArg = argv[argi];

		if (*nextArg == '-') {
			switch (nextArg[1]) {
#ifdef FILE_REPLAY
			case 'r': {
				//in replaying from file
				file_replay = 1;
				cout << "replaying"<<endl;
			}
			break;
#endif
			}
		}
	}

	if (logfilename[0] != '\0') {
		logofs = new OFSTREAM(logfilename, IOS_OUT);
	} else {
		logofs = &COUT;
	}

	// $DISPLAY is the X server for which we'll act as a proxy
	if (!displaySrc) {
		displaySrc = getenv("DISPLAY");
	}
	if ((displaySrc == NULL) || (*displaySrc == 0)) {
		CERR << "$DISPLAY is not set" << ENDL;
		Cleanup();
	}
	char *display = new char[strlen(displaySrc) + 1];

	if (!display) {
		CERR << "Out of memory duping DISPLAY" << ENDL;
		Cleanup();
	}
	strcpy(display, displaySrc);
	char *separator = strchr(display, ':');

	if ((separator == NULL) || !isdigit(*(separator + 1))) {
		CERR << "invalid DISPLAY '" << display << "'" << ENDL;
		Cleanup();
	}
	*separator = 0;
	int serverDisplayNumber = atoi(separator + 1);

	if ((separator == display) || !strcmp(display, "unix")) {
		// UNIX domain port
		xServerAddrFamily = AF_UNIX;
		sockaddr_un *xServerAddrUNIX = new sockaddr_un;

		xServerAddrUNIX->sun_family = AF_UNIX;
		sprintf(udomSocketPathname, "/tmp/.X11-unix/X%d", serverDisplayNumber);
		cout <<"use unix domain socket to connect to x server:"
				<<udomSocketPathname<<endl;
		struct stat statInfo;

		if (stat(udomSocketPathname, &statInfo) == -1) {
			CERR << "cannot open UNIX domain connection to X server"
			<< ENDL;
			Cleanup();
		}
		strcpy(xServerAddrUNIX->sun_path, udomSocketPathname);
		xServerAddr = (sockaddr *) xServerAddrUNIX;
		//      xServerAddrLength = strlen(udomSocketPathname) + 2;
		xServerAddrLength = sizeof(sockaddr_un);
	} else {
		// TCP port
		xServerAddrFamily = AF_INET;
		int ipAddr;
		hostent *hostAddr = gethostbyname(display);

		if (hostAddr == NULL) {
			// on some UNIXes, gethostbyname doesn't accept IP addresses,
			// so try inet_addr:
			ipAddr = (int) inet_addr(display);
			if (ipAddr == -1) {
				CERR << "Unknown host '" << display << "'" << ENDL;
				Cleanup();
			}
		} else
			ipAddr = *(int *) hostAddr->h_addr_list[0];
		sockaddr_in *xServerAddrTCP = new sockaddr_in;

		xServerAddrTCP->sin_family = AF_INET;
		xServerAddrTCP->sin_port = htons(X_TCP_PORT + serverDisplayNumber);
		xServerAddrTCP->sin_addr.s_addr = ipAddr;
		xServerAddr = (sockaddr *) xServerAddrTCP;
		xServerAddrLength = sizeof(sockaddr_in);
	}
	if (display) {
		delete[]display;
		display = 0;
	}

	// Increase the max # of open file descriptors for this process

	maxNumFDs = 0;
#if defined(RLIMIT_NOFILE)
	rlimit limits;

	if (getrlimit(RLIMIT_NOFILE, &limits) == 0) {
		if (limits.rlim_max == RLIM_INFINITY)
			maxNumFDs = 0;
		else
			maxNumFDs = (unsigned int) limits.rlim_max;
	}
#endif /* RLIMIT_NOFILE */

#if defined(_SC_OPEN_MAX)
	if (maxNumFDs == 0)
		maxNumFDs = sysconf(_SC_OPEN_MAX);
#endif

#if defined(FD_SETSIZE)
	if (maxNumFDs> FD_SETSIZE)
		maxNumFDs = FD_SETSIZE;
#endif /* FD_SETSIZE */

#if defined(RLIMIT_NOFILE)
	if (limits.rlim_cur < maxNumFDs) {
		limits.rlim_cur = maxNumFDs;
		setrlimit(RLIMIT_NOFILE, &limits);
	}
#endif /* RLIMIT_NOFILE */

	if (maxNumFDs == 0) {
		CERR <<
		"cannot determine number of available file descriptors, exiting!"
		<< ENDL;
		return 1;
	}

	// Install some signal handlers for graceful shutdown
	signal(SIGHUP, HandleSignal);
	signal(SIGINT, HandleSignal);
	signal(SIGTERM, HandleSignal);

	signal(SIGPIPE, (void (*)(int)) SIG_IGN);

	int tcpFD = -1;
	int unixFD = -1;

	cout << "create socket to accept connections from applications."<<endl;

	if (useTCPSocket) {
		// Open TCP socket for display
		tcpFD = socket(AF_INET, SOCK_STREAM, PF_UNSPEC);
		if (tcpFD == -1) {
			CERR << "socket() failed for TCP socket, errno=" <<
			errno << ENDL;
			Cleanup();
		}
		int flag = 1;

		if (setsockopt(tcpFD, SOL_SOCKET, SO_REUSEADDR, (char *) &flag,
				sizeof(flag)) < 0) {
			CERR <<
			"setsockopt(SO_REUSEADDR) failed for TCP socket, errno = "
			<< errno << ENDL;
		}

		SETNODELAY(tcpFD);

		sockaddr_in tcpAddr;

		tcpAddr.sin_family = AF_INET;
		unsigned int xPortTCP= X_TCP_PORT + displayNum;

		tcpAddr.sin_port = htons(xPortTCP);
		tcpAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		if (bind(tcpFD, (sockaddr *) &tcpAddr, sizeof(tcpAddr)) == -1) {
			CERR << "bind() failed for TCP port " << xPortTCP <<
			", errno=" << errno << ENDL;
			Cleanup();
		}
		cout <<" use tcp socket."<<endl;
		if (listen(tcpFD, 5) == -1) {
			CERR << "listen() failed for TCP port " << xPortTCP <<
			", errno=" << errno << ENDL;
			Cleanup();
		}
	}
	if (useUnixDomainSocket) {
		// Open UNIX domain socket for display
		unixFD = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC);
		if (unixFD == -1) {
			CERR << "socket() failed for UNIX domain socket, errno=" <<
			errno << ENDL;
			Cleanup();
		}
		sockaddr_un unixAddr;

		unixAddr.sun_family = AF_UNIX;
		struct stat dirStat;

		if ((stat("/tmp/.X11-unix", &dirStat) == -1) && (errno == ENOENT)) {
			mkdir("/tmp/.X11-unix", 0777);
			chmod("/tmp/.X11-unix", 0777);
		}
		sprintf(udomSocketPathname, "/tmp/.X11-unix/X%d", displayNum);
		strcpy(unixAddr.sun_path, udomSocketPathname);
		if (bind(unixFD, (sockaddr *) &unixAddr, strlen(udomSocketPathname) + 2)
				== -1) {
			CERR << "bind() failed for UNIX domain socket " <<
			udomSocketPathname << ", errno=" << errno << ENDL;
			CERR <<
			"This probably means you do not have sufficient rights to "
			<< "write to /tmp/.X11-unix/." << ENDL <<
			"Either use the -u option or obtain the necessary rights."
			<< ENDL;
			Cleanup();
		}
		cout <<"use unix domain socket"<<endl;
		if (listen(unixFD, 5) == -1) {
			CERR << "listen() failed for UNIX domain socket " <<
			udomSocketPathname << ", errno=" << errno << ENDL;
			Cleanup();
		}
	}
	struct thread_struct params;
	params.addrFamily = xServerAddrFamily;
	params.addr = xServerAddr;
	params.length = xServerAddrLength;
	params.statLevel = statisticsLevel;
	while (1) {
		int connectFD;
#ifdef FILE_REPLAY
		if (!file_replay) {
#endif

#ifdef CONVERT
		if (useUnixDomainSocket)
			connectFD = accept4(unixFD, NULL, NULL, SOCK_NONBLOCK);
		if (useTCPSocket)
			connectFD = accept4(tcpFD, NULL, NULL, SOCK_NONBLOCK);
#else
		if (useUnixDomainSocket)
		connectFD = accept(unixFD, NULL, NULL);
		if (useTCPSocket)
		connectFD = accept(tcpFD, NULL, NULL);
#endif
		if (connectFD == -1) {
			cerr <<"accept failed for socket."<<endl;
			Cleanup();
		}
		params.connectFD = connectFD;
#ifdef FILE_REPLAY
	}
#endif
		if (pthread_create(&threadID, NULL, serverThread, (void*)&params) != 0) {
			cerr <<"pthread failed to be created."<<endl;
#ifdef FILE_REPLAY
			if (!file_replay)
#endif
			close(connectFD);
			Cleanup();
		}
#ifdef FILE_REPLAY
		while (file_replay)
		;
#endif
	}

	return 0;
}

static void Cleanup() {
	if (!silent)
		cout << "Closing all file descriptors and shutting down..." << endl;

	if (useUnixDomainSocket)
		unlink(udomSocketPathname);

	for (unsigned int i = 0; i < maxNumFDs; i++)
		(void) close(i);

	exit(1);
}

static void HandleSignal(int) {
	Cleanup();
}
