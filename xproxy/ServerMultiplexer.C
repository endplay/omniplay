#include "dxpcconf.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "ServerMultiplexer.H"
#include "ServerChannel.H"

#if !defined(__MINGW32__)
# include <netinet/in.h>
#endif
#if !defined(__CYGWIN32__) && !defined(__MINGW32__)
# include <netinet/tcp.h>
#endif

ServerMultiplexer::ServerMultiplexer(int proxyFD, int xServerAddrFamily,
                                     sockaddr * xServerAddr,
                                     unsigned int xServerAddrLength,
                                     unsigned int
                                     statisticsLevel) :
    Multiplexer(proxyFD),
    xServerAddrFamily_(xServerAddrFamily),
    xServerAddr_(xServerAddr),
    xServerAddrLength_(xServerAddrLength),
    statisticsLevel_(statisticsLevel)
{
    for (unsigned int i = 0; i < MAX_CONNECTIONS; i++)
    {
        channelIDToFDMap_[i] = -1;
    }
}

ServerMultiplexer::~ServerMultiplexer()
{
    if (xServerAddr_)
    {
        delete xServerAddr_;
    }
}

void ServerMultiplexer::createNewConnection(int clientFD)
{
    clientFD = 0;
    CERR << "Internal error: in ServerMultiplexer::createNewConnection" <<
        ENDL;
}

int ServerMultiplexer::createNewConnectionFromProxy(int channelID)
{
    // Connect to the real X server
    int xServerFD = socket(xServerAddrFamily_, SOCK_STREAM, PF_UNSPEC);

    if (xServerFD == -1)
    {
        CERR << "socket() failed, errno=" << errno << ENDL;
        return 0;
    }

    SETNODELAY(xServerFD);

    if (connect(xServerFD, xServerAddr_, xServerAddrLength_) == -1)
    {
        CERR << "connect() to X server failed, errno=" << errno << " (" <<
            strerror(errno) << ")" << ENDL;
        SOCKCLOSE(xServerFD);
        return 0;
    }
    channelIDToFDMap_[channelID] = xServerFD;

//    channels_[channelID] = new ServerChannel(xServerFD, statisticsLevel_);
//    std::cout << "connect to x server."<<std::endl;
    return 1;
}

int ServerMultiplexer::channelIDToFD(int channelID) const
{
    if ((channelID < 0) || ((unsigned int) channelID >= MAX_CONNECTIONS))
        return -1;
    else
        return channelIDToFDMap_[channelID];
}

int ServerMultiplexer::fdToChannelID(int fd) const
{
    for (unsigned i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (channelIDToFDMap_[i] == fd)
        {
            return i;
        }
    }
    CERR << "No such fd " << fd << " in ServerMultiplexer::fdToChannelID" <<
        ENDL;
    return -1;
}

void ServerMultiplexer::cleanupChannelFDMapping(int channelID)
{
    channelIDToFDMap_[channelID] = -1;
}
