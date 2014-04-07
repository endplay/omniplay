#ifndef ServerMultiplexer_H
# define ServerMultiplexer_H

# include <sys/types.h>
# ifndef __MINGW32__
#  include <sys/socket.h>
# endif
# include "Multiplexer.H"


class ServerMultiplexer:public Multiplexer
{
  public:
    ServerMultiplexer(int proxyFD, int xServerAddrFamily,
                      sockaddr * xServerAddr, unsigned int xServerAddrLength,
                      unsigned int statisticsLevel);
      virtual ~ServerMultiplexer();

  protected:
      virtual void createNewConnection(int fd);
    virtual int createNewConnectionFromProxy(int channelID);

    virtual int channelIDToFD(int channelID) const;
    virtual int fdToChannelID(int fd) const;
    virtual void cleanupChannelFDMapping(int channelFD);

    int fdToChannelIDMap_[MAX_CONNECTIONS];
    int channelIDToFDMap_[MAX_CONNECTIONS];

    int xServerAddrFamily_;
    sockaddr *xServerAddr_;
    unsigned int xServerAddrLength_;

    unsigned int statisticsLevel_;
};


#endif /* ServerMultiplexer_H */
