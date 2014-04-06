#ifndef ClientMultiplexer_H
# define ClientMultiplexer_H

# include "Multiplexer.H"


class ClientMultiplexer:public Multiplexer
{
  public:
    ClientMultiplexer(int proxyFD, int statisticsLevel);
      virtual ~ ClientMultiplexer()
    {
    }

  protected:
      virtual void createNewConnection(int fd);
    virtual int createNewConnectionFromProxy(int channelID);

    virtual int channelIDToFD(int channelID) const;
    virtual int fdToChannelID(int fd) const;
    virtual void cleanupChannelFDMapping(int channelFD);

    unsigned int statisticsLevel_;
    int _channelMap[MAX_CONNECTIONS];
};


#endif /* ClientMultiplexer_H */
