#ifndef Multiplexer_H
# define Multiplexer_H

# include <sys/types.h>
# ifdef _AIX
#  include <sys/select.h>
# endif/* _AIX */

# include "ProxyReadBuffer.H"
# include "EncodeBuffer.H"
# include "constants.H"


class Channel;



class Multiplexer
{
  public:
    Multiplexer(int proxyFD);
      virtual ~ Multiplexer();

    void setSelectFDs(fd_set *, unsigned int &max);
    int handleSelect(int fd, int mode);

    virtual void createNewConnection(int clientFD) = 0;

  protected:

    // codes used for control messages in proxy-to-proxy protocol
    enum ControlCode
    {
        CTRL_NEW_CONNECTION, CTRL_DROP_CONNECTION,
        CTRL_SWITCH_CONNECTION
    };

    virtual int createNewConnectionFromProxy(int channelID) = 0;

    virtual int channelIDToFD(int channelID) const = 0;
    virtual int fdToChannelID(int fd) const = 0;
    virtual void cleanupChannelFDMapping(int channelFD) = 0;

    // Objects used to read data sent from peer proxy
    const int proxyFD_;
    ProxyReadBuffer proxyReadBuffer_;
    int proxyInputChannel_;

    // Objects used to send data to peer proxy
    EncodeBuffer encodeBuffer_;
    int proxyOutputChannel_;

    // X connections
    Channel *channels_[MAX_CONNECTIONS];
};


#endif /* Multiplexer_H */
