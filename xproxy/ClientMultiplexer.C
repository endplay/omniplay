#include "dxpcconf.h"

#include "ClientMultiplexer.H"
#include "ClientChannel.H"
#include "util.H"

#include <stdio.h>
#include <iostream>
using namespace std;
ClientMultiplexer::ClientMultiplexer(int proxyFD,
                                     int
                                     statisticsLevel):
    Multiplexer(proxyFD),
    statisticsLevel_(statisticsLevel)
{
    for (unsigned i = 0; i < MAX_CONNECTIONS; i++)
    {
        _channelMap[i] = -1;
    }
}

void ClientMultiplexer::createNewConnection(int clientFD)
{
    int channelNum = -1;

    for (unsigned i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (_channelMap[i] == -1)
        {
            _channelMap[i] = clientFD;
            channelNum = i;
            break;
        }
    }

//    channels_[channelNum] = new ClientChannel(clientFD, statisticsLevel_);
    unsigned char message[3];

    message[0] = 0;
    message[1] = (unsigned char) CTRL_NEW_CONNECTION;
    message[2] = channelNum;
    ofstream file;
    file.open ("replay_log", ios::app | ios::out | ios::binary);
    file.write ((char*)message, 3);
    file.close();
    cout <<"create new connection in clientMultiplexer and write into log"<<endl;
    WriteAll(proxyFD_, message, 3);
}

int ClientMultiplexer::createNewConnectionFromProxy(int)
{
    CERR <<
        "Internal error: in ClientMultiplexer::createNewConnectionFromProxy"
        << ENDL;
    return 0;
}

int ClientMultiplexer::channelIDToFD(int channelID) const
{
    return _channelMap[channelID];
}

int ClientMultiplexer::fdToChannelID(int fd) const
{
    for (unsigned i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (_channelMap[i] == fd)
        {
            return i;
        }
    }

    return -1;
}

void ClientMultiplexer::cleanupChannelFDMapping(int channelNum)
{
    _channelMap[channelNum] = -1;
}
