#include "dxpcconf.h"
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "Multiplexer.H"
#include "Channel.H"
#include "util.H"

extern int silent;
using namespace std;
#define replay_debug 1

Multiplexer::Multiplexer(int proxyFD):
    proxyFD_(proxyFD),
    proxyReadBuffer_(proxyFD), 
    proxyInputChannel_(-1), 
    proxyOutputChannel_(-1)
{
    for (unsigned int i = 0; i < MAX_CONNECTIONS; i++)
        channels_[i] = 0;
}


Multiplexer::~Multiplexer()
{
    for (unsigned int i = 0; i < MAX_CONNECTIONS; i++)
        delete channels_[i];
}


// Add the file descriptors for this multiplexer's X connections
// to the supplied select set
void Multiplexer::setSelectFDs(fd_set * fdSet, unsigned int &max)
{
    int numFDsToSelect = max;

    for (unsigned int i = 0; i < MAX_CONNECTIONS; i++)
        if (channels_[i] != 0)
        {
            int nextFD = channelIDToFD(i);

//      CERR << "Multiplexer::setSelectFDs setting " << nextFD << ENDL;
            FD_SET(nextFD, fdSet);
            if (nextFD >= numFDsToSelect)
                numFDsToSelect = nextFD + 1;
        }
    max = numFDsToSelect;
}


int Multiplexer::handleSelect(int fd, int mode)
{
    unsigned char controlMessages[9];
    unsigned int controlMessagesLength = 0;

    encodeBuffer_.reset();

    if (fd == proxyFD_)
    {
	    if (mode!=2) {
		    if (!proxyReadBuffer_.doRead())
		    {
			    if (!silent)
			    {
				    CERR << "lost connection to peer proxy" << ENDL;
			    }
			    return 0;
		    }
	    }


        const unsigned char *message;
        unsigned int messageLength;

        while ((message = proxyReadBuffer_.getMessage(messageLength)) != 0)
        {
		if(replay_debug) cout <<" parse a proxy message, size:"<<messageLength<<endl;
            if ((messageLength == 3) && (message[0] == 0))
            {
                if (message[1] == (unsigned char) CTRL_NEW_CONNECTION)
                {
			cout <<"new connection"<<endl;
                    int channelNum = (int) message[2];

                    if (!createNewConnectionFromProxy(channelNum))
                    {
                        controlMessages[controlMessagesLength++] = 0;
                        controlMessages[controlMessagesLength++] =
                            (unsigned char) CTRL_DROP_CONNECTION;
                        controlMessages[controlMessagesLength++] =
                            (unsigned char) channelNum;
                    }
                }
                else if (message[1] == (unsigned char) CTRL_DROP_CONNECTION)
                {
			if (mode != 2) {
				int channelNum = (int) message[2];

				if (((unsigned int) channelNum < MAX_CONNECTIONS) &&
						(channels_[channelNum] != 0))
				{
					SOCKCLOSE(channelIDToFD(channelNum));
					delete channels_[channelNum];

					channels_[channelNum] = 0;
					cleanupChannelFDMapping(channelNum);
				}
			}
                }
                else if (message[1] == (unsigned char) CTRL_SWITCH_CONNECTION)
                {
                    proxyInputChannel_ = (int) message[2];
                }
                else
                {
                    CERR << "invalid message from peer proxy!" << ENDL;
                    return 0;
                }
            }
            else
            {
                int channelNum = proxyInputChannel_;

                if ((channelNum >= 0) &&
                    ((unsigned int) channelNum < MAX_CONNECTIONS) &&
                    (channels_[channelNum] != 0))
                {
                    /*if (!channels_[channelNum]->
                        doWrite(message, messageLength))
                    {
                        SOCKCLOSE(channelIDToFD(channelNum));
                        delete channels_[channelNum];

                        channels_[channelNum] = 0;
                        cleanupChannelFDMapping(channelNum);
                        controlMessages[controlMessagesLength++] = 0;
                        controlMessages[controlMessagesLength++] =
                            (unsigned char) CTRL_DROP_CONNECTION;
                        controlMessages[controlMessagesLength++] =
                            (unsigned char) channelNum;
                    }*/
                }
            }
        }
    }
    else
    {
        // Data arrived from some X connection

        int channelNum = fdToChannelID(fd);

        if ((channelNum < 0) || (channels_[channelNum] == 0))
        {
            SOCKCLOSE(fd);
            return 1;
        }

//    CERR << "data received on X channel " << channelNum << ENDL;

        // Let the channel object read all the new data from its
        // file descriptor, isolate messages, compress those messages,
        // and append the compressed form to the encodeBuffer_
        /*if (!channels_[channelNum]->doRead(encodeBuffer_))
        {
            SOCKCLOSE(fd);
            delete channels_[channelNum];

            channels_[channelNum] = 0;
            cleanupChannelFDMapping(channelNum);

            // Send channel shutdown message to the peer proxy
            controlMessages[controlMessagesLength++] = 0;
            controlMessages[controlMessagesLength++] =
                (unsigned char) CTRL_DROP_CONNECTION;
            controlMessages[controlMessagesLength++] =
                (unsigned char) channelNum;
        }*/
        // Generate a control message to the peer proxy to tell it that
        // we're now sending data for a different channel
        else if (channelNum != proxyOutputChannel_)
        {
            proxyOutputChannel_ = channelNum;
            controlMessages[controlMessagesLength++] = 0;
            controlMessages[controlMessagesLength++] =
                (unsigned char) CTRL_SWITCH_CONNECTION;
            controlMessages[controlMessagesLength++] =
                (unsigned char) channelNum;
        }
    }


    // write any outstanding control messages, followed by any outstanding
    // compressed X messages, to proxyFD...
    // This code assumes that "encodeBuffer_.getData()" actually references
    // a location offset several bytes from the start of the buffer, so that
    // the length header and any necessary control messages can be inserted
    // in front of the data already in the buffer.  (See EncodeBuffer.C.)
    // This is an ugly hack, but it's the easiest way to encapsulate the
    // header and message data together in a single write(2) call.
    //  (Experimentation has shown that doing separate writes for the
    // header and the data causes the responsiveness of applications
    // run over dxpc to deteriorate enormously.)
    unsigned int dataLength = encodeBuffer_.getDataLength();

    if (dataLength + controlMessagesLength != 0)
    {
        unsigned char temp[5];
        unsigned int lengthLength = 0;
        unsigned int length = dataLength;

        while (length)
        {
            temp[lengthLength++] = (unsigned char) (length & 0x7f);
            length >>= 7;
        }

        unsigned char *data = encodeBuffer_.getData();
        unsigned char *outputMessage = data -
            (controlMessagesLength + lengthLength);
        unsigned int outputLength = dataLength + controlMessagesLength +
            lengthLength;
        unsigned char *nextDest = outputMessage;

        for (unsigned int i = 0; i < controlMessagesLength; i++)
            *nextDest++ = controlMessages[i];
        for (int j = lengthLength - 1; j > 0; j--)
            *nextDest++ = (temp[j] | 0x80);
        if (lengthLength)
            *nextDest++ = temp[0];

        if ((dataLength != 0) &&
            (proxyOutputChannel_ >= 0) &&
            ((unsigned int) proxyOutputChannel_ < MAX_CONNECTIONS) &&
            (channels_[proxyOutputChannel_] != NULL))
            channels_[proxyOutputChannel_]->recordFramingBits((controlMessagesLength + lengthLength) << 3);

	if (mode == 1) {
		ofstream logfile;
		logfile.open ("replay_log", ios::out | ios::binary | ios::app);
		logfile.write ((char*)outputMessage, outputLength);
		if(replay_debug) cout <<"write "<<outputLength<<" bytes into log."<<endl;
		logfile.close();
	}
	if (mode != 2) {
	if(replay_debug) cout <<"send out messages to peer. control_len:"<<controlMessagesLength<<", lengthlength:"<<lengthLength<<", total:"<<outputLength<<endl;
		if (WriteAll(proxyFD_, outputMessage, outputLength) <= 0)
			return 0;
	} else
		if(replay_debug) cout <<"replay mode, don't send out message to peers."<<endl;
    }
    return 1;
}
