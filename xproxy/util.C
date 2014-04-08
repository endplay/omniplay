#include "dxpcconf.h"
#include <stdlib.h>
#include <unistd.h>
#include "constants.H"
#include "util.H"

#include <stdio.h>
using namespace std;

void printString (const unsigned char* buf, int size) {
	for (int i = 0; i< size; ++i) 
		cout << (unsigned int) buf[i] <<",";
	cout <<endl;
}

void detailedCompare (unsigned char* buf1, int size1, unsigned char* buf2, int size2) {
	if (size1 != size2) {
		cout <<"detailed comparision: Size is not the same."<<endl;
		return;
	}
	cout <<"detailed comparison, differ in pos:";
	for (int i = 0; i <size1; ++i){
		if (buf1[i] != buf2[i])
			cout <<i<<",";
	}
	cout <<endl;
}


void printMessage (unsigned const char* buffer, int size, int num, ...) {
	va_list arguments;
	int count = 0;
	if (PRINT_DEBUG == 0)
		return;
	va_start (arguments, num);
	cout <<"----------------------"<<endl;
	for (int i = 0; i < num; ++i) {
		int entrySize = va_arg (arguments, int);
		if (i == num - 1 && entrySize == -1) {
			// the last bytes, and unused
			cout <<"    unused "<< size - count<<endl;
			count = size;
			break;
		}
		if (entrySize < MAGIC_SIZE) {
			cout <<"    "<<entrySize<<": ";
			for (int j = 0; j < entrySize; ++j) {
				cout << (unsigned int)buffer[count] << ",";
				++ count;
			}
		} else {
			entrySize -= MAGIC_SIZE;
			cout <<"    unused "<<entrySize;
			count += entrySize;
		}
		cout <<endl;
	}
	if (count < size) { 
		int remaining = size - count;
		cout<<"    remaining "<< size-count<<": ";
		for (int i = 0; i < remaining; ++i) {
			cout <<(unsigned int)buffer[count] <<",";
			++count;
		}
		cout <<endl;
	}
	cout <<"----------------------"<<endl;
}

unsigned int GetUINT(unsigned const char *buffer, int bigEndian)
{
    unsigned int result;

    if (bigEndian)
    {
        result = *buffer;
        result <<= 8;
        result += buffer[1];
    }
    else
    {
        result = buffer[1];
        result <<= 8;
        result += *buffer;
    }
    return result;
}


unsigned int GetULONG(unsigned const char *buffer, int bigEndian)
{
    const unsigned char *next = (bigEndian ? buffer : buffer + 3);
    unsigned int result = 0;

    for (int i = 0; i < 4; i++)
    {
        result <<= 8;
        result += *next;
        if (bigEndian)
            next++;
        else
            next--;
    }
    return result;
}

void PutUINT(unsigned int value, unsigned char *buffer, int bigEndian)
{
    if (bigEndian)
    {
        buffer[1] = (unsigned char) (value & 0xff);
        value >>= 8;
        *buffer = (unsigned char) value;
    }
    else
    {
        *buffer = (unsigned char) (value & 0xff);
        value >>= 8;
        buffer[1] = (unsigned char) value;
    }
}


void PutULONG(unsigned int value, unsigned char *buffer, int bigEndian)
{
    if (bigEndian)
    {
        buffer += 3;
        for (int i = 4; i; i--)
        {
            *buffer-- = (unsigned char) (value & 0xff);
            value >>= 8;
        }
    }
    else
    {
        for (int i = 4; i; i--)
        {
            *buffer++ = (unsigned char) (value & 0xff);
            value >>= 8;
        }
    }
}


unsigned int RoundUp4(unsigned int x)
{
    unsigned int y = x / 4;

    y *= 4;
    if (y != x)
        y += 4;
    return y;
}

void PrintVersionInfo()
{
    COUT << "xproxy - " <<
        "Version " << DXPC_VERSION_MAJOR << '.' << DXPC_VERSION_MINOR << '.'
        << DXPC_VERSION_PATCH;
    if (DXPC_VERSION_BETA != 0)
        COUT << "beta" << DXPC_VERSION_BETA;
    COUT << ENDL;
    COUT << getLicenseInfo() << ENDL;
}


void DumpMessage(const unsigned char *src, unsigned int numBytes)
{
    for (unsigned int i = 0; i < numBytes; i++)
        COUT << i << '\t' << (unsigned int) (src[i]) << ENDL;
}


const char *GetArg(int &argi, int argc, const char **argv)
{
    const char *nextArg = argv[argi] + 2;       // skip "-" and flag character

    if (*nextArg == 0)
    {
        if (argi + 1 == argc)
            return NULL;
        else
        {
            argi++;
            return argv[argi];
        }
    }
    else
        return nextArg;
}

int WriteAll(int fd, const unsigned char *data, unsigned int length)
{
    unsigned int bytesWritten = 0;

#undef SPEWIT
#ifdef SPEWIT
    unsigned i = 0;

    while (i < length)
    {
        unsigned rem = length - i;

        if (rem > 16)
        {
            rem = 16;
        }
        fprintf(stderr, "%04x: ", i % 16);
        for (unsigned j = 0; j < rem; j++)
        {
            fprintf(stderr, "%02x ", data[i++]);
        }
        fprintf(stderr, "\n");
    }
#endif

    while (bytesWritten < length)
    {
        int result = SOCKWRITE(fd, data + bytesWritten,
                               length - bytesWritten);

        if (result <= 0)
            return -1;
        bytesWritten += result;
    }
    return length;
}
