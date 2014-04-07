#include "dxpcconf.h"
#include <string.h>
#include "X-headers.H"
#include "ClientChannel.H"
#include "EncodeBuffer.H"
#include "DecodeBuffer.H"
#include "util.H"
#include "assert.h"

#include "Compresser.H"
#include "Decompresser.H"

Decompresser::Decompresser(int compressionLevel)
{
    decompressionFnc = Compresser::getDecompresser(compressionLevel);
}

Decompresser::~Decompresser()
{
}

void Decompresser::decompressBuffer(CompressionType compressionType,
                                    unsigned char *outBuffer,
                                    DecodeBuffer & decodeBuffer)
{
    lzo_uint size;
    unsigned compressedSize, value;

    if (!decompressionFnc || compressionType != LZO_COMPRESSION)
    {
        return;
    }

    decodeBuffer.decodeValue(compressedSize, sizeof(unsigned) * 8);
    decodeBuffer.decodeValue(value, sizeof(unsigned) * 8);
    size = (lzo_uint)value;

    decompressionFnc(decodeBuffer.decodeRawMem(compressedSize),
                     (lzo_uint)compressedSize, outBuffer, &size, NULL);
}
