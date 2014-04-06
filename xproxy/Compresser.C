#include "dxpcconf.h"

#include <string.h>
#include "X-headers.H"
#include "ClientChannel.H"
#include "EncodeBuffer.H"
#include "DecodeBuffer.H"
#include "util.H"
#include <assert.h>
#include <limits.h>

#include "Compresser.H"

typedef struct cEntry
{
    int cLevel;
    lzo_compress_t cFnc;
    lzo_uint cWorkMem;
    lzo_decompress_t dFnc;
} cEntry;

// The table including all supported LZO algorithms.
// lzo1x is the recommeded algortihm, but only comes
// with two compression levels: 1 & 999. lzo1c is used to fill
// in the gaps. 
static cEntry _knownAlgorithms[] = {
    {1, lzo1x_1_compress, LZO1X_MEM_COMPRESS, lzo1x_decompress},
    {2, lzo1c_2_compress, LZO1C_MEM_COMPRESS, lzo1c_decompress},
    {3, lzo1c_3_compress, LZO1C_MEM_COMPRESS, lzo1c_decompress},
    {4, lzo1c_4_compress, LZO1C_MEM_COMPRESS, lzo1c_decompress},
    {5, lzo1c_5_compress, LZO1C_MEM_COMPRESS, lzo1c_decompress},
    {6, lzo1c_6_compress, LZO1C_MEM_COMPRESS, lzo1c_decompress},
    {7, lzo1c_7_compress, LZO1C_MEM_COMPRESS, lzo1c_decompress},
    {8, lzo1c_8_compress, LZO1C_MEM_COMPRESS, lzo1c_decompress},
    {9, lzo1c_9_compress, LZO1C_MEM_COMPRESS, lzo1c_decompress},
    {99, lzo1c_99_compress, LZO1C_99_MEM_COMPRESS, lzo1c_decompress},
    {999, lzo1x_999_compress, LZO1X_999_MEM_COMPRESS, lzo1x_decompress},
    {0, 0, 0}
};

Compresser::Compresser(int compressionLevel) : 
    lzoCompressionWorkspace(0),
    lzoCompressionBuffer(0), 
    lzoCompressionBufferSize(0),
    compressionFnc(0)
{
    cEntry *alg = getCEntry(compressionLevel);

    if (alg)
    {
        lzoCompressionWorkspace = new lzo_byte[alg->cWorkMem];
        if (lzoCompressionWorkspace)
        {
            // memset here supresses valgrind warning in the bowels
            // of lzo.
            memset(lzoCompressionWorkspace, 0, alg->cWorkMem);
            compressionFnc = alg->cFnc;
        }
        else
        {
            *logofs << "Insufficient memory for image compression level "
                << compressionLevel << "\n";

        }
    }
    else
    {
        *logofs << "Unknown image compression level " << compressionLevel
            << "\n";
    }
}

Compresser::~Compresser()
{
    if (lzoCompressionWorkspace)
    {
        delete[]lzoCompressionWorkspace;
        lzoCompressionWorkspace = 0;
    }

    if (lzoCompressionBuffer)
    {
        delete[]lzoCompressionBuffer;
        lzoCompressionBuffer = 0;
        lzoCompressionBufferSize = 0;
    }
}

CompressionType
    Compresser::compressBuffer(const unsigned char *buffer,
                               const unsigned int size,
                               EncodeBuffer & encodeBuffer)
{
    if (!compressionFnc || !lzoCompressionWorkspace || size < 64)
    {
        return NO_STREAM_COMPRESSION;
    }

    // Algorithm stolen from LZO FAQ. 
    unsigned int max_compressed_size = size + (size / 64) + 16 + 3;

    if (max_compressed_size > lzoCompressionBufferSize)
    {
        if (lzoCompressionBuffer)
        {
            delete[]lzoCompressionBuffer;
        }

        lzoCompressionBuffer = new lzo_byte[max_compressed_size];
        if (lzoCompressionBuffer)
        {
            lzoCompressionBufferSize = max_compressed_size;
        }
        else
        {
            lzoCompressionBufferSize = 0;
        }
    }

    if (!lzoCompressionBuffer)
    {
        return NO_STREAM_COMPRESSION;
    }

    lzo_uint compressedSize = max_compressed_size;
    lzo_byte *compressedImage = lzoCompressionBuffer;

    if (compressionFnc(buffer, size,
                       compressedImage, &compressedSize,
                       lzoCompressionWorkspace) == LZO_E_OK)
    {
        assert(compressedSize <= max_compressed_size);
	assert(compressedSize <= UINT_MAX);
        encodeBuffer.encodeValue(LZO_COMPRESSION, COMPRESSION_TYPE_BITS);
        encodeBuffer.encodeValue((unsigned)compressedSize, sizeof(unsigned) * 8);
        encodeBuffer.encodeValue(size, sizeof(unsigned) * 8);
        encodeBuffer.encodeRawMem(compressedImage, compressedSize);

        return LZO_COMPRESSION;
    }
    return NO_STREAM_COMPRESSION;
}

int Compresser::isValidCompressionLevel(int compressionLevel)
{
    return getCEntry(compressionLevel) != 0;
}

cEntry *Compresser::getCEntry(int compressionLevel)
{
    cEntry *alg = _knownAlgorithms;

    while (alg->cLevel && alg->cLevel != compressionLevel)
    {
        alg++;
    }

    if (alg->cLevel)
    {
        return alg;
    }
    return 0;
}

lzo_decompress_t Compresser::getDecompresser(int compressionLevel)
{
    cEntry *alg;

    alg = getCEntry(compressionLevel);
    if (alg)
    {
        return alg->dFnc;
    }
    return 0;
}
