#ifndef COMPRESSER_H_
# define COMPRESSER_H_

# ifdef LZO2
#  include "lzo/lzo1x.h"
#  include "lzo/lzo1c.h"
# else
#  include "lzo1x.h"
#  include "lzo1c.h"
# endif

class EncodeBuffer;
struct cEntry;

typedef enum
{ NO_STREAM_COMPRESSION = 0, LZO_COMPRESSION = 1 } CompressionType;

// Number of bits needed to hold an enum value.
# define COMPRESSION_TYPE_BITS 1



class Compresser
{
  public:

    Compresser(int compressionLevel);
     ~Compresser();

    CompressionType compressBuffer(const unsigned char *buffer,
                                   const unsigned int size,
                                   EncodeBuffer & encodeBuffer);

    // These next two things really belong in a factory class that
    // builds compressers & decompressers based on the compression
    // level. But I'm lazy.
    static int isValidCompressionLevel(int compressionLevel);
    static lzo_decompress_t getDecompresser(int compressionLevel);

  private:
      lzo_byte * lzoCompressionWorkspace;
    lzo_byte *lzoCompressionBuffer;
    lzo_uint lzoCompressionBufferSize;
    lzo_compress_t compressionFnc;
    static cEntry *getCEntry(int compressionLevel);
};

#endif
