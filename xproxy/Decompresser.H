#ifndef DECOMPRESSER_H_
# define DECOMPRESSER_H_

# ifdef LZO2
#  include "lzo/lzo1c.h"
# else
#  include "lzo1c.h"
# endif

class DecodeBuffer;

# include "Compresser.H"

class Decompresser
{
  public:

    Decompresser(int compressionLevel);
     ~Decompresser();

    void decompressBuffer(CompressionType compressionType,
                          unsigned char *outBuffer,
                          DecodeBuffer & decodeBuffer);

  private:
      lzo_decompress_t decompressionFnc;
};

#endif
