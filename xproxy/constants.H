#ifndef Constants_H
# define Constants_H

// dxpc version number
static const unsigned int DXPC_VERSION_MAJOR = 1;
static const unsigned int DXPC_VERSION_MINOR = 0;
static const unsigned int DXPC_VERSION_PATCH = 0;
static const unsigned int DXPC_VERSION_BETA = 0;        // zero if not beta

// Maximum number of X connections supported
static const unsigned int MAX_CONNECTIONS = 256;

// TCP port on which server proxy listens for connections from
// client proxy
static const unsigned int DEFAULT_PROXY_PORT = 4000;

// X display number that client proxy imitates
static const unsigned int DEFAULT_DISPLAY_NUM = 8;

// Default image compression level.
static const int DEFAULT_IMAGE_COMPRESSION_LEVEL = 9;

// Bit masks to select the lower 'i' bits of an int, 0 <= 'i' <= 32
extern const unsigned int PARTIAL_INT_MASK[33];

// Maximum number of points in a FillPoly request that are given
// their own history caches
static const unsigned int FILL_POLY_MAX_POINTS = 10;

// Sizes of optional fields for ConfigureWindow request
extern const unsigned int CONFIGUREWINDOW_FIELD_WIDTH[7];

// Sizes of optional fields for CreateGC request
extern const unsigned int CREATEGC_FIELD_WIDTH[23];

// Mapping to reverse the bits in a byte, for image processing on
// little-endian architectures:
extern unsigned char REVERSED_BYTE[256];

// Min width/height ratio for treatment of a bitmap image as a line of
// bitmapped text
static const unsigned int PUT_IMAGE_MIN_ASPECT_RATIO = 8;

// Return the license/copyright info string.
extern const char *getLicenseInfo();

#endif /* Constants_H */
