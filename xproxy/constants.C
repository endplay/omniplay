#include "constants.H"

const char copyright[] = "Copyright (c) 1995,1996 Brian Pane\n\
Copyright (c) 1996,1997 Zachary Vonler and Brian Pane\n\
Copyright (c) 1999-2009 Kevin Vigor and Brian Pane\n\
All rights reserved.\n\
\n\
Redistribution and use in source and binary forms, with or without\n\
modification, are permitted provided that the following conditions are met:\n\
\n\
* Redistributions of source code must retain the above copyright\n\
  notice, this list of conditions and the following disclaimer.\n\
\n\
* Redistributions in binary form must reproduce the above copyright\n\
  notice, this list of conditions and the following disclaimer in the\n\
  documentation and/or other materials provided with the distribution.\n\
\n\
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND\n\
CONTRIBUTORS \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES,\n\
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF\n\
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE\n\
DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS\n\
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,\n\
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n\
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;\n\
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)\n\
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN\n\
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR\n\
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS\n\
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH\n\
DAMAGE.";

// Make sure that both "source and binary forms" of any dxpc distribution
// bear the copyright and liability disclaimer specified in the README.
// (Call this function from some other .C file to ensure that the
// "copyright" string literal ends up in the resulting binary
const char *getLicenseInfo()
{
    return copyright;
}

const unsigned int PARTIAL_INT_MASK[33] = {
    0x00000000,
    0x00000001,
    0x00000003,
    0x00000007,
    0x0000000f,
    0x0000001f,
    0x0000003f,
    0x0000007f,
    0x000000ff,
    0x000001ff,
    0x000003ff,
    0x000007ff,
    0x00000fff,
    0x00001fff,
    0x00003fff,
    0x00007fff,
    0x0000ffff,
    0x0001ffff,
    0x0003ffff,
    0x0007ffff,
    0x000fffff,
    0x001fffff,
    0x003fffff,
    0x007fffff,
    0x00ffffff,
    0x01ffffff,
    0x03ffffff,
    0x07ffffff,
    0x0fffffff,
    0x1fffffff,
    0x3fffffff,
    0x7fffffff,
    0xffffffff
};

const unsigned int CONFIGUREWINDOW_FIELD_WIDTH[7] = {
    16,                         // x
    16,                         // y
    16,                         // width
    16,                         // height
    16,                         // border width
    29,                         // sibling window
    3                           // stack mode
};

const unsigned int CREATEGC_FIELD_WIDTH[23] = {
    4,                          // function
    32,                         // plane mask
    32,                         // foreground
    32,                         // background
    16,                         // line width
    2,                          // line style
    2,                          // cap style
    2,                          // join style
    2,                          // fill style
    1,                          // fill rule
    29,                         // tile
    29,                         // stipple
    16,                         // tile/stipple x origin
    16,                         // tile/stipple y origin
    29,                         // font
    1,                          // subwindow mode
    1,                          // graphics exposures
    16,                         // clip x origin
    16,                         // clip y origin
    29,                         // clip mask
    16,                         // card offset
    8,                          // dashes
    1,                          // arc mode
};

unsigned char REVERSED_BYTE[256] = {
    0x00,
    0x80,
    0x40,
    0xc0,
    0x20,
    0xa0,
    0x60,
    0xe0,
    0x10,
    0x90,
    0x50,
    0xd0,
    0x30,
    0xb0,
    0x70,
    0xf0,

    0x08,
    0x88,
    0x48,
    0xc8,
    0x28,
    0xa8,
    0x68,
    0xe8,
    0x18,
    0x98,
    0x58,
    0xd8,
    0x38,
    0xb8,
    0x78,
    0xf8,

    0x04,
    0x84,
    0x44,
    0xc4,
    0x24,
    0xa4,
    0x64,
    0xe4,
    0x14,
    0x94,
    0x54,
    0xd4,
    0x34,
    0xb4,
    0x74,
    0xf4,

    0x0c,
    0x8c,
    0x4c,
    0xcc,
    0x2c,
    0xac,
    0x6c,
    0xec,
    0x1c,
    0x9c,
    0x5c,
    0xdc,
    0x3c,
    0xbc,
    0x7c,
    0xfc,

    0x02,
    0x82,
    0x42,
    0xc2,
    0x22,
    0xa2,
    0x62,
    0xe2,
    0x12,
    0x92,
    0x52,
    0xd2,
    0x32,
    0xb2,
    0x72,
    0xf2,

    0x0a,
    0x8a,
    0x4a,
    0xca,
    0x2a,
    0xaa,
    0x6a,
    0xea,
    0x1a,
    0x9a,
    0x5a,
    0xda,
    0x3a,
    0xba,
    0x7a,
    0xfa,

    0x06,
    0x86,
    0x46,
    0xc6,
    0x26,
    0xa6,
    0x66,
    0xe6,
    0x16,
    0x96,
    0x56,
    0xd6,
    0x36,
    0xb6,
    0x76,
    0xf6,

    0x0e,
    0x8e,
    0x4e,
    0xce,
    0x2e,
    0xae,
    0x6e,
    0xee,
    0x1e,
    0x9e,
    0x5e,
    0xde,
    0x3e,
    0xbe,
    0x7e,
    0xfe,

    0x01,
    0x81,
    0x41,
    0xc1,
    0x21,
    0xa1,
    0x61,
    0xe1,
    0x11,
    0x91,
    0x51,
    0xd1,
    0x31,
    0xb1,
    0x71,
    0xf1,

    0x09,
    0x89,
    0x49,
    0xc9,
    0x29,
    0xa9,
    0x69,
    0xe9,
    0x19,
    0x99,
    0x59,
    0xd9,
    0x39,
    0xb9,
    0x79,
    0xf9,

    0x05,
    0x85,
    0x45,
    0xc5,
    0x25,
    0xa5,
    0x65,
    0xe5,
    0x15,
    0x95,
    0x55,
    0xd5,
    0x35,
    0xb5,
    0x75,
    0xf5,

    0x0d,
    0x8d,
    0x4d,
    0xcd,
    0x2d,
    0xad,
    0x6d,
    0xed,
    0x1d,
    0x9d,
    0x5d,
    0xdd,
    0x3d,
    0xbd,
    0x7d,
    0xfd,

    0x03,
    0x83,
    0x43,
    0xc3,
    0x23,
    0xa3,
    0x63,
    0xe3,
    0x13,
    0x93,
    0x53,
    0xd3,
    0x33,
    0xb3,
    0x73,
    0xf3,

    0x0b,
    0x8b,
    0x4b,
    0xcb,
    0x2b,
    0xab,
    0x6b,
    0xeb,
    0x1b,
    0x9b,
    0x5b,
    0xdb,
    0x3b,
    0xbb,
    0x7b,
    0xfb,

    0x07,
    0x87,
    0x47,
    0xc7,
    0x27,
    0xa7,
    0x67,
    0xe7,
    0x17,
    0x97,
    0x57,
    0xd7,
    0x37,
    0xb7,
    0x77,
    0xf7,

    0x0f,
    0x8f,
    0x4f,
    0xcf,
    0x2f,
    0xaf,
    0x6f,
    0xef,
    0x1f,
    0x9f,
    0x5f,
    0xdf,
    0x3f,
    0xbf,
    0x7f,
    0xff
};
