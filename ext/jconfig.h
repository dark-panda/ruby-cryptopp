/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JCONFIG_H__
#define __JCONFIG_H__

// to enable or disable specific cipher algorithms,
// set these to either 1 or 0 -- 1 for enabled, 0 for
// disabled, obviously.
//
// if we have config.h, rely on that, otherwise, below
// are the defaults...

#ifdef HAVE_CONFIG_H
#include "config.h"
#else

#define ENABLED_THREEWAY_CIPHER                       1
#define ENABLED_AES_CIPHER                            1
#define ENABLED_BLOWFISH_CIPHER                       1
#define ENABLED_CAMELLIA_CIPHER                       1
#define ENABLED_CAST128_CIPHER                        1
#define ENABLED_CAST256_CIPHER                        1
#define ENABLED_DES_CIPHER                            1
#define ENABLED_DES_EDE2_CIPHER                       1
#define ENABLED_DES_EDE3_CIPHER                       1
#define ENABLED_DES_XEX3_CIPHER                       1
#define ENABLED_DIAMOND2_CIPHER                       0
#define ENABLED_DIAMOND2_LITE_CIPHER                  0
#define ENABLED_GOST_CIPHER                           1
#define ENABLED_IDEA_CIPHER                           1
#define ENABLED_MARS_CIPHER                           1
#define ENABLED_RC2_CIPHER                            1
#define ENABLED_RC5_CIPHER                            1
#define ENABLED_RC6_CIPHER                            1
#define ENABLED_SAFER_K_CIPHER                        1
#define ENABLED_SAFER_SK_CIPHER                       1
#define ENABLED_SHACAL2_CIPHER                        1
#define ENABLED_SHARK_CIPHER                          1
#define ENABLED_SERPENT_CIPHER                        1
#define ENABLED_SKIPJACK_CIPHER                       1
#define ENABLED_SQUARE_CIPHER                         1
#define ENABLED_TEA_CIPHER                            1
#define ENABLED_TWOFISH_CIPHER                        1

#define ENABLED_ARC4_CIPHER                           1
#define ENABLED_MARC4_CIPHER                          1
#define ENABLED_PANAMA_LITTLE_ENDIAN_CIPHER           1
#define ENABLED_PANAMA_BIG_ENDIAN_CIPHER              1
#define ENABLED_SEAL_LITTLE_ENDIAN_CIPHER             1
#define ENABLED_SEAL_BIG_ENDIAN_CIPHER                1

#define ENABLED_HAVAL_HASH                            0
#define ENABLED_HAVAL3_HASH                           0
#define ENABLED_HAVAL4_HASH                           0
#define ENABLED_HAVAL5_HASH                           0
#define ENABLED_MD2_HASH                              1
#define ENABLED_MD4_HASH                              1
#define ENABLED_MD5_HASH                              1
#define ENABLED_PANAMA_LITTLE_ENDIAN_HASH             1
#define ENABLED_PANAMA_BIG_ENDIAN_HASH                1
#define ENABLED_RIPEMD128_HASH                        1
#define ENABLED_RIPEMD160_HASH                        1
#define ENABLED_RIPEMD256_HASH                        1
#define ENABLED_RIPEMD320_HASH                        1
#define ENABLED_SHA1_HASH                             1
#define ENABLED_SHA256_HASH                           1
#define ENABLED_SHA384_HASH                           1
#define ENABLED_SHA512_HASH                           1
#define ENABLED_TIGER_HASH                            1
#define ENABLED_WHIRLPOOL_HASH                        1

#define ENABLED_MD2_HMAC                              1
#define ENABLED_MD4_HMAC                              1
#define ENABLED_MD5_HMAC                              1
#define ENABLED_RIPEMD128_HMAC                        1
#define ENABLED_RIPEMD160_HMAC                        1
#define ENABLED_RIPEMD256_HMAC                        1
#define ENABLED_RIPEMD320_HMAC                        1
#define ENABLED_SHA1_HMAC                             1
#define ENABLED_SHA256_HMAC                           1
#define ENABLED_SHA384_HMAC                           1
#define ENABLED_SHA512_HMAC                           1
#define ENABLED_TIGER_HMAC                            1
#define ENABLED_WHIRLPOOL_HMAC                        1

#define ENABLED_ADLER32_CHECKSUM                      1
#define ENABLED_CRC32_CHECKSUM                        1

#endif

// just to make sure SHARK and such are disabled if we don't
// have WORD64 or some version thereof...

// test if word64 is available for SHARK, SHA-384, SHA-512 and Tiger.

#if defined(__GNUC__) || defined(__MWERKS__) || defined(_MSC_VER) || defined(__BCPLUSPLUS__)
#define WORD64_AVAILABLE
#else
#undef ENABLED_CAMELLIA_CIPHER
#undef ENABLED_SHARK_CIPHER
#undef ENABLED_SHA384_HASH
#undef ENABLED_SHA512_HASH
#undef ENABLED_SHA384_HMAC
#undef ENABLED_SHA512_HMAC
#undef ENABLED_TIGER_HASH
#undef ENABLED_TIGER_HMAC
#undef ENABLED_WHIRLPOOL_HASH
#undef ENABLED_WHIRLPOOL_HMAC

#define ENABLED_CAMELLIA_CIPHER  0
#define ENABLED_SHARK_CIPHER     0
#define ENABLED_SHA384_HASH      0
#define ENABLED_SHA512_HASH      0
#define ENABLED_SHA384_HMAC      0
#define ENABLED_SHA512_HMAC      0
#define ENABLED_TIGER_HASH       0
#define ENABLED_TIGER_HMAC       0
#define ENABLED_WHIRLPOOL_HASH   0
#define ENABLED_WHIRLPOOL_HMAC   0
#endif

#endif
