
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JRIPEMD160_H__
#define __JRIPEMD160_H__

#include "jconfig.h"

#if ENABLED_RIPEMD128_HASH || ENABLED_RIPEMD160_HASH || ENABLED_RIPEMD256_HASH || ENABLED_RIPEMD320_HASH || \
  ENABLED_RIPEMD128_HMAC || ENABLED_RIPEMD160_HMAC || ENABLED_RIPEMD256_HMAC || ENABLED_RIPEMD320_HMAC

#if ENABLED_RIPEMD128_HASH || ENABLED_RIPEMD160_HASH || ENABLED_RIPEMD256_HASH || ENABLED_RIPEMD320_HASH
#include "jhash_t.h"
#endif

#if ENABLED_RIPEMD128_HMAC || ENABLED_RIPEMD160_HMAC || ENABLED_RIPEMD256_HMAC || ENABLED_RIPEMD320_HMAC
#include "jhmac_t.h"
#endif

// Crypto++ headers...

#include "ripemd.h"

using namespace CryptoPP;

#if ENABLED_RIPEMD128_HASH
class JRIPEMD128 : public JHash_Template<RIPEMD128, RIPEMD128_HASH>
{
  public:
    JRIPEMD128(string plaintext = "") : JHash_Template<RIPEMD128, RIPEMD128_HASH>(plaintext) { }

    static string getHashName() { return "RIPEMD-128"; }
};
#endif

#if ENABLED_RIPEMD160_HASH
class JRIPEMD160 : public JHash_Template<RIPEMD160, RIPEMD160_HASH>
{
  public:
    JRIPEMD160(string plaintext = "") : JHash_Template<RIPEMD160, RIPEMD160_HASH>(plaintext) { }

    static string getHashName() { return "RIPEMD-160"; }
};
#endif

#if ENABLED_RIPEMD256_HASH
class JRIPEMD256 : public JHash_Template<RIPEMD256, RIPEMD256_HASH>
{
  public:
    JRIPEMD256(string plaintext = "") : JHash_Template<RIPEMD256, RIPEMD256_HASH>(plaintext) { }

    static string getHashName() { return "RIPEMD-256"; }
};
#endif

#if ENABLED_RIPEMD320_HASH
class JRIPEMD320 : public JHash_Template<RIPEMD320, RIPEMD320_HASH>
{
  public:
    JRIPEMD320(string plaintext = "") : JHash_Template<RIPEMD320, RIPEMD320_HASH>(plaintext) { }

    static string getHashName() { return "RIPEMD-320"; }
};
#endif



#if ENABLED_RIPEMD128_HMAC
class JRIPEMD128_HMAC : public JHMAC_Template<RIPEMD128, RIPEMD128_HMAC>
{
  public:
    JRIPEMD128_HMAC(string plaintext = "") : JHMAC_Template<RIPEMD128, RIPEMD128_HMAC>(plaintext) { }

    static string getHashName() { return "RIPEMD-128-HMAC"; }
};
#endif

#if ENABLED_RIPEMD160_HMAC
class JRIPEMD160_HMAC : public JHMAC_Template<RIPEMD160, RIPEMD160_HMAC>
{
  public:
    JRIPEMD160_HMAC(string plaintext = "") : JHMAC_Template<RIPEMD160, RIPEMD160_HMAC>(plaintext) { }

    static string getHashName() { return "RIPEMD-160-HMAC"; }
};
#endif

#if ENABLED_RIPEMD256_HMAC
class JRIPEMD256_HMAC : public JHMAC_Template<RIPEMD256, RIPEMD256_HMAC>
{
  public:
    JRIPEMD256_HMAC(string plaintext = "") : JHMAC_Template<RIPEMD256, RIPEMD256_HMAC>(plaintext) { }

    static string getHashName() { return "RIPEMD-256-HMAC"; }
};
#endif

#if ENABLED_RIPEMD320_HMAC
class JRIPEMD320_HMAC : public JHMAC_Template<RIPEMD320, RIPEMD320_HMAC>
{
  public:
    JRIPEMD320_HMAC(string plaintext = "") : JHMAC_Template<RIPEMD320, RIPEMD320_HMAC>(plaintext) { }

    static string getHashName() { return "RIPEMD-320-HMAC"; }
};
#endif

#endif
#endif
