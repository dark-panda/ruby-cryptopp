
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#ifndef __JSHA3_H__
#define __JSHA3_H__

#include "jconfig.h"

#define ANY_SHA3_HASH_ENABLED \
  ENABLED_SHA3_HASH || ENABLED_SHA3_224_HASH || \
  ENABLED_SHA3_256_HASH || ENABLED_SHA3_384_HASH || \
  ENABLED_SHA3_512_HASH

#define ANY_SHA3_HMAC_ENABLED\
  ENABLED_SHA3_HMAC || ENABLED_SHA3_224_HMAC || \
  ENABLED_SHA3_256_HMAC || ENABLED_SHA3_384_HMAC || \
  ENABLED_SHA3_512_HMAC

#if ANY_SHA3_HASH_ENABLED || ANY_SHA3_HMAC_ENABLED

#if ANY_SHA3_HASH_ENABLED
#include "jhash_t.h"
#endif

#if ANY_SHA3_HMAC_ENABLED
#include "jhmac_t.h"
#endif


// Crypto++ headers...

#ifdef HAVE_CRYPTOPP_SHA3_BLOCKSIZE
#include "sha3.h"
#else
#include "jsha3_blocksizes.h"
#endif

using namespace CryptoPP;

#if ENABLED_SHA3_224_HASH
class JSHA3_224 : public JHash_Template<SHA3_224, SHA3_224_HASH>
{
  public:
    JSHA3_224(string plaintext = "") : JHash_Template<SHA3_224, SHA3_224_HASH>(plaintext) { }

    static string getHashName() { return "SHA3-224"; }
};

typedef JSHA3_224 JSHA3;
#endif

#if ENABLED_SHA3_256_HASH
class JSHA3_256 : public JHash_Template<SHA3_256, SHA3_256_HASH>
{
  public:
    JSHA3_256(string plaintext = "") : JHash_Template<SHA3_256, SHA3_256_HASH>(plaintext) { }

    static string getHashName() { return "SHA-256"; }
};
#endif

#if ENABLED_SHA3_384_HASH
class JSHA3_384 : public JHash_Template<SHA3_384, SHA3_384_HASH>
{
  public:
    JSHA3_384(string plaintext = "") : JHash_Template<SHA3_384, SHA3_384_HASH>(plaintext) { }

    static string getHashName() { return "SHA-384"; }
};
#endif

#if ENABLED_SHA3_512_HASH
class JSHA3_512 : public JHash_Template<SHA3_512, SHA3_512_HASH>
{
  public:
    JSHA3_512(string plaintext = "") : JHash_Template<SHA3_512, SHA3_512_HASH>(plaintext) { }

    static string getHashName() { return "SHA-512"; }
};
#endif


#if ENABLED_SHA3_224_HMAC
class JSHA3_224_HMAC : public JHMAC_Template<SHA3_224, SHA3_224_HMAC>
{
  public:
    JSHA3_224_HMAC(string plaintext = "") : JHMAC_Template<SHA3_224, SHA3_224_HMAC>(plaintext) { }

    static string getHashName() { return "SHA-224-HMAC"; }
};

typedef JSHA3_224_HMAC JSHA3_HMAC;
#endif

#if ENABLED_SHA3_256_HMAC
class JSHA3_256_HMAC : public JHMAC_Template<SHA3_256, SHA3_256_HMAC>
{
  public:
    JSHA3_256_HMAC(string plaintext = "") : JHMAC_Template<SHA3_256, SHA3_256_HMAC>(plaintext) { }

    static string getHashName() { return "SHA-256-HMAC"; }
};
#endif

#if ENABLED_SHA3_384_HMAC
class JSHA3_384_HMAC : public JHMAC_Template<SHA3_384, SHA3_384_HMAC>
{
  public:
    JSHA3_384_HMAC(string plaintext = "") : JHMAC_Template<SHA3_384, SHA3_384_HMAC>(plaintext) { }

    static string getHashName() { return "SHA-384-HMAC"; }
};
#endif

#if ENABLED_SHA3_512_HMAC
class JSHA3_512_HMAC : public JHMAC_Template<SHA3_512, SHA3_512_HMAC>
{
  public:
    JSHA3_512_HMAC(string plaintext = "") : JHMAC_Template<SHA3_512, SHA3_512_HMAC>(plaintext) { }

    static string getHashName() { return "SHA-512-HMAC"; }
};
#endif

#endif
#endif
