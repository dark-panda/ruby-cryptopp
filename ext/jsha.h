
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JSHA_H__
#define __JSHA_H__

#include "jconfig.h"

#if ENABLED_SHA1_HASH || ENABLED_SHA256_HASH || (defined(WORD64_AVAILABLE) && (ENABLED_SHA384_HASH || ENABLED_SHA512_HASH)) || \
    ENABLED_SHA1_HMAC || ENABLED_SHA256_HMAC || (defined(WORD64_AVAILABLE) && (ENABLED_SHA384_HMAC || ENABLED_SHA512_HMAC))

#if ENABLED_SHA1_HASH || ENABLED_SHA256_HASH || (defined(WORD64_AVAILABLE) && (ENABLED_SHA384_HASH || ENABLED_SHA512_HASH))
#include "jhash_t.h"
#endif

#if ENABLED_SHA1_HMAC || ENABLED_SHA256_HMAC || (defined(WORD64_AVAILABLE) && (ENABLED_SHA384_HMAC || ENABLED_SHA512_HMAC))
#include "jhmac_t.h"
#endif


// Crypto++ headers...

#include "sha.h"

using namespace CryptoPP;

#if ENABLED_SHA1_HASH
class JSHA1 : public JHash_Template<SHA1, SHA1_HASH>
{
  public:
    JSHA1(string plaintext = "") : JHash_Template<SHA1, SHA1_HASH>(plaintext) { }

    static string getHashName() { return "SHA1"; }
};

typedef JSHA1 JSHA;
#endif

#if ENABLED_SHA256_HASH
class JSHA256 : public JHash_Template<SHA256, SHA256_HASH>
{
  public:
    JSHA256(string plaintext = "") : JHash_Template<SHA256, SHA256_HASH>(plaintext) { }

    static string getHashName() { return "SHA-256"; }
};
#endif

#ifdef WORD64_AVAILABLE
#if ENABLED_SHA384_HASH
class JSHA384 : public JHash_Template<SHA384, SHA384_HASH>
{
  public:
    JSHA384(string plaintext = "") : JHash_Template<SHA384, SHA384_HASH>(plaintext) { }

    static string getHashName() { return "SHA-384"; }
};
#endif

#if ENABLED_SHA512_HASH
class JSHA512 : public JHash_Template<SHA512, SHA512_HASH>
{
  public:
    JSHA512(string plaintext = "") : JHash_Template<SHA512, SHA512_HASH>(plaintext) { }

    static string getHashName() { return "SHA-512"; }
};
#endif
#endif


#if ENABLED_SHA1_HMAC
class JSHA1_HMAC : public JHMAC_Template<SHA1, SHA1_HMAC>
{
  public:
    JSHA1_HMAC(string plaintext = "") : JHMAC_Template<SHA1, SHA1_HMAC>(plaintext) { }

    static string getHashName() { return "SHA1-HMAC"; }
};

typedef JSHA1_HMAC JSHA_HMAC;
#endif

#if ENABLED_SHA256_HMAC
class JSHA256_HMAC : public JHMAC_Template<SHA256, SHA256_HMAC>
{
  public:
    JSHA256_HMAC(string plaintext = "") : JHMAC_Template<SHA256, SHA256_HMAC>(plaintext) { }

    static string getHashName() { return "SHA-256-HMAC"; }
};
#endif

#ifdef WORD64_AVAILABLE
#if ENABLED_SHA384_HMAC
class JSHA384_HMAC : public JHMAC_Template<SHA384, SHA384_HMAC>
{
  public:
    JSHA384_HMAC(string plaintext = "") : JHMAC_Template<SHA384, SHA384_HMAC>(plaintext) { }

    static string getHashName() { return "SHA-384-HMAC"; }
};
#endif

#if ENABLED_SHA512_HMAC
class JSHA512_HMAC : public JHMAC_Template<SHA512, SHA512_HMAC>
{
  public:
    JSHA512_HMAC(string plaintext = "") : JHMAC_Template<SHA512, SHA512_HMAC>(plaintext) { }

    static string getHashName() { return "SHA-512-HMAC"; }
};
#endif
#endif


#endif
#endif
