
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JTIGER_H__
#define __JTIGER_H__

#include "jconfig.h"

#ifdef WORD64_AVAILABLE
#if ENABLED_TIGER_HASH || ENABLED_TIGER_HMAC

#if ENABLED_TIGER_HASH
#include "jhash_t.h"
#endif

#if ENABLED_TIGER_HMAC
#include "jhmac_t.h"
#endif

// Crypto++ headers...

#include "tiger.h"

using namespace CryptoPP;

#if ENABLED_TIGER_HASH
class JTiger : public JHash_Template<Tiger, TIGER_HASH>
{
  public:
    JTiger(string plaintext = "") : JHash_Template<Tiger, TIGER_HASH>(plaintext) { }

    static string getHashName() { return "Tiger"; }
};
#endif

#if ENABLED_TIGER_HMAC
class JTiger_HMAC : public JHMAC_Template<Tiger, TIGER_HMAC>
{
  public:
    JTiger_HMAC(string plaintext = "") : JHMAC_Template<Tiger, TIGER_HMAC>(plaintext) { }

    static string getHashName() { return "Tiger HMAC"; }
};
#endif

#endif
#endif
#endif
