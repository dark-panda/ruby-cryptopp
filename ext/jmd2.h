
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JMD2_H__
#define __JMD2_H__

#include "jconfig.h"

#if ENABLED_MD2_HASH || ENABLED_MD2_HMAC

#ifndef CRYPTOPP_ENABLE_NAMESPACE_WEAK
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#endif

#if ENABLED_MD2_HASH
#include "jhash_t.h"
#endif

#if ENABLED_MD2_HMAC
#include "jhmac_t.h"
#endif

// Crypto++ headers...

#include "md2.h"

using namespace CryptoPP;

#if ENABLED_MD2_HASH
class JMD2 : public JHash_Template<Weak::MD2, MD2_HASH>
{
  public:
    JMD2(string plaintext = "") : JHash_Template<Weak::MD2, MD2_HASH>(plaintext) { }

    static string getHashName() { return "MD2"; }
};
#endif

#if ENABLED_MD5_HMAC
class JMD2_HMAC : public JHMAC_Template<Weak::MD2, MD2_HMAC>
{
  public:
    JMD2_HMAC(string plaintext = "") : JHMAC_Template<Weak::MD2, MD2_HMAC>(plaintext) { }

    static string getHashName() { return "MD2-HMAC"; }
};
#endif

#undef CRYPTOPP_ENABLE_NAMESPACE_WEAK

#endif
#endif
