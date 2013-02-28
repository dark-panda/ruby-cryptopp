
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JMD4_H__
#define __JMD4_H__

#include "jconfig.h"

#if ENABLED_MD4_HASH || ENABLED_MD4_HMAC

#ifndef CRYPTOPP_ENABLE_NAMESPACE_WEAK
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#endif

#if ENABLED_MD4_HASH
#include "jhash_t.h"
#endif

#if ENABLED_MD4_HMAC
#include "jhmac_t.h"
#endif

// Crypto++ headers...

#include "md4.h"

using namespace CryptoPP;

#if ENABLED_MD4_HASH
class JMD4 : public JHash_Template<Weak::MD4, MD4_HASH>
{
	public:
		JMD4(string plaintext = "") : JHash_Template<Weak::MD4, MD4_HASH>(plaintext) { }

		static string getHashName() { return "MD4"; }
};
#endif

#if ENABLED_MD4_HMAC
class JMD4_HMAC : public JHMAC_Template<Weak::MD4, MD4_HMAC>
{
	public:
		JMD4_HMAC(string plaintext = "") : JHMAC_Template<Weak::MD4, MD4_HMAC>(plaintext) { }

		static string getHashName() { return "MD4-HMAC"; }
};
#endif

#undef CRYPTOPP_ENABLE_NAMESPACE_WEAK

#endif
#endif
