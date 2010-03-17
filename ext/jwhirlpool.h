/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JWHIRLPOOL_H__
#define __JWHIRLPOOL_H__

#include "jconfig.h"

#ifdef WORD64_AVAILABLE
#if ENABLED_WHIRLPOOL_HASH || ENABLED_WHIRLPOOL_HMAC

#if ENABLED_WHIRLPOOL_HASH
#include "jhash_t.h"
#endif

#if ENABLED_WHIRLPOOL_HMAC
#include "jhmac_t.h"
#endif

// Crypto++ headers...

#include "whrlpool.h"

using namespace CryptoPP;

#if ENABLED_WHIRLPOOL_HASH
class JWhirlpool : public JHash_Template<Whirlpool, WHIRLPOOL_HASH>
{
	public:
		JWhirlpool(string plaintext = "") : JHash_Template<Whirlpool, WHIRLPOOL_HASH>(plaintext) { }

		static string getHashName() { return "Whirlpool"; }
};
#endif

#if ENABLED_WHIRLPOOL_HMAC
class JWhirlpool_HMAC : public JHMAC_Template<Whirlpool, WHIRLPOOL_HMAC>
{
	public:
		JWhirlpool_HMAC(string plaintext = "") : JHMAC_Template<Whirlpool, WHIRLPOOL_HMAC>(plaintext) { }

		static string getHashName() { return "Whirlpool-HMAC"; }
};
#endif

#endif
#endif
#endif
