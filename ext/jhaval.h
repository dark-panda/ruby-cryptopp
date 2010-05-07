
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JHAVAL_H__
#define __JHAVAL_H__

#include "jconfig.h"

#if ENABLED_HAVAL_HASH || ENABLED_HAVAL3_HASH || ENABLED_HAVAL4_HASH || ENABLED_HAVAL5_HASH

#include "jhash_t.h"

// Crypto++ headers...

#include "haval.h"

using namespace CryptoPP;

#if ENABLED_HAVAL_HASH
class JHAVAL : public JHash_Template<HAVAL, HAVAL_HASH>
{
	public:
		JHAVAL(string plaintext = "") : JHash_Template<HAVAL, HAVAL_HASH>(plaintext) { }

		static string getHashName() { return "HAVAL"; }
};
#endif

#if ENABLED_HAVAL3_HASH
class JHAVAL3 : public JHash_Template<HAVAL3, HAVAL3_HASH>
{
	public:
		JHAVAL3(string plaintext = "") : JHash_Template<HAVAL3, HAVAL3_HASH>(plaintext) { }

		static string getHashName() { return "HAVAL3"; }
};
#endif

#if ENABLED_HAVAL4_HASH
class JHAVAL4 : public JHash_Template<HAVAL4, HAVAL4_HASH>
{
	public:
		JHAVAL4(string plaintext = "") : JHash_Template<HAVAL4, HAVAL4_HASH>(plaintext) { }

		static string getHashName() { return "HAVAL4"; }
};
#endif

#if ENABLED_HAVAL5_HASH
class JHAVAL5 : public JHash_Template<HAVAL5, HAVAL5_HASH>
{
	public:
		JHAVAL5(string plaintext = "") : JHash_Template<HAVAL5, HAVAL5_HASH>(plaintext) { }

		static string getHashName() { return "HAVAL5"; }
};
#endif

#endif
#endif
