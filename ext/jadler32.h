
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JADLER32_H__
#define __JADLER32_H__

#include "jconfig.h"

#if ENABLED_ADLER32_CHECKSUM

#include "jhash_t.h"

// Crypto++ headers...

#include "adler32.h"

using namespace CryptoPP;

class JAdler32 : public JHash_Template<Adler32, ADLER32_CHECKSUM>
{
	public:
		JAdler32(string plaintext = "") : JHash_Template<Adler32, ADLER32_CHECKSUM>(plaintext) { }

		static string getHashName() { return "Adler32"; }
};

#endif
#endif
