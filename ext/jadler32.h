/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
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
