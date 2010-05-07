
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JCRC32_H__
#define __JCRC32_H__

#include "jconfig.h"

#if ENABLED_CRC32_CHECKSUM

#include "jhash_t.h"

// Crypto++ headers...

#include "crc.h"

using namespace CryptoPP;

class JCRC32 : public JHash_Template<CRC32, CRC32_CHECKSUM>
{
	public:
		JCRC32(string plaintext = "") : JHash_Template<CRC32, CRC32_CHECKSUM>(plaintext) { }

		static string getHashName() { return "CRC32"; }
};

#endif
#endif
