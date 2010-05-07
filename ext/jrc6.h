
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JRC6_H__
#define __JRC6_H__

#include "jconfig.h"

#if ENABLED_RC6_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "rc6.h"

using namespace CryptoPP;

class JRC6 : public JCipher_Template<RC6_Info, RC6_CIPHER, 20, 1, INT_MAX>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
