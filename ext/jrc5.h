
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JRC5_H__
#define __JRC5_H__

#include "jconfig.h"

#if ENABLED_RC5_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "rc5.h"

using namespace CryptoPP;

class JRC5 : public JCipher_Template<RC5_Info, RC5_CIPHER, 16, 1, INT_MAX>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
