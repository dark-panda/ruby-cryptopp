
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JTWOFISH_H__
#define __JTWOFISH_H__

#include "jconfig.h"

#if ENABLED_TWOFISH_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "twofish.h"

using namespace CryptoPP;

class JTwofish : public JCipher_Template<Twofish_Info, TWOFISH_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
