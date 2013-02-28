
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JSQUARE_H__
#define __JSQUARE_H__

#include "jconfig.h"

#if ENABLED_SQUARE_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "square.h"

using namespace CryptoPP;

class JSquare : public JCipher_Template<Square_Info, SQUARE_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
