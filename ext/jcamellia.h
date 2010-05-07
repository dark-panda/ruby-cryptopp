
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JCAMELLIA_H__
#define __JCAMELLIA_H__

#include "jconfig.h"

#ifdef WORD64_AVAILABLE
#if ENABLED_CAMELLIA_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "camellia.h"

using namespace CryptoPP;

class JCamellia : public JCipher_Template<Camellia_Info, CAMELLIA_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
#endif
