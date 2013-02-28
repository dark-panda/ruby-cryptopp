
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JAES_H__
#define __JAES_H__

#include "jconfig.h"

#if ENABLED_AES_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "aes.h"

class JAES : public JCipher_Template<Rijndael_Info, AES_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

typedef JAES JRijndael;

#endif
#endif
