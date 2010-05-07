
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
 */

#include "jrc6.h"

#if ENABLED_RC6_CIPHER

BlockCipher* JRC6::getEncryptionObject()
{
	return new RC6Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JRC6::getDecryptionObject()
{
	return new RC6Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
