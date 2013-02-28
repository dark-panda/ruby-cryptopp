
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jserpent.h"

#if ENABLED_SERPENT_CIPHER

BlockCipher* JSerpent::getEncryptionObject()
{
	return new SerpentEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JSerpent::getDecryptionObject()
{
	return new SerpentDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
