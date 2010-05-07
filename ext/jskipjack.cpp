
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
 */

#include "jskipjack.h"

#if ENABLED_SKIPJACK_CIPHER

BlockCipher* JSKIPJACK::getEncryptionObject()
{
	return new SKIPJACKEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JSKIPJACK::getDecryptionObject()
{
	return new SKIPJACKDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
