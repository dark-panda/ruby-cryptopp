
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
 */

#include "jblowfish.h"

#if ENABLED_BLOWFISH_CIPHER

BlockCipher* JBlowfish::getEncryptionObject()
{
	return new BlowfishEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JBlowfish::getDecryptionObject()
{
	return new BlowfishDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
