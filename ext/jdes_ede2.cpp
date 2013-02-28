
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jdes_ede2.h"

#if ENABLED_DES_EDE2_CIPHER

BlockCipher* JDES_EDE2::getEncryptionObject()
{
	return new DES_EDE2_Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JDES_EDE2::getDecryptionObject()
{
	return new DES_EDE2_Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
