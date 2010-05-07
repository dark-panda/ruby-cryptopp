
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
 */

#include "jcamellia.h"

#ifdef WORD64_AVAILABLE
#if ENABLED_CAMELLIA_CIPHER

BlockCipher* JCamellia::getEncryptionObject()
{
	return new CamelliaEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JCamellia::getDecryptionObject()
{
	return new CamelliaDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
#endif
