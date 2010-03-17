/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
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
