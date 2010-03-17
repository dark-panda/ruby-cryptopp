/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jcast256.h"

#if ENABLED_CAST256_CIPHER

BlockCipher* JCAST256::getEncryptionObject()
{
	return new CAST256Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JCAST256::getDecryptionObject()
{
	return new CAST256Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
