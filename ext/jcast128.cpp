/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jcast128.h"

#if ENABLED_CAST128_CIPHER

BlockCipher* JCAST128::getEncryptionObject()
{
	return new CAST128Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JCAST128::getDecryptionObject()
{
	return new CAST128Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
