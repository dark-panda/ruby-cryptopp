/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jaes.h"

#if ENABLED_AES_CIPHER

BlockCipher* JAES::getEncryptionObject()
{
	return new AESEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JAES::getDecryptionObject()
{
	return new AESDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
