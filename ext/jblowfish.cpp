/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
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
