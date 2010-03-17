/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jrc5.h"

#if ENABLED_RC5_CIPHER

BlockCipher* JRC5::getEncryptionObject()
{
	return new RC5Encryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

BlockCipher* JRC5::getDecryptionObject()
{
	return new RC5Decryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

#endif
