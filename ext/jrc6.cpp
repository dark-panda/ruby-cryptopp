/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jrc6.h"

#if ENABLED_RC6_CIPHER

BlockCipher* JRC6::getEncryptionObject()
{
	return new RC6Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JRC6::getDecryptionObject()
{
	return new RC6Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
