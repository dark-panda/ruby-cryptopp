/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jserpent.h"

#if ENABLED_SERPENT_CIPHER

BlockCipher* JSerpent::getEncryptionObject()
{
	return new SerpentEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JSerpent::getDecryptionObject()
{
	return new SerpentDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
