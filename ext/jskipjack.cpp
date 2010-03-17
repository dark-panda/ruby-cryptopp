/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jskipjack.h"

#if ENABLED_SKIPJACK_CIPHER

BlockCipher* JSKIPJACK::getEncryptionObject()
{
	return new SKIPJACKEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JSKIPJACK::getDecryptionObject()
{
	return new SKIPJACKDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
