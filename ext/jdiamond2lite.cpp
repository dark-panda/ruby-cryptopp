/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jdiamond2lite.h"

#if ENABLED_DIAMOND2_LITE_CIPHER

BlockCipher* JDiamond2Lite::getEncryptionObject()
{
	return new Diamond2LiteEncryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

BlockCipher* JDiamond2Lite::getDecryptionObject()
{
	return new Diamond2LiteDecryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

#endif
