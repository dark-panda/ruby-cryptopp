/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jsquare.h"

#if ENABLED_SQUARE_CIPHER

BlockCipher* JSquare::getEncryptionObject()
{
	return new SquareEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JSquare::getDecryptionObject()
{
	return new SquareDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
