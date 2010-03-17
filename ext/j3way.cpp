/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "j3way.h"

#if ENABLED_THREEWAY_CIPHER

BlockCipher* J3Way::getEncryptionObject()
{
	return new ThreeWayEncryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

BlockCipher* J3Way::getDecryptionObject()
{
	return new ThreeWayDecryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

#endif
