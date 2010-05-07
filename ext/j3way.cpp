
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
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
