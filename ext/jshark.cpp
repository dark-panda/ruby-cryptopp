
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
 */

#include "jshark.h"

#ifdef WORD64_AVAILABLE
#if ENABLED_SHARK_CIPHER

BlockCipher* JSHARK::getEncryptionObject()
{
	return new SHARKEncryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

BlockCipher* JSHARK::getDecryptionObject()
{
	return new SHARKDecryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

#endif
#endif
