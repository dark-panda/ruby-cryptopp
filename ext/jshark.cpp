/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
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
