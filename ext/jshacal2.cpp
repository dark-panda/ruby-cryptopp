/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jshacal2.h"

#if ENABLED_SHACAL2_CIPHER

BlockCipher* JSHACAL2::getEncryptionObject()
{
	return new SHACAL2Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JSHACAL2::getDecryptionObject()
{
	return new SHACAL2Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
