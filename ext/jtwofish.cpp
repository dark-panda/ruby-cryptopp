/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jtwofish.h"

#if ENABLED_TWOFISH_CIPHER

BlockCipher* JTwofish::getEncryptionObject()
{
	return new TwofishEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JTwofish::getDecryptionObject()
{
	return new TwofishDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
