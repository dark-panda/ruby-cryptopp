/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jtea.h"

#if ENABLED_TEA_CIPHER

BlockCipher* JTEA::getEncryptionObject()
{
	return new TEAEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JTEA::getDecryptionObject()
{
	return new TEADecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
