/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jdes_xex3.h"

#if ENABLED_DES_XEX3_CIPHER

BlockCipher* JDES_XEX3::getEncryptionObject()
{
	return new DES_XEX3_Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JDES_XEX3::getDecryptionObject()
{
	return new DES_XEX3_Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
