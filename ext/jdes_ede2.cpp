/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jdes_ede2.h"

#if ENABLED_DES_EDE2_CIPHER

BlockCipher* JDES_EDE2::getEncryptionObject()
{
	return new DES_EDE2_Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JDES_EDE2::getDecryptionObject()
{
	return new DES_EDE2_Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
