/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jgost.h"

#if ENABLED_GOST_CIPHER

BlockCipher* JGOST::getEncryptionObject()
{
	return new GOSTEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JGOST::getDecryptionObject()
{
	return new GOSTDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
