/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jmars.h"

#if ENABLED_MARS_CIPHER

BlockCipher* JMARS::getEncryptionObject()
{
	return new MARSEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JMARS::getDecryptionObject()
{
	return new MARSDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
