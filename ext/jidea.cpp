/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jidea.h"

#if ENABLED_IDEA_CIPHER

BlockCipher* JIDEA::getEncryptionObject()
{
	return new IDEAEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JIDEA::getDecryptionObject()
{
	return new IDEADecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
