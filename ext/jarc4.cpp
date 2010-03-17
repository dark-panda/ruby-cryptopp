/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jarc4.h"

#if ENABLED_ARC4_CIPHER

SymmetricCipher* JARC4::getEncryptionObject()
{
	return new Weak::ARC4((byte*) itsKey.data(), itsKeylength);
}

SymmetricCipher* JARC4::getDecryptionObject()
{
	return getEncryptionObject();
}

#endif
