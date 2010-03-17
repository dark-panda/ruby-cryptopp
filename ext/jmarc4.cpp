/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jmarc4.h"

#if ENABLED_MARC4_CIPHER

SymmetricCipher* JMARC4::getEncryptionObject()
{
	return new Weak::MARC4((byte*) itsKey.data(), itsKeylength);
}

SymmetricCipher* JMARC4::getDecryptionObject()
{
	return getEncryptionObject();
}

#endif
