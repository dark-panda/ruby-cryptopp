/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#include "jseal.h"

#if ENABLED_SEAL_LITTLE_ENDIAN_CIPHER
SymmetricCipher* JSEAL_LE::getEncryptionObject()
{
	return new SEAL<LittleEndian>::Encryption((byte*) itsKey.data(), itsKeylength, (byte*) itsIV.data());
}

SymmetricCipher* JSEAL_LE::getDecryptionObject()
{
	return getEncryptionObject();
}
#endif

#if ENABLED_SEAL_BIG_ENDIAN_CIPHER
SymmetricCipher* JSEAL_BE::getEncryptionObject()
{
	return new SEAL<BigEndian>::Encryption((byte*) itsKey.data(), itsKeylength, (byte*) itsIV.data());
}

SymmetricCipher* JSEAL_BE::getDecryptionObject()
{
	return getEncryptionObject();
}
#endif
