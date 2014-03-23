
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
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
