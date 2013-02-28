
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
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
