
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jdiamond2.h"

#if ENABLED_DIAMOND2_CIPHER

BlockCipher* JDiamond2::getEncryptionObject()
{
  return new Diamond2Encryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

BlockCipher* JDiamond2::getDecryptionObject()
{
  return new Diamond2Decryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

#endif
