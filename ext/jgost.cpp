
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
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
