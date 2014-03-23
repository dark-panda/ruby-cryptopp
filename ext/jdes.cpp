
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#include "jdes.h"

#if ENABLED_DES_CIPHER

BlockCipher* JDES::getEncryptionObject()
{
  return new DESEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JDES::getDecryptionObject()
{
  return new DESDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
