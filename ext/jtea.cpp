
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#include "jtea.h"

#if ENABLED_TEA_CIPHER

BlockCipher* JTEA::getEncryptionObject()
{
  return new TEAEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JTEA::getDecryptionObject()
{
  return new TEADecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
