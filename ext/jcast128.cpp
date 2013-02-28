
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jcast128.h"

#if ENABLED_CAST128_CIPHER

BlockCipher* JCAST128::getEncryptionObject()
{
  return new CAST128Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JCAST128::getDecryptionObject()
{
  return new CAST128Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
