
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jcast256.h"

#if ENABLED_CAST256_CIPHER

BlockCipher* JCAST256::getEncryptionObject()
{
  return new CAST256Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JCAST256::getDecryptionObject()
{
  return new CAST256Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
