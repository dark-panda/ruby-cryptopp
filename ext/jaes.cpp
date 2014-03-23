
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#include "jaes.h"

#if ENABLED_AES_CIPHER

BlockCipher* JAES::getEncryptionObject()
{
  return new AESEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JAES::getDecryptionObject()
{
  return new AESDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
