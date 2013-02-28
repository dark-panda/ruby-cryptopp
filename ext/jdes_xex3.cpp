
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jdes_xex3.h"

#if ENABLED_DES_XEX3_CIPHER

BlockCipher* JDES_XEX3::getEncryptionObject()
{
  return new DES_XEX3_Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JDES_XEX3::getDecryptionObject()
{
  return new DES_XEX3_Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
