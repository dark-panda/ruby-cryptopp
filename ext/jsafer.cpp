
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jsafer.h"

#if ENABLED_SAFER_K_CIPHER
BlockCipher* JSAFER_K::getEncryptionObject()
{
  return new SAFER_K_Encryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

BlockCipher* JSAFER_K::getDecryptionObject()
{
  return new SAFER_K_Decryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}
#endif

#if ENABLED_SAFER_SK_CIPHER
BlockCipher* JSAFER_SK::getEncryptionObject()
{
  return new SAFER_SK_Encryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

BlockCipher* JSAFER_SK::getDecryptionObject()
{
  return new SAFER_SK_Decryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}
#endif
