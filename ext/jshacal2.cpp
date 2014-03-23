
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#include "jshacal2.h"

#if ENABLED_SHACAL2_CIPHER

BlockCipher* JSHACAL2::getEncryptionObject()
{
  return new SHACAL2Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JSHACAL2::getDecryptionObject()
{
  return new SHACAL2Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
