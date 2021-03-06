
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#include "jrc6.h"

#if ENABLED_RC6_CIPHER

BlockCipher* JRC6::getEncryptionObject()
{
  return new RC6Encryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JRC6::getDecryptionObject()
{
  return new RC6Decryption((byte*) itsKey.data(), itsKeylength);
}

#endif
