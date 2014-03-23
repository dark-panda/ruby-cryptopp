
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jrc5.h"

#if ENABLED_RC5_CIPHER

BlockCipher* JRC5::getEncryptionObject()
{
  return new RC5Encryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

BlockCipher* JRC5::getDecryptionObject()
{
  return new RC5Decryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

#endif
