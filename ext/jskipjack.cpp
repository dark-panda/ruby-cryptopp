
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#include "jskipjack.h"

#if ENABLED_SKIPJACK_CIPHER

BlockCipher* JSKIPJACK::getEncryptionObject()
{
  return new SKIPJACKEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JSKIPJACK::getDecryptionObject()
{
  return new SKIPJACKDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
