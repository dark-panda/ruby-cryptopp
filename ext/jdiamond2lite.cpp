
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jdiamond2lite.h"

#if ENABLED_DIAMOND2_LITE_CIPHER

BlockCipher* JDiamond2Lite::getEncryptionObject()
{
  return new Diamond2LiteEncryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

BlockCipher* JDiamond2Lite::getDecryptionObject()
{
  return new Diamond2LiteDecryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

#endif
