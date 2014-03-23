
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jsquare.h"

#if ENABLED_SQUARE_CIPHER

BlockCipher* JSquare::getEncryptionObject()
{
  return new SquareEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JSquare::getDecryptionObject()
{
  return new SquareDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
