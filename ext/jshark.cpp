
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#include "jshark.h"

#if ENABLED_SHARK_CIPHER

BlockCipher* JSHARK::getEncryptionObject()
{
  return new SHARKEncryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

BlockCipher* JSHARK::getDecryptionObject()
{
  return new SHARKDecryption((byte*) itsKey.data(), itsKeylength, itsRounds);
}

#endif
