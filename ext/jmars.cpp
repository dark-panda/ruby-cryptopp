
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#include "jmars.h"

#if ENABLED_MARS_CIPHER

BlockCipher* JMARS::getEncryptionObject()
{
  return new MARSEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JMARS::getDecryptionObject()
{
  return new MARSDecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
