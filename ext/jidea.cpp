
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jidea.h"

#if ENABLED_IDEA_CIPHER

BlockCipher* JIDEA::getEncryptionObject()
{
  return new IDEAEncryption((byte*) itsKey.data(), itsKeylength);
}

BlockCipher* JIDEA::getDecryptionObject()
{
  return new IDEADecryption((byte*) itsKey.data(), itsKeylength);
}

#endif
