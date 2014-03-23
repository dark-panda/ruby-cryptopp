
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#include "jrc2.h"

#if ENABLED_RC2_CIPHER

JRC2::JRC2()
{
  itsEffectiveKeylength = RC2_Info::DEFAULT_EFFECTIVE_KEYLENGTH;
}

unsigned int JRC2::setEffectiveKeylength(const unsigned int keylength)
{
  if (keylength > RC2_Info::MAX_EFFECTIVE_KEYLENGTH) {
    itsEffectiveKeylength = RC2_Info::MAX_EFFECTIVE_KEYLENGTH;
  }
  else {
    itsEffectiveKeylength = keylength;
  }

  return itsEffectiveKeylength;
}

unsigned int JRC2::getEffectiveKeylength() const
{
  return itsEffectiveKeylength;
}

BlockCipher* JRC2::getEncryptionObject()
{
  return new RC2Encryption((byte*) itsKey.data(), itsKeylength, itsEffectiveKeylength);
}

BlockCipher* JRC2::getDecryptionObject()
{
  return new RC2Decryption((byte*) itsKey.data(), itsKeylength, itsEffectiveKeylength);
}

#endif
