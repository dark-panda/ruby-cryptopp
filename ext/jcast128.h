
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#ifndef __JCAST128_H__
#define __JCAST128_H__

#include "jconfig.h"

#if ENABLED_CAST128_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "cast.h"

using namespace CryptoPP;

class JCAST128 : public JCipher_Template<CAST128_Info, CAST128_CIPHER>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
