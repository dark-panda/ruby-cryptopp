
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JCAST256_H__
#define __JCAST256_H__

#include "jconfig.h"

#if ENABLED_CAST256_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "cast.h"

using namespace CryptoPP;

class JCAST256 : public JCipher_Template<CAST256_Info, CAST256_CIPHER>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
