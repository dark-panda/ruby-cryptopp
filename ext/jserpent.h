
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JSERPENT_H__
#define __JSERPENT_H__

#include "jconfig.h"

#if ENABLED_SERPENT_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "serpent.h"

using namespace CryptoPP;

class JSerpent : public JCipher_Template<Serpent_Info, SERPENT_CIPHER>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
