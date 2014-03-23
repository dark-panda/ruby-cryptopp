
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JDIAMOND2_H__
#define __JDIAMOND2_H__

#include "jconfig.h"

#if ENABLED_DIAMOND2_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "diamond.h"

using namespace CryptoPP;

class JDiamond2 : public JCipher_Template<Diamond2_Info, DIAMOND2_CIPHER, 10, 1, INT_MAX>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
