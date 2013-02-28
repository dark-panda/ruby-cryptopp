
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __J3WAY_H__
#define __J3WAY_H__

#include "jconfig.h"

#if ENABLED_THREEWAY_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "3way.h"

class J3Way : public JCipher_Template<ThreeWay_Info, THREEWAY_CIPHER, 11, 1, INT_MAX>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
