
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JBLOWFISH_H__
#define __JBLOWFISH_H__

#include "jconfig.h"

#if ENABLED_BLOWFISH_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "blowfish.h"

class JBlowfish : public JCipher_Template<Blowfish_Info, BLOWFISH_CIPHER>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
