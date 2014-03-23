
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JIDEA_H__
#define __JIDEA_H__

#include "jconfig.h"

#if ENABLED_IDEA_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "idea.h"

using namespace CryptoPP;

class JIDEA : public JCipher_Template<IDEA_Info, IDEA_CIPHER>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
