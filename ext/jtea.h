
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JTEA_H__
#define __JTEA_H__

#include "jconfig.h"

#if ENABLED_TEA_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "tea.h"

using namespace CryptoPP;

class JTEA : public JCipher_Template<TEA_Info, TEA_CIPHER>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
