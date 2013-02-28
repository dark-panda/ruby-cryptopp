
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JDES_EDE2_H__
#define __JDES_EDE2_H__

#include "jconfig.h"

#if ENABLED_DES_EDE2_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "des.h"

using namespace CryptoPP;

class JDES_EDE2 : public JCipher_Template<DES_EDE2_Info, DES_EDE2_CIPHER>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
