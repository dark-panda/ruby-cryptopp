
/*
 * Copyright (c) 2002-2013 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JDES_XEX3_H__
#define __JDES_XEX3_H__

#include "jconfig.h"

#if ENABLED_DES_XEX3_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "des.h"

using namespace CryptoPP;

class JDES_XEX3 : public JCipher_Template<DES_XEX3_Info, DES_XEX3_CIPHER>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
