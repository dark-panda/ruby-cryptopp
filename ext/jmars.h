
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JMARS_H__
#define __JMARS_H__

#include "jconfig.h"

#if ENABLED_MARS_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "mars.h"

using namespace CryptoPP;

class JMARS : public JCipher_Template<MARS_Info, MARS_CIPHER>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
