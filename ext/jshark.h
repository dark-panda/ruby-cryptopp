
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JSHARK_H__
#define __JSHARK_H__

#include "jconfig.h"

#if ENABLED_SHARK_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "shark.h"

using namespace CryptoPP;

class JSHARK : public JCipher_Template<SHARK_Info, SHARK_CIPHER, 6, 2, INT_MAX>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
