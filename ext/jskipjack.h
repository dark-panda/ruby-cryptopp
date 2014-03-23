
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JSKIPJACK_H__
#define __JSKIPJACK_H__

#include "jconfig.h"

#if ENABLED_SKIPJACK_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "skipjack.h"

using namespace CryptoPP;

class JSKIPJACK : public JCipher_Template<SKIPJACK_Info, SKIPJACK_CIPHER>
{
  protected:
    BlockCipher* getEncryptionObject();
    BlockCipher* getDecryptionObject();
};

#endif
#endif
