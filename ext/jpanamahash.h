
/*
 * Copyright (c) 2002-2014 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2013 Wei Dai
 * See MIT-LICENSE for the extact license
 */

#ifndef __JPANAMAHASH_H__
#define __JPANAMAHASH_H__

#include "jconfig.h"

#if ENABLED_PANAMA_LITTLE_ENDIAN_HASH || ENABLED_PANAMA_BIG_ENDIAN_HASH

#include "jhash_t.h"

// Crypto++ headers...

#include "panama.h"

using namespace CryptoPP;

#if ENABLED_PANAMA_LITTLE_ENDIAN_HASH
class JPanamaHashLE : public JHash_Template<Weak::PanamaHash<LittleEndian>, PANAMA_LITTLE_ENDIAN_HASH>
{
  public:
    JPanamaHashLE(string plaintext = "") : JHash_Template<Weak::PanamaHash<LittleEndian>, PANAMA_LITTLE_ENDIAN_HASH>(plaintext) { }

    static string getHashName() { return "Panama-LE Hash"; }
};
#endif

#if ENABLED_PANAMA_BIG_ENDIAN_HASH
class JPanamaHashBE : public JHash_Template<Weak::PanamaHash<BigEndian>, PANAMA_BIG_ENDIAN_HASH>
{
  public:
    JPanamaHashBE(string plaintext = "") : JHash_Template<Weak::PanamaHash<BigEndian>, PANAMA_BIG_ENDIAN_HASH>(plaintext) { }

    static string getHashName() { return "Panama-BE Hash"; }
};
#endif

#endif
#endif
