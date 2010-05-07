
/*
 * Copyright (c) 2002-2010 J Smith <dark.panda@gmail.com>
 * Crypto++ copyright (c) 1995-2010 Wei Dai
 * See COPYING for the extact license
 */

#ifndef __JPANAMACIPHER_H__
#define __JPANAMACIPHER_H__

#include "jconfig.h"

#if ENABLED_PANAMA_LITTLE_ENDIAN_CIPHER || ENABLED_PANAMA_BIG_ENDIAN_CIPHER

#include "jstream_t.h"

// Crypto++ headers...

#include "panama.h"

using namespace CryptoPP;

#if ENABLED_PANAMA_LITTLE_ENDIAN_CIPHER
class JPanamaCipherLE : public JStream_Template<PanamaCipherInfo<LittleEndian>, PANAMA_LITTLE_ENDIAN_CIPHER>
{
	protected:
		SymmetricCipher* getEncryptionObject();
		SymmetricCipher* getDecryptionObject();
};

typedef JPanamaCipherLE JPanamaLittleEndianCipher;
#endif

#if ENABLED_PANAMA_BIG_ENDIAN_CIPHER
class JPanamaCipherBE : public JStream_Template<PanamaCipherInfo<BigEndian>, PANAMA_BIG_ENDIAN_CIPHER>
{
	 protected:
		SymmetricCipher* getEncryptionObject();
		SymmetricCipher* getDecryptionObject();
};

typedef JPanamaCipherBE JPanamaBigEndianCipher;
#endif

#endif
#endif
