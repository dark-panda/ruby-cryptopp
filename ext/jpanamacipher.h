/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
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
