/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JSERPENT_H__
#define __JSERPENT_H__

#include "jconfig.h"

#if ENABLED_SERPENT_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "serpent.h"

using namespace CryptoPP;

class JSerpent : public JCipher_Template<Serpent_Info, SERPENT_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
