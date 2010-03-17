/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JCAST128_H__
#define __JCAST128_H__

#include "jconfig.h"

#if ENABLED_CAST128_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "cast.h"

using namespace CryptoPP;

class JCAST128 : public JCipher_Template<CAST128_Info, CAST128_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
