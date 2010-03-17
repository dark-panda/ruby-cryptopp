/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JRC5_H__
#define __JRC5_H__

#include "jconfig.h"

#if ENABLED_RC5_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "rc5.h"

using namespace CryptoPP;

class JRC5 : public JCipher_Template<RC5_Info, RC5_CIPHER, 16, 1, INT_MAX>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
