/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JTWOFISH_H__
#define __JTWOFISH_H__

#include "jconfig.h"

#if ENABLED_TWOFISH_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "twofish.h"

using namespace CryptoPP;

class JTwofish : public JCipher_Template<Twofish_Info, TWOFISH_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
