/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JDIAMOND2_H__
#define __JDIAMOND2_H__

#include "jconfig.h"

#if ENABLED_DIAMOND2_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "diamond.h"

using namespace CryptoPP;

class JDiamond2 : public JCipher_Template<Diamond2_Info, DIAMOND2_CIPHER, 10, 1, INT_MAX>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
