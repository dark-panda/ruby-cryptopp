/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JDIAMOND2LITE_H__
#define __JDIAMOND2LITE_H__

#include "jconfig.h"

#if ENABLED_DIAMOND2_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "diamond.h"

using namespace CryptoPP;

class JDiamond2Lite : public JCipher_Template<Diamond2Lite_Info, DIAMOND2_LITE_CIPHER, 8, 1, INT_MAX>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
