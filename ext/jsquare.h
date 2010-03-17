/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JSQUARE_H__
#define __JSQUARE_H__

#include "jconfig.h"

#if ENABLED_SQUARE_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "square.h"

using namespace CryptoPP;

class JSquare : public JCipher_Template<Square_Info, SQUARE_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
