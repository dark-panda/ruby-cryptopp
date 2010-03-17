/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JGOST_H__
#define __JGOST_H__

#include "jconfig.h"

#if ENABLED_GOST_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "gost.h"

using namespace CryptoPP;

class JGOST : public JCipher_Template<GOST_Info, GOST_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
