/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JIDEA_H__
#define __JIDEA_H__

#include "jconfig.h"

#if ENABLED_IDEA_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "idea.h"

using namespace CryptoPP;

class JIDEA : public JCipher_Template<IDEA_Info, IDEA_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
