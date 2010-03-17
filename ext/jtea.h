/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JTEA_H__
#define __JTEA_H__

#include "jconfig.h"

#if ENABLED_TEA_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "tea.h"

using namespace CryptoPP;

class JTEA : public JCipher_Template<TEA_Info, TEA_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
