/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JCAMELLIA_H__
#define __JCAMELLIA_H__

#include "jconfig.h"

#ifdef WORD64_AVAILABLE
#if ENABLED_CAMELLIA_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "camellia.h"

using namespace CryptoPP;

class JCamellia : public JCipher_Template<Camellia_Info, CAMELLIA_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
#endif
