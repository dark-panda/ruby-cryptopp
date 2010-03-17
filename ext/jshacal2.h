/*
   +----------------------------------------------------------------------+
   | Copyright (c) 2002-2009 J Smith <dark.panda@gmail.com>               |
   | Crypto++ sources (not included) copyright (c) 1995-2009 Wei Dai      |
   +----------------------------------------------------------------------+
   | Check out COPYING for the exact license.                             |
   +----------------------------------------------------------------------+

$Id: $
*/

#ifndef __JSHACAL2_H__
#define __JSHACAL2_H__

#include "jconfig.h"

#if ENABLED_SHACAL2_CIPHER

#include "jcipher_t.h"

// Crypto++ headers...

#include "shacal2.h"

using namespace CryptoPP;

class JSHACAL2 : public JCipher_Template<SHACAL2_Info, SHACAL2_CIPHER>
{
	protected:
		BlockCipher* getEncryptionObject();
		BlockCipher* getDecryptionObject();
};

#endif
#endif
